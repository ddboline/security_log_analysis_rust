use anyhow::{format_err, Error};
use diesel::connection::SimpleConnection;
use log::{debug, error};
use parking_lot::RwLock;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{collections::HashMap, net::ToSocketAddrs, process::Stdio, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use crate::{
    exponential_retry,
    models::{CountryCode, HostCountry},
    pgpool::PgPool,
};

#[derive(Clone, Debug)]
pub struct HostCountryMetadata {
    pub pool: Option<PgPool>,
    pub country_code_map: Arc<RwLock<HashMap<StackString, CountryCode>>>,
    pub host_country_map: Arc<RwLock<HashMap<StackString, HostCountry>>>,
    pub client: Client,
}

impl Default for HostCountryMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCountryMetadata {
    pub fn new() -> Self {
        Self {
            pool: None,
            country_code_map: Arc::new(RwLock::new(HashMap::new())),
            host_country_map: Arc::new(RwLock::new(HashMap::new())),
            client: Client::new(),
        }
    }

    pub fn from_pool(pool: &PgPool) -> Result<Self, Error> {
        let result = Self {
            pool: Some(pool.clone()),
            country_code_map: Arc::new(RwLock::new(
                CountryCode::get_country_code_list(pool)?
                    .into_iter()
                    .map(|item| (item.code.clone(), item))
                    .collect(),
            )),
            host_country_map: Arc::new(RwLock::new(
                HostCountry::get_host_country(pool)?
                    .into_iter()
                    .map(|item| (item.host.clone(), item))
                    .collect(),
            )),
            ..Self::default()
        };
        Ok(result)
    }

    pub fn insert_host_code(&self, host: &str, code: &str) -> Result<StackString, Error> {
        let ccmap = self.country_code_map.read();
        if (*ccmap).contains_key(code) {
            let ipaddr = (host, 22).to_socket_addrs()?.next().and_then(|s| {
                let ip = s.ip();
                if ip.is_ipv4() {
                    Some(ip.to_string().into())
                } else {
                    None
                }
            });
            let host_country = HostCountry {
                host: host.into(),
                code: code.into(),
                ipaddr,
            };
            let host_exists = { (*self.host_country_map.read()).contains_key(host) };
            if !host_exists {
                let mut lock = self.host_country_map.write();
                if !(*lock).contains_key(host) {
                    if let Some(pool) = self.pool.as_ref() {
                        host_country.insert_host_country(pool)?;
                    }
                    (*lock).insert(host.into(), host_country);
                }
            }
            return Ok(code.into());
        }
        Err(format_err!("Failed to insert {}", code))
    }

    pub async fn get_country_info(&self, host: &str) -> Result<StackString, Error> {
        if let Some(entry) = (*self.host_country_map.read()).get(host) {
            return Ok(entry.code.clone());
        }
        let whois_code = self.get_whois_country_info(host).await?;
        self.insert_host_code(host, &whois_code)
    }

    pub async fn get_whois_country_info(&self, host: &str) -> Result<StackString, Error> {
        if let Ok(country) = self.get_whois_country_info_ipwhois(host).await {
            return Ok(country);
        }
        Self::get_whois_country_info_cmd(host).await
    }

    pub async fn get_whois_country_info_ipwhois(&self, host: &str) -> Result<StackString, Error> {
        #[derive(Serialize, Deserialize)]
        struct IpWhoIsOutput {
            country_code: StackString,
        }

        let ipaddr = (host, 22)
            .to_socket_addrs()?
            .next()
            .and_then(|s| {
                let ip = s.ip();
                if ip.is_ipv4() {
                    Some(ip.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| format_err!("Failed to extract IP address from {}", host))?;
        let url = Url::parse("http://ipwhois.app/json/")?.join(&ipaddr)?;
        debug!("{}", url);
        let resp = self.client.get(url).send().await?.error_for_status()?;
        let output: IpWhoIsOutput = resp.json().await?;
        Ok(output.country_code)
    }

    pub async fn get_whois_country_info_cmd(host: &str) -> Result<StackString, Error> {
        async fn _get_whois_country_info(args: &[&str]) -> Result<StackString, Error> {
            let output = Command::new("whois").args(args).output().await?;
            if output.status.success() {
                let buf = String::from_utf8_lossy(&output.stdout);
                for line in buf.split('\n') {
                    let line = line.to_uppercase();
                    if let LineResult::Country(code) = process_line(&line) {
                        return Ok(code);
                    }
                }
            }
            Err(format_err!("No Country Code Found"))
        }

        if let Ok(code) =
            exponential_retry(|| async move { _get_whois_country_info(&[host]).await }).await
        {
            Ok(code)
        } else if let Ok(code) =
            exponential_retry(|| async move { _get_whois_country_info(&["-B", host]).await }).await
        {
            Ok(code)
        } else {
            exponential_retry(|| async move { _get_whois_country_info(&["-r", host]).await }).await
        }
    }

    pub fn cleanup_intrusion_log(&self) -> Result<(), Error> {
        let dedupe_query0 = r#"
            DELETE FROM intrusion_log a
                USING intrusion_log b
            WHERE a.id<b.id AND 
                  a.service=b.service AND 
                  a.server=b.server AND 
                  a.datetime=b.datetime AND 
                  a.host=b.host AND 
                  a.username=b.username
        "#;
        let dedupe_query1 = r#"
            DELETE FROM intrusion_log a
                USING intrusion_log b
            WHERE a.id<b.id AND
                  a.service=b.service AND
                  a.server=b.server AND
                  a.datetime=b.datetime AND
                  a.host=b.host AND
                  a.username is NULL
        "#;
        if let Some(pool) = self.pool.as_ref() {
            let conn = pool.get()?;
            conn.batch_execute(dedupe_query0)?;
            conn.batch_execute(dedupe_query1)?;
        }
        Ok(())
    }
}

enum LineResult {
    Country(StackString),
    Break,
    Continue,
}

fn process_line(line: &str) -> LineResult {
    if line.contains("QUERY RATE") {
        LineResult::Break
    } else if line.contains("KOREA") {
        LineResult::Country("KR".into())
    } else if line.ends_with(".BR") {
        LineResult::Country("BR".into())
    } else if line.contains("COMCAST CABLE") {
        LineResult::Country("US".into())
    } else if line.contains("HINET-NET") {
        LineResult::Country("TW".into())
    } else if line.contains(".JP") {
        LineResult::Country("JP".into())
    } else {
        let tokens: SmallVec<[&str; 2]> = line.split_whitespace().take(2).collect();
        if tokens.len() >= 2 && tokens[0] == "COUNTRY:" {
            let code = tokens[1].into();
            LineResult::Country(code)
        } else {
            LineResult::Continue
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use log::debug;
    use std::net::ToSocketAddrs;

    use crate::host_country_metadata::HostCountryMetadata;

    #[tokio::test]
    async fn test_get_whois_country_info() -> Result<(), Error> {
        let hm = HostCountryMetadata::new();
        assert_eq!(
            hm.get_whois_country_info("36.110.50.217").await?.as_str(),
            "CN"
        );
        assert_eq!(
            hm.get_whois_country_info("82.73.86.33").await?.as_str(),
            "NL"
        );
        assert_eq!(
            hm.get_whois_country_info("217.29.210.13").await?.as_str(),
            "ZA"
        );
        assert_eq!(
            hm.get_whois_country_info("31.162.240.19").await?.as_str(),
            "RU"
        );
        assert_eq!(
            hm.get_whois_country_info("174.61.53.116").await?.as_str(),
            "US"
        );
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_whois_country_info_cmd() -> Result<(), Error> {
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("36.110.50.217")
                .await?
                .as_str(),
            "CN"
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("82.73.86.33")
                .await?
                .as_str(),
            "NL"
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("217.29.210.13")
                .await?
                .as_str(),
            "EU"
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("31.162.240.19")
                .await?
                .as_str(),
            "RU"
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("174.61.53.116")
                .await?
                .as_str(),
            "US"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_get_whois_country_info_ipwhois() -> Result<(), Error> {
        let hm = HostCountryMetadata::new();
        assert_eq!(
            hm.get_whois_country_info_ipwhois("36.110.50.217")
                .await?
                .as_str(),
            "CN"
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("82.73.86.33")
                .await?
                .as_str(),
            "NL"
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("217.29.210.13")
                .await?
                .as_str(),
            "ZA"
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("31.162.240.19")
                .await?
                .as_str(),
            "RU"
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("174.61.53.116")
                .await?
                .as_str(),
            "US"
        );
        Ok(())
    }

    #[test]
    fn test_get_socket_addr() {
        let sockaddr = ("home.ddboline.net", 22)
            .to_socket_addrs()
            .unwrap()
            .nth(0)
            .unwrap();
        let ipaddr = sockaddr.ip();
        assert!(ipaddr.is_ipv4());
        debug!("{}", ipaddr);
    }
}
