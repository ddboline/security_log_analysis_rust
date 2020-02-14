use anyhow::{format_err, Error};
use diesel::connection::SimpleConnection;
use log::{debug, error};
use parking_lot::RwLock;
use reqwest::blocking::Client;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use subprocess::{Exec, Redirection};
use whois_rust::{WhoIs, WhoIsError, WhoIsLookupOptions};

use crate::exponential_retry;
use crate::models::{
    get_country_code_list, get_host_country, insert_host_country, CountryCode, HostCountry,
};
use crate::pgpool::PgPool;

#[derive(Clone, Debug)]
pub struct HostCountryMetadata {
    pub pool: Option<PgPool>,
    pub country_code_map: Arc<RwLock<HashMap<String, CountryCode>>>,
    pub host_country_map: Arc<RwLock<HashMap<String, HostCountry>>>,
    pub whois: Arc<WhoIs>,
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
            whois: Arc::new(
                WhoIs::from_string(include_str!("servers.json")).expect("No server json"),
            ),
            client: Client::new(),
        }
    }

    pub fn from_pool(pool: &PgPool) -> Result<Self, Error> {
        let result = Self {
            pool: Some(pool.clone()),
            country_code_map: Arc::new(RwLock::new(
                get_country_code_list(&pool)?
                    .into_iter()
                    .map(|item| (item.code.to_string(), item))
                    .collect(),
            )),
            host_country_map: Arc::new(RwLock::new(
                get_host_country(&pool)?
                    .into_iter()
                    .map(|item| (item.host.to_string(), item))
                    .collect(),
            )),
            ..Self::default()
        };
        Ok(result)
    }

    pub fn insert_host_code(&self, host: &str, code: &str) -> Result<String, Error> {
        let ccmap = self.country_code_map.read();
        if (*ccmap).contains_key(code) {
            let ipaddr = (host, 22).to_socket_addrs()?.nth(0).and_then(|s| {
                let ip = s.ip();
                if ip.is_ipv4() {
                    Some(ip.to_string())
                } else {
                    None
                }
            });
            let host_country = HostCountry {
                host: host.to_string(),
                code: code.to_string(),
                ipaddr,
            };
            let host_exists = { (*self.host_country_map.read()).contains_key(host) };
            if !host_exists {
                let mut lock = self.host_country_map.write();
                if !(*lock).contains_key(host) {
                    if let Some(pool) = self.pool.as_ref() {
                        insert_host_country(pool, &host_country)?;
                    }
                    (*lock).insert(host.to_string(), host_country);
                }
            }
            return Ok(code.to_string());
        }
        Err(format_err!("Failed to insert {}", code))
    }

    pub fn get_country_info(&self, host: &str) -> Result<String, Error> {
        if let Some(entry) = (*self.host_country_map.read()).get(host) {
            return Ok(entry.code.to_string());
        }
        let whois_code = self.get_whois_country_info(host)?;
        self.insert_host_code(host, &whois_code)
    }

    fn run_lookup(&self, host: &str) -> Result<String, WhoIsError> {
        let opts = WhoIsLookupOptions::from_string(host)?;
        self.whois.lookup(opts)
    }

    pub fn get_whois_country_info(&self, host: &str) -> Result<String, Error> {
        if let Ok(country) = self.get_whois_country_info_ipwhois(&host) {
            return Ok(country);
        }
        let lookup_str = match self.run_lookup(host) {
            Ok(s) => s,
            Err(WhoIsError::SerdeJsonError(e)) => return Err(e.into()),
            Err(WhoIsError::IOError(e)) => return Err(e.into()),
            Err(WhoIsError::DomainError(e)) => return Err(e.into()),
            Err(WhoIsError::IPv4Error(e)) => return Err(e.into()),
            Err(WhoIsError::IPv6Error(e)) => return Err(e.into()),
            Err(WhoIsError::MapError(e)) => panic!("Unrecoverable error {}", e),
        };
        for line in lookup_str.split('\n') {
            match process_line(&line.to_uppercase()) {
                LineResult::Country(country) => return Ok(country),
                LineResult::Break => {
                    error!("Retry {} : {}", host, line.trim());
                    break;
                }
                LineResult::Continue => {}
            }
        }
        Self::get_whois_country_info_cmd(host)
    }

    pub fn get_whois_country_info_ipwhois(&self, host: &str) -> Result<String, Error> {
        #[derive(Serialize, Deserialize)]
        struct IpWhoIsOutput {
            country_code: String,
        }

        let ipaddr = (host, 22)
            .to_socket_addrs()?
            .nth(0)
            .and_then(|s| {
                let ip = s.ip();
                if ip.is_ipv4() {
                    Some(ip.to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| format_err!("Failed to extract IP address from {}", host))?;
        let url = Url::parse("http://free.ipwhois.io/json/")?.join(&ipaddr)?;
        debug!("{}", url);
        let resp = self.client.get(url).send()?.error_for_status()?;
        let output: IpWhoIsOutput = resp.json()?;
        Ok(output.country_code)
    }

    pub fn get_whois_country_info_cmd(host: &str) -> Result<String, Error> {
        fn _get_whois_country_info(command: &str, host: &str) -> Result<String, Error> {
            let mut process = Exec::shell(command).stdout(Redirection::Pipe).popen()?;
            let exit_status = process.wait()?;
            if exit_status.success() {
                if let Some(f) = process.stdout.as_ref() {
                    let reader = BufReader::new(f);
                    for line in reader.lines() {
                        let l = match line {
                            Ok(l) => l.trim().to_uppercase(),
                            Err(e) => {
                                error!("{:?}", e);
                                continue;
                            }
                        };
                        if l.contains("QUERY RATE") {
                            error!("Retry {} : {}", host, l.trim());
                            break;
                        } else if l.contains("KOREA") {
                            return Ok("KR".to_string());
                        } else if l.ends_with(".BR") {
                            return Ok("BR".to_string());
                        } else if l.contains("COMCAST CABLE") {
                            return Ok("US".to_string());
                        } else if l.contains("HINET-NET") {
                            return Ok("TW".to_string());
                        } else if l.contains(".JP") {
                            return Ok("JP".to_string());
                        }
                        let tokens: Vec<_> = l.split_whitespace().collect();
                        if tokens.len() >= 2 && tokens[0] == "COUNTRY:" {
                            let code = tokens[1].to_string();
                            return Ok(code);
                        }
                    }
                } else if !command.contains(" -B ") {
                    let new_command = format!("whois -B {}", host);
                    debug!("command {}", new_command);
                    return exponential_retry(|| _get_whois_country_info(&new_command, host));
                }
                Err(format_err!("No country found {}", host))
            } else if command.contains(" -r ") {
                Err(format_err!("Failed with exit status {:?}", exit_status))
            } else {
                let new_command = format!("whois -r {}", host);
                debug!("command {}", new_command);
                exponential_retry(|| _get_whois_country_info(&new_command, host))
            }
        }

        let command = format!("whois {}", host);
        debug!("command {}", command);
        exponential_retry(|| _get_whois_country_info(&command, host))
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
    Country(String),
    Break,
    Continue,
}

fn process_line(line: &str) -> LineResult {
    if line.contains("QUERY RATE") {
        LineResult::Break
    } else if line.contains("KOREA") {
        LineResult::Country("KR".to_string())
    } else if line.ends_with(".BR") {
        LineResult::Country("BR".to_string())
    } else if line.contains("COMCAST CABLE") {
        LineResult::Country("US".to_string())
    } else if line.contains("HINET-NET") {
        LineResult::Country("TW".to_string())
    } else if line.contains(".JP") {
        LineResult::Country("JP".to_string())
    } else {
        let tokens: Vec<_> = line.split_whitespace().collect();
        if tokens.len() >= 2 && tokens[0] == "COUNTRY:" {
            let code = tokens[1].to_string();
            LineResult::Country(code)
        } else {
            LineResult::Continue
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Error;
    use std::io::{stdout, Write};
    use std::net::ToSocketAddrs;

    use crate::host_country_metadata::HostCountryMetadata;

    #[test]
    fn test_get_whois_country_info() -> Result<(), Error> {
        let hm = HostCountryMetadata::new();
        assert_eq!(
            hm.get_whois_country_info("36.110.50.217")?,
            "CN".to_string()
        );
        assert_eq!(hm.get_whois_country_info("82.73.86.33")?, "NL".to_string());
        assert_eq!(
            hm.get_whois_country_info("217.29.210.13")?,
            "ZA".to_string()
        );
        assert_eq!(hm.get_whois_country_info("31.162.240.19")?, "RU");
        assert_eq!(hm.get_whois_country_info("174.61.53.116")?, "US");
        Ok(())
    }

    #[test]
    fn test_get_whois_country_info_cmd() -> Result<(), Error> {
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("36.110.50.217")?,
            "CN".to_string()
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("82.73.86.33")?,
            "NL".to_string()
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("217.29.210.13")?,
            "EU".to_string()
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("31.162.240.19")?,
            "RU"
        );
        assert_eq!(
            HostCountryMetadata::get_whois_country_info_cmd("174.61.53.116")?,
            "US"
        );
        Ok(())
    }

    #[test]
    fn test_get_whois_country_info_ipwhois() -> Result<(), Error> {
        let hm = HostCountryMetadata::new();
        assert_eq!(
            hm.get_whois_country_info_ipwhois("36.110.50.217")?,
            "CN".to_string()
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("82.73.86.33")?,
            "NL".to_string()
        );
        assert_eq!(
            hm.get_whois_country_info_ipwhois("217.29.210.13")?,
            "ZA".to_string()
        );
        assert_eq!(hm.get_whois_country_info_ipwhois("31.162.240.19")?, "RU");
        assert_eq!(hm.get_whois_country_info_ipwhois("174.61.53.116")?, "US");
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
        writeln!(stdout(), "{}", ipaddr).unwrap();
    }
}
