use diesel::connection::SimpleConnection;
use failure::{err_msg, Error};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use subprocess::{Exec, Redirection};

use crate::models::{
    get_country_code_list, get_host_country, insert_host_country, CountryCode, HostCountry,
};
use crate::pgpool::PgPool;

#[derive(Clone, Debug)]
pub struct HostCountryMetadata {
    pub pool: Option<PgPool>,
    pub country_code_map: Arc<RwLock<HashMap<String, CountryCode>>>,
    pub host_country_map: Arc<RwLock<HashMap<String, HostCountry>>>,
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
        }
    }

    pub fn from_pool(pool: &PgPool) -> Result<Self, Error> {
        let result = HostCountryMetadata {
            pool: Some(pool.clone()),
            country_code_map: Arc::new(RwLock::new(
                get_country_code_list(&pool)?
                    .into_iter()
                    .map(|item| (item.code.clone(), item))
                    .collect(),
            )),
            host_country_map: Arc::new(RwLock::new(
                get_host_country(&pool)?
                    .into_iter()
                    .map(|item| (item.host.clone(), item))
                    .collect(),
            )),
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
        Err(err_msg(format!("Failed to insert {}", code)))
    }

    pub fn get_country_info(&self, host: &str) -> Result<String, Error> {
        if let Some(entry) = (*self.host_country_map.read()).get(host) {
            return Ok(entry.code.clone());
        }
        let whois_code = self.get_whois_country_info(host)?;
        self.insert_host_code(host, &whois_code)
    }

    pub fn get_whois_country_info(&self, host: &str) -> Result<String, Error> {
        let command = format!("whois {}", host);
        println!("command {}", command);

        let mut process = Exec::shell(command).stdout(Redirection::Pipe).popen()?;
        let exit_status = process.wait()?;
        if exit_status.success() {
            if let Some(f) = process.stdout.as_ref() {
                let reader = BufReader::new(f);
                for line in reader.lines() {
                    let l = match line {
                        Ok(l) => l.trim().to_uppercase(),
                        Err(e) => {
                            println!("{:?}", e);
                            continue;
                        }
                    };
                    if l.contains("QUERY RATE") {
                        println!("Retry");
                        sleep(Duration::from_secs(5));
                        return self.get_whois_country_info(host);
                    } else if l.contains("KOREA") {
                        return Ok("KR".to_string());
                    } else if l.ends_with(".BR") {
                        return Ok("BR".to_string());
                    } else if l.contains("COMCAST CABLE") {
                        return Ok("US".to_string());
                    }
                    let tokens: Vec<_> = l.split_whitespace().collect();
                    if tokens.len() >= 2 && tokens[0] == "COUNTRY:" {
                        let code = tokens[1].to_string();
                        return Ok(code);
                    }
                }
            }
            Err(err_msg(format!("No country found {}", host)))
        } else {
            Err(err_msg(format!(
                "Failed with exit status {:?}",
                exit_status
            )))
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

#[cfg(test)]
mod test {
    use crate::host_country_metadata::HostCountryMetadata;
    use std::net::ToSocketAddrs;

    #[test]
    fn test_get_whois_country_info() {
        let metadata = HostCountryMetadata::new();
        assert_eq!(
            metadata.get_whois_country_info("36.110.50.217").unwrap(),
            "CN".to_string()
        );
        assert_eq!(
            metadata.get_whois_country_info("82.73.86.33").unwrap(),
            "NL".to_string()
        );
        assert_eq!(
            metadata.get_whois_country_info("217.29.210.13").unwrap(),
            "EU".to_string()
        );
        assert_eq!(
            metadata.get_whois_country_info("31.162.240.19").unwrap(),
            "RU"
        );
        assert_eq!(
            metadata.get_whois_country_info("174.61.53.116").unwrap(),
            "US"
        );
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
        println!("{}", ipaddr);
    }
}
