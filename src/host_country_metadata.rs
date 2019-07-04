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
                if let Some(pool) = self.pool.as_ref() {
                    insert_host_country(pool, &host_country)?;
                }
                (*self.host_country_map.write()).insert(host.to_string(), host_country);
            }
            return Ok(code.to_string());
        }
        Err(err_msg(format!("Failed to insert {}", code)))
    }

    pub fn get_country_info(&self, host: &str) -> Result<String, Error> {
        if let Some(entry) = (*self.host_country_map.read()).get(host) {
            return Ok(entry.code.clone());
        }
        let command = format!("whois {}", host);
        println!("command {}", command);

        let mut process = Exec::shell(command).stdout(Redirection::Pipe).popen()?;
        let exit_status = process.wait()?;
        if exit_status.success() {
            if let Some(f) = process.stdout.as_ref() {
                let reader = BufReader::new(f);
                for line in reader.lines() {
                    let l = line?.trim().to_uppercase();
                    if l.contains("QUERY RATE") {
                        println!("Retry");
                        sleep(Duration::from_secs(5));
                        return self.get_country_info(host);
                    } else if l.contains("KOREA") {
                        return self.insert_host_code(host, "KR");
                    } else if l.ends_with(".BR") {
                        return self.insert_host_code(host, "BR");
                    }
                    let tokens: Vec<_> = l.split_whitespace().collect();
                    if tokens.len() >= 2 && tokens[0] == "COUNTRY:" {
                        let code = tokens[1].to_string();
                        return self.insert_host_code(host, &code);
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
