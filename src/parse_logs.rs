use chrono::{DateTime, Local, TimeZone, Utc};
use failure::{err_msg, Error};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};
use subprocess::Exec;

use crate::map_result;
use crate::models::{get_country_code_list, get_host_country, CountryCode, HostCountry};
use crate::pgpool::PgPool;

#[derive(Clone, Debug)]
pub struct HostCountryMetadata {
    pub country_code_map: Arc<RwLock<HashMap<String, CountryCode>>>,
    pub host_country_map: Arc<RwLock<HashMap<String, HostCountry>>>,
}

impl HostCountryMetadata {
    pub fn from_pool(pool: &PgPool) -> Result<Self, Error> {
        let result = HostCountryMetadata {
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

    pub fn get_country_info(&self, host: &str) -> Result<String, Error> {
        if let Ok(hcmap) = self.host_country_map.read() {
            if let Some(entry) = (*hcmap).get(host) {
                return Ok(entry.code.clone());
            }
        }
        let command = format!("whois {}", host);
        let stream = Exec::shell(command).stream_stdout()?;
        let reader = BufReader::new(stream);
        for line in reader.lines() {
            let l = line?.to_uppercase();
            let tokens: Vec<_> = l.split_whitespace().collect();
            if tokens.len() >= 2 {
                if tokens[0] == "COUNTRY:" {
                    if let Ok(ccmap) = self.country_code_map.read() {
                        if (*ccmap).contains_key(tokens[1]) {
                            let code = tokens[1].to_string();
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
                                code: code.clone(),
                                ipaddr,
                            };
                            if let Ok(mut hcmap) = self.host_country_map.write() {
                                (*hcmap).insert(host.to_string(), host_country);
                            }
                            return Ok(tokens[1].to_string());
                        }
                    }
                }
            }
        }
        Err(err_msg("No country found"))
    }
}

#[derive(Debug)]
pub struct LogLineSSH {
    pub host: String,
    pub user: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub fn parse_log_line_ssh(year: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    if !line.contains("sshd") && !line.contains("Invalid user") {
        return Ok(None);
    }
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens.len() < 10 {
        println!("Too few tokens: {}", line.trim());
        return Ok(None);
    }
    let timestr = format!("{} {} {} {}", tokens[0], tokens[1], year, tokens[2]);
    let timestamp = Local.datetime_from_str(&timestr, "%B %e %Y %H:%M:%S")?;
    let user = line
        .split("Invalid user ")
        .nth(1)
        .ok_or_else(|| err_msg("Invalid line"))?;
    let remaining: Vec<_> = user.split(" from ").collect();
    let user = remaining.get(0).ok_or_else(|| err_msg("No user"))?;
    let host = remaining
        .get(1)
        .ok_or_else(|| err_msg("No host"))?
        .split("port")
        .nth(0)
        .ok_or_else(|| err_msg("No host"))?
        .trim();
    let result = LogLineSSH {
        host: host.to_string(),
        user: Some(user.to_string()),
        timestamp: timestamp.with_timezone(&Utc),
    };
    Ok(Some(result))
}

pub fn parse_log_file_ssh(year: i32, fname: &str) -> Result<Vec<LogLineSSH>, Error> {
    let f = File::open(fname)?;
    let b = BufReader::new(f);
    let results: Vec<_> = b.lines().map(|l| l.map_err(err_msg)).collect();
    let lines: Vec<_> = map_result(results)?;
    let results: Vec<_> = lines
        .into_par_iter()
        .map(|line| parse_log_line_ssh(year, &line))
        .collect();
    let results: Vec<_> = map_result(results)?;
    let results: Vec<_> = results.into_iter().filter_map(|x| x).collect();
    Ok(results)
}

pub fn parse_log_line_apache(line: &str) -> Result<Option<LogLineSSH>, Error> {
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return Ok(None);
    }
    let host = tokens[0];
    let timestr = tokens[3..5].join("").replace("[", "").replace("]", "");
    let timestamp = Local.datetime_from_str(&timestr, "%e/%B/%Y:%H:%M:%S%z")?;
    let result = LogLineSSH {
        host: host.to_string(),
        user: None,
        timestamp: timestamp.with_timezone(&Utc),
    };
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use chrono::Timelike;
    use std::net::ToSocketAddrs;

    use crate::config::Config;
    use crate::parse_logs::{parse_log_line_apache, parse_log_line_ssh, HostCountryMetadata};
    use crate::pgpool::PgPool;

    #[test]
    fn test_parse_log_line_ssh() {
        let test_line = "Jun 24 00:07:25 dilepton-tower sshd[15932]: Invalid user test from 36.110.50.217 port 28898\n";
        let result = parse_log_line_ssh(2019, test_line).unwrap().unwrap();
        println!("{:?}", result);
        assert_eq!(result.user, Some("test".to_string()));
        assert_eq!(result.host, "36.110.50.217".to_string());
        assert_eq!(result.timestamp.hour(), 4);
    }

    #[test]
    fn test_parse_log_line_apache() {
        let test_line = r#"82.73.86.33 - - [30/Jun/2019:18:02:14 -0400] "GET /db/db-admin/index.php?lang=en HTTP/1.1" 404 458 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 S
afari/537.36""#;
        let result = parse_log_line_apache(test_line).unwrap().unwrap();
        assert_eq!(result.user, None);
        assert_eq!(result.host, "82.73.86.33".to_string());
        assert_eq!(result.timestamp.hour(), 22);
    }

    #[test]
    fn test_get_country_info() {
        let config = Config::init_config().unwrap();
        let pool = PgPool::new(&config.database_url);
        let metadata = HostCountryMetadata::from_pool(&pool).unwrap();
        assert_eq!(
            metadata.get_country_info("36.110.50.217").unwrap(),
            "CN".to_string()
        );
        assert_eq!(
            metadata.get_country_info("82.73.86.33").unwrap(),
            "NL".to_string()
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
