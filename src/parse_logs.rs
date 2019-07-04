use chrono::{DateTime, Datelike, Local, TimeZone, Utc};
use failure::{err_msg, Error};
use flate2::read::GzDecoder;
use glob::glob;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};

use crate::host_country_metadata::HostCountryMetadata;
use crate::map_result;
use crate::models::{get_intrusion_log_max_datetime, insert_intrusion_log, IntrusionLogInsert};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct LogLineSSH {
    pub host: String,
    pub user: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub fn parse_log_line_ssh(year: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    if !line.contains("sshd") || !line.contains("Invalid user") {
        return Ok(None);
    }
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens.len() < 10 {
        return Ok(None);
    }
    let timestr = format!("{} {} {} {}", tokens[0], tokens[1], year, tokens[2]);
    let timestamp = Local.datetime_from_str(&timestr, "%B %e %Y %H:%M:%S")?;
    let user = match line.split("Invalid user ").nth(1) {
        Some(x) => x,
        None => return Ok(None),
    };
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

pub fn parse_log_file<T, U>(
    hc: &HostCountryMetadata,
    year: i32,
    infile: T,
    parse_func: &U,
) -> Result<Vec<LogLineSSH>, Error>
where
    T: Read,
    U: Fn(i32, &str) -> Result<Option<LogLineSSH>, Error> + Send + Sync,
{
    let b = BufReader::new(infile);
    let results: Vec<_> = b.lines().map(|l| l.map_err(err_msg)).collect();
    let lines: Vec<_> = map_result(results)?;
    let results: Vec<_> = lines
        .into_par_iter()
        .filter_map(|line| match parse_func(year, &line) {
            Ok(Some(x)) => match hc.get_country_info(&x.host) {
                Ok(_) => Some(Ok(x)),
                Err(e) => Some(Err(e)),
            },
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
        .collect();
    let results: Vec<_> = map_result(results)?;
    println!("results {}", results.len());
    Ok(results)
}

pub fn parse_all_log_files<T>(
    hc: &HostCountryMetadata,
    service: &str,
    server: &str,
    parse_func: &T,
    log_prefix: &str,
) -> Result<Vec<IntrusionLogInsert>, Error>
where
    T: Fn(i32, &str) -> Result<Option<LogLineSSH>, Error> + Send + Sync,
{
    let mut results = Vec::new();
    for entry in glob(&format!("{}*", log_prefix))? {
        let fname = entry?;
        let metadata = fname.metadata()?;
        let modified: DateTime<Utc> = metadata.modified()?.into();
        let year = modified.year();
        let ext = match fname.extension() {
            Some(x) => x.to_str().unwrap_or_else(|| ""),
            None => "",
        };
        println!("{:?} {}", fname, ext);
        if ext == "gz" {
            let gz = GzDecoder::new(File::open(fname)?);
            results.extend(parse_log_file(&hc, year, gz, parse_func)?);
        } else {
            let f = File::open(fname)?;
            results.extend(parse_log_file(&hc, year, f, parse_func)?);
        }
    }

    let max_datetime: Option<DateTime<Utc>> = match hc.pool.as_ref() {
        Some(pool) => get_intrusion_log_max_datetime(pool, service, server)?,
        None => None,
    };

    let inserts: Vec<_> = results
        .into_iter()
        .filter(|log_line| match max_datetime.as_ref() {
            Some(maxdt) => log_line.timestamp > *maxdt,
            None => true,
        })
        .map(|log_line| IntrusionLogInsert {
            service: service.to_string(),
            server: server.to_string(),
            datetime: log_line.timestamp,
            host: log_line.host,
            username: log_line.user,
        })
        .collect();

    if let Some(pool) = hc.pool.as_ref() {
        insert_intrusion_log(pool, &inserts)?;
    }
    Ok(inserts)
}

pub fn parse_log_line_apache(_: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
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
    use std::fs::File;
    use std::net::ToSocketAddrs;

    use crate::config::Config;
    use crate::parse_logs::{
        parse_all_log_files, parse_log_file, parse_log_line_apache, parse_log_line_ssh,
        HostCountryMetadata,
    };
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
        let result = parse_log_line_apache(2019, test_line).unwrap().unwrap();
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
        assert_eq!(
            metadata.get_country_info("217.29.210.13").unwrap(),
            "EU".to_string()
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

    #[test]
    fn test_parse_log_file_ssh() {
        let config = Config::init_config().unwrap();
        let pool = PgPool::new(&config.database_url);
        let mut hc = HostCountryMetadata::from_pool(&pool).unwrap();
        hc.pool = None;
        let fname = "/var/log/auth.log";
        let infile = File::open(fname).unwrap();
        let results = parse_log_file(&hc, 2019, infile, &parse_log_line_ssh).unwrap();
        assert!(results.len() > 0);
    }

    #[test]
    fn test_parse_all_log_files_ssh() {
        let config = Config::init_config().unwrap();
        let pool = PgPool::new(&config.database_url);
        let mut hc = HostCountryMetadata::from_pool(&pool).unwrap();
        hc.pool = None;
        let results = parse_all_log_files(
            &hc,
            "ssh",
            "home.ddboline.net",
            &parse_log_line_ssh,
            "/var/log/auth.log",
        )
        .unwrap();
        assert!(results.len() > 0);
    }
}
