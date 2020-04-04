use anyhow::{format_err, Error};
use chrono::{DateTime, Datelike, FixedOffset, Local, TimeZone, Utc};
use flate2::read::GzDecoder;
use glob::glob;
use log::debug;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Read},
};

use crate::{
    host_country_metadata::HostCountryMetadata,
    models::{get_intrusion_log_max_datetime, IntrusionLogInsert},
};

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
    let user = remaining.get(0).ok_or_else(|| format_err!("No user"))?;
    let user = if user.len() > 15 { &user[0..15] } else { user };
    let host = remaining
        .get(1)
        .ok_or_else(|| format_err!("No host"))?
        .split("port")
        .next()
        .ok_or_else(|| format_err!("No host"))?
        .trim();
    let host = if host.len() > 60 { &host[0..60] } else { host };
    let result = LogLineSSH {
        host: host.to_string(),
        user: Some(user.to_string()),
        timestamp: timestamp.with_timezone(&Utc),
    };
    Ok(Some(result))
}

pub fn parse_log_file<T, U>(year: i32, infile: T, parse_func: &U) -> Result<Vec<LogLineSSH>, Error>
where
    T: Read,
    U: Fn(i32, &str) -> Result<Option<LogLineSSH>, Error> + Send + Sync,
{
    let mut b = BufReader::new(infile);
    let mut line = String::new();
    let mut lines = Vec::new();
    loop {
        if b.read_line(&mut line)? == 0 {
            break;
        }
        if let Some(logline) = parse_func(year, &line)? {
            lines.push(logline);
        }
    }
    debug!("results {}", lines.len());
    Ok(lines)
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
            Some(x) => x.to_string_lossy(),
            None => "".into(),
        };
        debug!("{:?} {}", fname, ext);
        if ext == "gz" {
            let gz = GzDecoder::new(File::open(fname)?);
            results.extend(parse_log_file(year, gz, parse_func)?);
        } else {
            let f = File::open(fname)?;
            results.extend(parse_log_file(year, f, parse_func)?);
        }
    }

    let max_datetime: Option<DateTime<Utc>> = match hc.pool.as_ref() {
        Some(pool) => get_intrusion_log_max_datetime(pool, service, server)?,
        None => None,
    };

    let inserts: HashSet<_> = results
        .into_iter()
        .filter_map(|log_line| {
            let cond = match max_datetime.as_ref() {
                Some(maxdt) => log_line.timestamp > *maxdt,
                None => true,
            };
            if cond {
                Some(IntrusionLogInsert {
                    service: service.to_string(),
                    server: server.to_string(),
                    datetime: log_line.timestamp,
                    host: log_line.host,
                    username: log_line.user,
                })
            } else {
                None
            }
        })
        .collect();
    let inserts: Vec<_> = inserts.into_iter().collect();
    Ok(inserts)
}

pub fn parse_log_line_apache(_: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    let tokens: Vec<_> = line.split_whitespace().collect();
    if tokens.len() < 5 {
        return Ok(None);
    }
    let host = tokens[0];
    let host = if host.len() > 60 { &host[0..60] } else { host };
    let offset: i32 = tokens[4].replace("]", "").parse()?;
    let offset = FixedOffset::east((offset / 100) * 60 * 60 + (offset % 100) * 60);
    let timestr = tokens[3..5].join("").replace("[", "").replace("]", "");
    let timestamp = offset.datetime_from_str(&timestr, "%e/%B/%Y:%H:%M:%S%z")?;
    let result = LogLineSSH {
        host: host.to_string(),
        user: None,
        timestamp: timestamp.with_timezone(&Utc),
    };
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use chrono::{Utc, Timelike, Datelike};
    use log::debug;
    use std::fs::File;

    use crate::{
        config::Config,
        host_country_metadata::HostCountryMetadata,
        parse_logs::{
            parse_all_log_files, parse_log_file, parse_log_line_apache, parse_log_line_ssh,
        },
        pgpool::PgPool,
    };

    #[test]
    #[ignore]
    fn test_parse_log_line_ssh() {
        let test_line = "Jun 24 00:07:25 dilepton-tower sshd[15932]: Invalid user test from \
                         36.110.50.217 port 28898\n";
        let result = parse_log_line_ssh(2019, test_line).unwrap().unwrap();
        debug!("{:?}", result);
        assert_eq!(result.user, Some("test".to_string()));
        assert_eq!(result.host, "36.110.50.217".to_string());
        assert_eq!(result.timestamp.hour(), 4);
    }

    #[test]
    fn test_parse_log_line_apache() {
        let test_line = r#"
            82.73.86.33 - - [30/Jun/2019:18:02:14 -0400] "GET /db/db-admin/index.php?lang=en HTTP/1.1" 404 458 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"
        "#;
        let result = parse_log_line_apache(2019, test_line).unwrap().unwrap();
        assert_eq!(result.user, None);
        assert_eq!(result.host, "82.73.86.33".to_string());
        assert_eq!(result.timestamp.hour(), 22);
    }

    #[test]
    #[ignore]
    fn test_parse_log_file_ssh() {
        let fname = "tests/data/test_auth.log";
        let infile = File::open(fname).unwrap();
        let year = Utc::now().year();
        let results = parse_log_file(year, infile, &parse_log_line_ssh).unwrap();
        assert!(results.len() == 992);
    }

    #[test]
    #[ignore]
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
            "tests/data/test_auth.log",
        )
        .unwrap();
        println!("{}", results.len());
        assert!(results.len() == 1);
    }
}
