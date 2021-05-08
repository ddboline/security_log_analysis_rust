use anyhow::{format_err, Error};
use chrono::{DateTime, Datelike, FixedOffset, Local, NaiveDateTime, TimeZone, Utc};
use flate2::read::GzDecoder;
use glob::glob;
use itertools::Itertools;
use log::debug;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{
    collections::HashSet,
    convert::{TryFrom, TryInto},
    fmt,
    fs::File,
    io::{BufRead, BufReader, Read},
};
use tokio::{process::Command, task::spawn_blocking};

use crate::{
    host_country_metadata::HostCountryMetadata,
    models::{IntrusionLog, IntrusionLogInsert},
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct LogLineSSH {
    pub host: StackString,
    pub user: Option<StackString>,
    pub timestamp: DateTime<Utc>,
}

pub fn parse_log_message(line: &str) -> Result<Option<(&str, &str)>, Error> {
    let user = match line.split("Invalid user ").nth(1) {
        Some(x) => x,
        None => return Ok(None),
    };
    let remaining: SmallVec<[&str; 2]> = user.split(" from ").take(2).collect();
    let user = remaining.get(0).ok_or_else(|| format_err!("No user"))?;
    let user = if user.len() == 0 {
        ""
    } else if user.len() > 15 {
        &user[0..15]
    } else {
        user
    };
    let host = remaining
        .get(1)
        .ok_or_else(|| format_err!("No host"))?
        .split("port")
        .next()
        .ok_or_else(|| format_err!("No host"))?
        .trim();
    let host = if host.len() > 60 { &host[0..60] } else { host };
    Ok(Some((host, user)))
}

pub fn parse_log_line_ssh(year: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    if !line.contains("sshd") || !line.contains("Invalid user") {
        return Ok(None);
    }
    let tokens: SmallVec<[&str; 10]> = line.split_whitespace().take(10).collect();
    if tokens.len() < 10 {
        return Ok(None);
    }
    let timestr = format!("{} {} {} {}", tokens[0], tokens[1], year, tokens[2]);
    let timestamp = Local.datetime_from_str(&timestr, "%B %e %Y %H:%M:%S")?;
    if let Some((host, user)) = parse_log_message(line)? {
        let result = LogLineSSH {
            host: host.into(),
            user: Some(user.into()),
            timestamp: timestamp.with_timezone(&Utc),
        };
        Ok(Some(result))
    } else {
        Ok(None)
    }
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
        line.clear();
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
        Some(pool) => IntrusionLog::get_max_datetime(pool, service, server)?,
        None => None,
    };

    let inserts = results
        .into_iter()
        .filter_map(|log_line| {
            let cond = match max_datetime.as_ref() {
                Some(maxdt) => log_line.timestamp > *maxdt,
                None => true,
            };
            if cond {
                Some(IntrusionLogInsert {
                    service: service.into(),
                    server: server.into(),
                    datetime: log_line.timestamp,
                    host: log_line.host,
                    username: log_line.user,
                })
            } else {
                None
            }
        })
        .sorted()
        .dedup()
        .collect();
    Ok(inserts)
}

pub fn parse_log_line_apache(_: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    let tokens: SmallVec<[&str; 5]> = line.split_whitespace().take(5).collect();
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
        host: host.into(),
        user: None,
        timestamp: timestamp.with_timezone(&Utc),
    };
    Ok(Some(result))
}

pub async fn parse_systemd_logs_sshd_all(
    hc: &HostCountryMetadata,
    server: &str,
) -> Result<Vec<IntrusionLogInsert>, Error> {
    let max_datetime: Option<DateTime<Utc>> = match hc.pool.as_ref() {
        Some(pool) => {
            let pool = pool.clone();
            let server: StackString = server.into();
            spawn_blocking(move || IntrusionLog::get_max_datetime(&pool, "ssh", &server)).await??
        }
        None => None,
    };

    let inserts = parse_systemd_logs_sshd(server)
        .await?
        .into_iter()
        .filter(|log_line| match max_datetime.as_ref() {
            Some(maxdt) => log_line.datetime > *maxdt,
            None => true,
        })
        .collect();
    Ok(inserts)
}

pub async fn parse_systemd_logs_sshd(server: &str) -> Result<Vec<IntrusionLogInsert>, Error> {
    let command = Command::new("journalctl")
        .args(&[
            "-t",
            "sshd",
            "-o",
            "json",
            "--output-fields=MESSAGE,_SOURCE_REALTIME_TIMESTAMP",
        ])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&command.stdout);
    stdout
        .split('\n')
        .filter(|line| line.contains("_SOURCE_REALTIME_TIMESTAMP") && line.contains("Invalid user"))
        .map(|line| {
            let log: ServiceLogLine = serde_json::from_str(line)?;
            let log_line: LogLineSSH = log.try_into()?;
            Ok(IntrusionLogInsert {
                service: "ssh".into(),
                server: server.into(),
                datetime: log_line.timestamp,
                host: log_line.host,
                username: log_line.user,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceLogLine<'a> {
    #[serde(alias = "_SOURCE_REALTIME_TIMESTAMP")]
    timestamp: &'a str,
    #[serde(alias = "MESSAGE")]
    message: StackString,
}

impl TryFrom<ServiceLogLine<'_>> for LogLineSSH {
    type Error = Error;
    fn try_from(line: ServiceLogLine) -> Result<Self, Self::Error> {
        let timestamp: i64 = line.timestamp.parse()?;
        let timestamp = NaiveDateTime::from_timestamp((timestamp / 1_000_000) as i64, (timestamp % 1_000_000 * 1000) as u32);
        let timestamp = DateTime::from_utc(timestamp, Utc);
        let (host, user) = parse_log_message(&line.message)?
            .ok_or_else(|| format_err!("Failed to parse {}", line.message))?;

        Ok(Self {
            timestamp,
            host: host.into(),
            user: Some(user.into()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServiceLogEntry {
    timestamp: DateTime<Utc>,
    message: StackString,
    hostname: StackString,
}

impl fmt::Display for ServiceLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.timestamp, self.hostname, self.message)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use chrono::{Datelike, Timelike, Utc};
    use log::debug;
    use stack_string::StackString;
    use std::fs::File;

    use crate::{
        config::Config,
        host_country_metadata::HostCountryMetadata,
        parse_logs::{
            parse_all_log_files, parse_log_file, parse_log_line_apache, parse_log_line_ssh,
            parse_systemd_logs_sshd,
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
        assert_eq!(result.user, Some("test".into()));
        assert_eq!(result.host, "36.110.50.217");
        assert_eq!(result.timestamp.hour(), 4);

        let test_line = "Apr 19 07:40:45 dilepton-tower sshd[72399]: Invalid user admin1 from \
                         196.189.241.98 port 40113\n";
        let result = parse_log_line_ssh(2021, test_line).unwrap().unwrap();
        debug!("{:?}", result);
        assert_eq!(result.user, Some("admin1".into()));
        assert_eq!(result.host, "196.189.241.98");
        assert_eq!(result.timestamp.hour(), 11);

        let test_line = "May 17 03:10:32 ip-172-31-78-8 sshd[1205097]: Invalid user admin from \
                         106.54.145.68 port 52542";
        let result = parse_log_line_ssh(2020, test_line).unwrap().unwrap();
        debug!("{:?}", result);
        assert_eq!(result.user, Some("admin".into()));
        assert_eq!(result.host, "106.54.145.68");
        assert_eq!(result.timestamp.hour(), 7);
    }

    #[test]
    fn test_parse_log_line_apache() {
        let test_line = r#"
            82.73.86.33 - - [30/Jun/2019:18:02:14 -0400] "GET /db/db-admin/index.php?lang=en HTTP/1.1" 404 458 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.119 Safari/537.36"
        "#;
        let result = parse_log_line_apache(2019, test_line).unwrap().unwrap();
        assert_eq!(result.user, None);
        assert_eq!(result.host, "82.73.86.33");
        assert_eq!(result.timestamp.hour(), 22);

        let test_line = r#"
        67.250.95.88 - - [17/May/2020:01:49:57 +0000] "GET /garmin/fitbit/heartrate_plots HTTP/1.1" 200 7457 "https://cloud.ddboline.net/garmin" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
        "#;
        let result = parse_log_line_apache(2020, test_line).unwrap().unwrap();
        assert_eq!(result.user, None);
        assert_eq!(result.host, "67.250.95.88");
        assert_eq!(result.timestamp.hour(), 1);
    }

    #[test]
    #[ignore]
    fn test_parse_log_file_ssh() {
        let fname = "tests/data/test_auth.log";
        let infile = File::open(fname).unwrap();
        let year = Utc::now().year();
        let results = parse_log_file(year, infile, &parse_log_line_ssh).unwrap();
        println!("{}", results.len());
        assert!(results.len() == 20);
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
        assert!(results.len() == 18);
    }

    #[tokio::test]
    #[ignore]
    async fn test_parse_systemd_logs_sshd() -> Result<(), Error> {
        let logs = parse_systemd_logs_sshd("home.ddboline.net").await?;
        println!("{:?}", logs[0]);
        assert!(logs.len() > 0);
        Ok(())
    }
}
