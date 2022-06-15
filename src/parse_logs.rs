use anyhow::{format_err, Error};
use flate2::read::GzDecoder;
use glob::glob;
use itertools::Itertools;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::{format_sstr, StackString};
use std::{
    fmt,
    fs::File,
    io::{BufRead, BufReader, Read},
    net::Ipv4Addr,
    process::Stdio,
};
use time::{macros::format_description, Duration, OffsetDateTime, PrimitiveDateTime};
use time_tz::{timezones::db::UTC, OffsetDateTimeExt, PrimitiveDateTimeExt};
use tokio::{
    io::{self, AsyncBufReadExt, AsyncRead},
    process::Command,
    task::{spawn, JoinHandle},
    time::sleep,
};

use crate::{
    config::Config,
    host_country_metadata::HostCountryMetadata,
    models::{IntrusionLog, LogLevel, SystemdLogMessages},
    pgpool::PgPool,
    ses_client::SesInstance,
    DateTimeType, Host, Service,
};

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct LogLineSSH {
    pub host: StackString,
    pub user: Option<StackString>,
    pub timestamp: DateTimeType,
}

impl LogLineSSH {
    #[must_use]
    pub fn into_intrusion_log(self, service: &str, server: &str) -> IntrusionLog {
        IntrusionLog {
            id: -1,
            service: service.into(),
            server: server.into(),
            datetime: self.timestamp,
            host: self.host,
            username: self.user,
        }
    }
}

/// # Errors
/// Return error if db query fails
pub fn parse_log_message(line: &str) -> Result<Option<(&str, &str)>, Error> {
    let user = match line.split("Invalid user ").nth(1) {
        Some(x) => x,
        None => return Ok(None),
    };
    let remaining: SmallVec<[&str; 2]> = user.split(" from ").take(2).collect();
    let user = remaining.get(0).ok_or_else(|| format_err!("No user"))?;
    let user = if user.is_empty() {
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
    if host.contains('.') {
        Ok(Some((host, user)))
    } else {
        Ok(None)
    }
}

/// # Errors
/// Return error if db query fails
pub fn parse_log_line_ssh(year: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    let local = time_tz::system::get_timezone().unwrap_or(UTC);
    if !line.contains("sshd") || !line.contains("Invalid user") {
        return Ok(None);
    }
    let tokens: SmallVec<[&str; 10]> = line.split_whitespace().take(10).collect();
    if tokens.len() < 10 {
        return Ok(None);
    }
    let timestr = format_sstr!("{} {} {} {}", tokens[0], tokens[1], year, tokens[2]);
    let timestamp = PrimitiveDateTime::parse(
        &timestr,
        format_description!(
            "[month repr:short] [day padding:space] [year] [hour]:[minute]:[second]"
        ),
    )?
    .assume_timezone(local)
    .unwrap();
    if let Some((host, user)) = parse_log_message(line)? {
        let result = LogLineSSH {
            host: host.into(),
            user: Some(user.into()),
            timestamp: timestamp.to_timezone(UTC).into(),
        };
        Ok(Some(result))
    } else {
        Ok(None)
    }
}

/// # Errors
/// Return error if db query fails
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

/// # Errors
/// Return error if db query fails
pub async fn parse_all_log_files<T>(
    hc: &HostCountryMetadata,
    service: Service,
    server: Host,
    parse_func: &T,
    log_prefix: &str,
) -> Result<Vec<IntrusionLog>, Error>
where
    T: Fn(i32, &str) -> Result<Option<LogLineSSH>, Error> + Send + Sync,
{
    let mut results = Vec::new();
    for entry in glob(&format_sstr!("{log_prefix}*"))? {
        let fname = entry?;
        let metadata = fname.metadata()?;
        let modified: OffsetDateTime = metadata.modified()?.into();
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

    let max_datetime: Option<OffsetDateTime> = match hc.pool.as_ref() {
        Some(pool) => IntrusionLog::get_max_datetime(pool, service, server).await?,
        None => None,
    };

    let inserts = results
        .into_iter()
        .filter_map(|log_line| {
            let cond = match max_datetime.as_ref() {
                Some(maxdt) => log_line.timestamp > (*maxdt).into(),
                None => true,
            };
            if cond {
                Some(IntrusionLog {
                    id: -1,
                    service: service.to_str().into(),
                    server: server.to_str().into(),
                    datetime: log_line.timestamp,
                    host: log_line.host,
                    username: log_line.user,
                })
            } else {
                None
            }
        })
        .sorted_by(|i0, i1| Ord::cmp(&i0.datetime, &i1.datetime))
        .dedup_by(|i0, i1| {
            (i0.datetime == i1.datetime) && (i0.host == i1.host) && (i0.username == i1.username)
        })
        .collect();
    Ok(inserts)
}

/// # Errors
/// Return error if db query fails
pub fn parse_log_line_apache(_: i32, line: &str) -> Result<Option<LogLineSSH>, Error> {
    let tokens: SmallVec<[&str; 5]> = line.split_whitespace().take(5).collect();
    if tokens.len() < 5 {
        return Ok(None);
    }
    let host = tokens[0];
    let host = if host.len() > 60 { &host[0..60] } else { host };
    if !host.contains('.') {
        return Ok(None);
    }
    let timestr = tokens[3..5].join("").replace('[', "").replace(']', "");
    let timestamp = OffsetDateTime::parse(
        &timestr,
        format_description!(
            "[day padding:none]/[month repr:short]/[year]:[hour]:[minute]:[second][offset_hour \
             sign:mandatory][offset_minute]"
        ),
    )?;
    let result = LogLineSSH {
        host: host.into(),
        user: None,
        timestamp: timestamp.to_timezone(UTC).into(),
    };
    Ok(Some(result))
}

/// # Errors
/// Return error if db query fails
pub async fn parse_systemd_logs_sshd_all(
    hc: &HostCountryMetadata,
    server: Host,
) -> Result<Vec<IntrusionLog>, Error> {
    let max_datetime: Option<OffsetDateTime> = match hc.pool.as_ref() {
        Some(pool) => {
            let pool = pool.clone();
            IntrusionLog::get_max_datetime(&pool, Service::Ssh, server).await?
        }
        None => None,
    };

    let inserts = parse_systemd_logs_sshd(server)
        .await?
        .into_iter()
        .filter(|log_line| match max_datetime.as_ref() {
            Some(maxdt) => log_line.datetime > (*maxdt).into(),
            None => true,
        })
        .collect();
    Ok(inserts)
}

/// # Errors
/// Return error if db query fails
pub async fn parse_systemd_logs_sshd(server: Host) -> Result<Vec<IntrusionLog>, Error> {
    let command = Command::new("journalctl")
        .args(&[
            "-o",
            "json",
            "--output-fields=UNIT,MESSAGE,__REALTIME_TIMESTAMP",
        ])
        .output()
        .await?;
    let stdout = String::from_utf8_lossy(&command.stdout);
    stdout
        .split('\n')
        .filter(|line| line.contains("__REALTIME_TIMESTAMP"))
        .map(|line| {
            if line.contains("Invalid user") {
                let log: ServiceLogLine = serde_json::from_str(line)?;
                let log_line: LogLineSSH = log.parse_sshd()?;
                Ok(Some(IntrusionLog {
                    id: -1,
                    service: Service::Ssh.to_str().into(),
                    server: server.to_str().into(),
                    datetime: log_line.timestamp,
                    host: log_line.host,
                    username: log_line.user,
                }))
            } else if line.contains("nginx") {
                let log: ServiceLogLine = serde_json::from_str(line)?;
                Ok(log.parse_nginx()?.map(|log_line| IntrusionLog {
                    id: -1,
                    service: Service::Nginx.to_str().into(),
                    server: server.to_str().into(),
                    datetime: log_line.timestamp,
                    host: log_line.host,
                    username: log_line.user,
                }))
            } else {
                Ok(None)
            }
        })
        .filter_map(Result::transpose)
        .collect()
}

/// # Errors
/// Return error if db query fails
pub async fn parse_systemd_logs_sshd_daemon(config: &Config, pool: &PgPool) -> Result<(), Error> {
    let mut p = Command::new("journalctl")
        .args(&[
            "-o",
            "json",
            "--output-fields=UNIT,MESSAGE,__REALTIME_TIMESTAMP",
            "-f",
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = p.stdout.take().ok_or_else(|| format_err!("No Stdout"))?;
    let reader = io::BufReader::new(stdout);
    let stdout_task: JoinHandle<Result<(), Error>> = {
        let config = config.clone();
        let pool = pool.clone();
        spawn(async move { process_systemd_sshd_output(reader, &config, &pool).await })
    };
    p.wait().await?;
    stdout_task.await??;
    Ok(())
}

async fn process_systemd_sshd_output(
    mut reader: io::BufReader<impl AsyncRead + Unpin>,
    config: &Config,
    pool: &PgPool,
) -> Result<(), Error> {
    let mut buf = Vec::new();
    while let Ok(bytes) = reader.read_until(b'\n', &mut buf).await {
        if bytes > 0 {
            let line = String::from_utf8_lossy(&buf);
            if line.contains("__REALTIME_TIMESTAMP") {
                let log: ServiceLogLine = serde_json::from_str(&line)?;
                if line.contains("kex_exchange_identification")
                    || line.contains(
                        "error: maximum authentication attempts exceeded for invalid user",
                    )
                    || line.contains("Disconnected from invalid user")
                    || line.contains("Failed password for invalid user")
                    || line.contains(
                        "SSL_read() failed (SSL: error:0A000126:SSL routines::unexpected eof \
                         while reading) while keepalive",
                    )
                {
                    continue;
                }
                if line.contains("Invalid user") {
                    let log_line = log.parse_sshd()?;
                    let log_entry = log_line.into_intrusion_log("ssh", &config.server);
                    let conn = pool.get().await?;
                    debug!("proc sshd {:?}", log_entry);
                    log_entry.insert_single(&conn).await?;
                    continue;
                }
                if line.contains("nginx") {
                    if let Some(log_line) = log.parse_nginx()? {
                        let log_entry = log_line.into_intrusion_log("nginx", &config.server);
                        let conn = pool.get().await?;
                        debug!("proc nginx {:?}", log_entry);
                        log_entry.insert_single(&conn).await?;
                    }
                }
                if let Some(log_level) = LogLevel::line_contains_level(&line, None) {
                    let log: ServiceLogLine = serde_json::from_str(&line)?;
                    let log_time = log.get_datetime()?;
                    let log_message =
                        SystemdLogMessages::new(log_level, log.unit, &log.message, log_time);
                    debug!("proc level {log_level} {:?}", log_message);
                    log_message.insert(pool).await?;
                }
            }
        } else {
            break;
        }
        buf.clear();
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceLogLine<'a> {
    #[serde(alias = "UNIT")]
    unit: Option<&'a str>,
    #[serde(alias = "__REALTIME_TIMESTAMP")]
    timestamp: &'a str,
    #[serde(alias = "MESSAGE")]
    message: StackString,
}

impl ServiceLogLine<'_> {
    pub fn get_datetime(&self) -> Result<DateTimeType, Error> {
        let timestamp: i64 = self.timestamp.parse()?;
        let nanoseconds = (timestamp % 1_000_000 * 1000) as i64;
        let timestamp = (OffsetDateTime::from_unix_timestamp((timestamp / 1_000_000) as i64)?
            + Duration::nanoseconds(nanoseconds))
        .into();
        Ok(timestamp)
    }

    fn parse_sshd(&self) -> Result<LogLineSSH, Error> {
        let timestamp = self.get_datetime()?;
        let (host, user) = parse_log_message(&self.message)?
            .ok_or_else(|| format_err!("Failed to parse {}", self.message))?;

        Ok(LogLineSSH {
            timestamp,
            host: host.into(),
            user: Some(user.into()),
        })
    }

    fn parse_nginx(&self) -> Result<Option<LogLineSSH>, Error> {
        let timestamp = self.get_datetime()?;
        let tokens: SmallVec<[&str; 3]> = self.message.split_whitespace().take(3).collect();
        if tokens.len() < 3 {
            return Ok(None);
        }
        let host = tokens[2];
        let host = if host.len() > 60 { &host[0..60] } else { host };
        if host.parse::<Ipv4Addr>().is_err() {
            return Ok(None);
        }
        Ok(Some(LogLineSSH {
            host: host.into(),
            user: None,
            timestamp,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct ServiceLogEntry {
    timestamp: DateTimeType,
    message: StackString,
    hostname: StackString,
}

impl fmt::Display for ServiceLogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.timestamp, self.hostname, self.message)
    }
}

/// # Errors
/// Returns error on db query failure
pub async fn process_systemd_logs(config: &Config, pool: &PgPool) -> Result<(), Error> {
    let ses_instance = SesInstance::new(None);
    let sending_email_address = match &config.sending_email_address {
        Some(e) => e,
        None => {
            error!("No sending email given");
            return Err(format_err!("No sending email given"));
        }
    };
    let alert_email_address = match &config.alert_email_address {
        Some(e) => e,
        None => {
            error!("No alert email given");
            return Err(format_err!("No alert email given"));
        }
    };
    debug!("{sending_email_address} {alert_email_address}");
    loop {
        if let Some(message) = SystemdLogMessages::get_oldest_message(pool).await? {
            if message.log_level >= config.alert_log_level {
                let subject = format_sstr!("Systemd Alert {} {}", config.server, message.log_level);
                ses_instance
                    .send_email(
                        sending_email_address.as_str(),
                        alert_email_address.as_str(),
                        &subject,
                        &message.log_message,
                    )
                    .await?;
                sleep(std::time::Duration::from_secs(10)).await;
            }
            message.set_message_processed(pool).await?;
        } else {
            sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use log::debug;
    use stack_string::StackString;
    use std::fs::File;
    use time::OffsetDateTime;

    use crate::{
        config::Config,
        host_country_metadata::HostCountryMetadata,
        models::LogLevel,
        parse_logs::{
            parse_all_log_files, parse_log_file, parse_log_line_apache, parse_log_line_ssh,
            parse_systemd_logs_sshd, ServiceLogLine, SystemdLogMessages,
        },
        pgpool::PgPool,
        Host, Service,
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
        let year = OffsetDateTime::now_utc().year();
        let results = parse_log_file(year, infile, &parse_log_line_ssh).unwrap();
        println!("{}", results.len());
        assert!(results.len() == 20);
    }

    #[tokio::test]
    #[ignore]
    async fn test_parse_all_log_files_ssh() -> Result<(), Error> {
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let mut hc = HostCountryMetadata::from_pool(&pool).await?;
        hc.pool = None;
        let results = parse_all_log_files(
            &hc,
            Service::Ssh,
            Host::Home,
            &parse_log_line_ssh,
            "tests/data/test_auth.log",
        )
        .await?;
        println!("{}", results.len());
        assert!(results.len() == 18);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_parse_systemd_logs_sshd() -> Result<(), Error> {
        let logs = parse_systemd_logs_sshd(Host::Home).await?;
        println!("{:?}", logs[0]);
        assert!(logs.len() > 0);
        Ok(())
    }

    #[test]
    fn test_process_systemd_sshd_log_line() -> Result<(), Error> {
        let line = r#"{"__REALTIME_TIMESTAMP":"1655046591494032","_SOURCE_REALTIME_TIMESTAMP":"1655046591493997","__CURSOR":"s=5726468a2162439e9e18a191202b1a7b;i=28e9c;b=e8ee305cff53408da12356a3876792ba;m=370bd562e;t=5e141902c3790;x=ec3c36f10424aa47","__MONOTONIC_TIMESTAMP":"14776358446","MESSAGE":"Invalid user ark from 43.154.144.211 port 42608","_BOOT_ID":"e8ee305cff53408da12356a3876792ba"}"#;
        let log: ServiceLogLine = serde_json::from_str(line)?;
        let log_line = log.parse_sshd()?;
        let log_entry = log_line.into_intrusion_log("ssh", "home.ddboline.net");
        println!("{log_entry:?}");
        assert_eq!(log_entry.id, -1);
        assert_eq!(&log_entry.service, "ssh");
        assert_eq!(&log_entry.server, "home.ddboline.net");
        assert_eq!(&log_entry.host, "43.154.144.211");
        assert_eq!(
            log_entry.username.as_ref().map(StackString::as_str),
            Some("ark")
        );
        Ok(())
    }

    #[test]
    fn test_process_systemd_unit() -> Result<(), Error> {
        let lines = include_str!("../tests/data/test_systemd.json");
        let mut logs = Vec::new();
        for line in lines.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let log: ServiceLogLine = serde_json::from_str(line)?;
            let log_level = LogLevel::line_contains_level(line, None).unwrap();
            assert_eq!(log_level, LogLevel::Error);
            let log_time = log.get_datetime()?;
            let log_message = SystemdLogMessages::new(log_level, log.unit, &log.message, log_time);
            logs.push(log_message);
        }
        assert_eq!(logs.len(), 24);
        Ok(())
    }
}
