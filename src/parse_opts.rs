use anyhow::{format_err, Error};
use chrono::{DateTime, Utc};
use futures::future::try_join_all;
use log::debug;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env::var,
    io::{stdout, BufRead, BufReader, Write},
    net::ToSocketAddrs,
    str::FromStr,
};
use structopt::StructOpt;
use subprocess::Exec;
use tokio::{fs::File, io::AsyncWriteExt};

use crate::{
    config::Config,
    host_country_metadata::HostCountryMetadata,
    models::{
        get_intrusion_log_filtered, get_intrusion_log_max_datetime, insert_intrusion_log,
        IntrusionLogInsert,
    },
    parse_logs::{parse_all_log_files, parse_log_line_apache, parse_log_line_ssh},
    pgpool::PgPool,
    pgpool_pg::PgPoolPg,
    reports::get_country_count_recent,
};

#[derive(Debug)]
pub enum ParseActions {
    Parse,
    Serialize,
    Sync,
    CountryPlot,
    AddHost,
}

impl FromStr for ParseActions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "parse" => Ok(Self::Parse),
            "serialize" | "ser" => Ok(Self::Serialize),
            "sync" => Ok(Self::Sync),
            "plot" | "country_plot" => Ok(Self::CountryPlot),
            "add_host" | "add" => Ok(Self::AddHost),
            _ => Err(format_err!("Invalid Action")),
        }
    }
}

#[derive(Debug)]
pub struct HostName(pub String);

impl FromStr for HostName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let host_port_str = format!("{}:{}", s, 22);
        host_port_str.to_socket_addrs()?;
        Ok(Self(s.to_string()))
    }
}

#[derive(Debug)]
pub struct DateTimeInput(pub DateTime<Utc>);

impl FromStr for DateTimeInput {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map(Self)
            .map_err(Into::into)
    }
}

#[derive(StructOpt, Debug)]
pub struct ParseOpts {
    /// parse, serialize|ser, sync, plot|country_plot, add|add_host
    #[structopt(parse(try_from_str), default_value = "parse")]
    pub action: ParseActions,
    #[structopt(short = "s", long = "server", parse(try_from_str))]
    pub server: Option<HostName>,
    #[structopt(short = "d", long = "datetime", parse(try_from_str))]
    pub datetime: Option<DateTimeInput>,
    #[structopt(short = "u", long = "username")]
    pub username: Option<String>,
    #[structopt(long)]
    /// List of <host>:<country code> combinations i.e. 8.8.8.8:US
    pub host_codes: Vec<String>,
}

impl ParseOpts {
    pub async fn process_args() -> Result<(), Error> {
        let opts = Self::from_args();

        match opts.action {
            ParseActions::Parse => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool)?;
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for parse action"))?;
                let mut inserts = parse_all_log_files(
                    &metadata,
                    "ssh",
                    &server.0,
                    &parse_log_line_ssh,
                    "/var/log/auth.log",
                )?;
                inserts.extend(parse_all_log_files(
                    &metadata,
                    "apache",
                    &server.0,
                    &parse_log_line_apache,
                    "/var/log/apache2/access.log",
                )?);
                writeln!(stdout().lock(), "new lines {}", inserts.len())?;
                let new_hosts: HashSet<_> =
                    inserts.iter().map(|item| item.host.to_string()).collect();
                let futures: Vec<_> = new_hosts
                    .into_iter()
                    .map(|host| {
                        let metadata = metadata.clone();
                        async move { metadata.get_country_info(&host).await }
                    })
                    .collect();
                try_join_all(futures).await?;
                insert_intrusion_log(&pool, &inserts)?;

                Ok(())
            }
            ParseActions::Serialize => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let datetime = match opts.datetime {
                    Some(d) => d.0,
                    None => Utc::now(),
                };
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for ser action"))?;
                for service in &["ssh", "apache"] {
                    let results = get_intrusion_log_filtered(&pool, service, &server.0, datetime)?;
                    for result in results {
                        writeln!(stdout().lock(), "{}", serde_json::to_string(&result)?)?;
                    }
                }
                Ok(())
            }
            ParseActions::Sync => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool)?;
                debug!("{:?}", opts);
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for sync action"))?;
                let username = opts.username.as_ref().unwrap_or_else(|| &config.username);
                let command = format!(
                    r#"ssh {}@{} "security-log-parse-rust parse -s {}""#,
                    username, server.0, server.0,
                );
                debug!("{}", command);
                let status = Exec::shell(&command).join()?.success();
                if !status {
                    return Err(format_err!("{} failed", command));
                }

                let max_datetime = get_intrusion_log_max_datetime(&pool, "ssh", &server.0)?
                    .as_ref()
                    .and_then(|dt| {
                        if let Ok(Some(dt2)) =
                            get_intrusion_log_max_datetime(&pool, "apache", &server.0)
                        {
                            if *dt > dt2 {
                                Some(*dt)
                            } else {
                                Some(dt2)
                            }
                        } else {
                            Some(*dt)
                        }
                    })
                    .unwrap_or_else(Utc::now);
                debug!("{:?}", max_datetime);
                let command = format!(
                    r#"ssh {}@{} "security-log-parse-rust ser -s {} -d {}""#,
                    username,
                    server.0,
                    server.0,
                    max_datetime.to_rfc3339(),
                );
                debug!("{}", command);
                let stream = Exec::shell(command).stream_stdout()?;
                let reader = BufReader::new(stream);
                let inserts: Result<Vec<_>, Error> = reader
                    .lines()
                    .map(|line| {
                        let l = line?;
                        let val: IntrusionLogInsert = serde_json::from_str(&l)?;
                        Ok(val)
                    })
                    .collect();
                let inserts = inserts?;
                let new_hosts: HashSet<_> =
                    inserts.iter().map(|item| item.host.to_string()).collect();
                let futures: Vec<_> = new_hosts
                    .into_iter()
                    .map(|host| {
                        let metadata = metadata.clone();
                        async move { metadata.get_country_info(&host).await }
                    })
                    .collect();
                try_join_all(futures).await?;
                insert_intrusion_log(&pool, &inserts)?;

                writeln!(stdout().lock(), "inserts {}", inserts.len())?;
                Ok(())
            }
            ParseActions::CountryPlot => {
                let config = Config::init_config()?;
                let pool = PgPoolPg::new(&config.database_url);
                let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
                for service in &["ssh", "apache"] {
                    for server_prefix in &["home", "cloud"] {
                        let server = format!("{}.ddboline.net", server_prefix);
                        let results: Vec<_> = get_country_count_recent(&pool, service, &server, 30)
                            .await?
                            .into_iter()
                            .map(|(x, y)| format!(r#"["{}", {}]"#, x, y))
                            .collect();
                        let results = template
                            .replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results.join(","));

                        if let Some(export_dir) = config.export_dir.as_ref() {
                            let outfname =
                                format!("{}_intrusion_attempts_{}.html", service, server_prefix);
                            let outpath = export_dir.join(&outfname);
                            let mut output = File::create(&outpath).await?;
                            output.write(results.as_bytes()).await?;
                        }
                    }
                }
                Ok(())
            }
            ParseActions::AddHost => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool)?;
                for host_country in &opts.host_codes {
                    let vals: Vec<_> = host_country.split(':').collect();
                    if vals.len() < 2 {
                        continue;
                    }
                    match vals[..2] {
                        [host, code] => {
                            metadata.insert_host_code(&host, &code)?;
                        }
                        _ => continue,
                    }
                }
                Ok(())
            }
        }
    }
}
