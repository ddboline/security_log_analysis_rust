use anyhow::{format_err, Error};
use chrono::{DateTime, Utc};
use futures::future::try_join_all;
use itertools::Itertools;
use log::debug;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use refinery::embed_migrations;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{collections::HashSet, env::var, net::ToSocketAddrs, process::Stdio, str::FromStr};
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
    task::spawn_blocking,
};

use crate::{
    config::Config,
    host_country_metadata::HostCountryMetadata,
    models::IntrusionLog,
    parse_logs::{
        parse_all_log_files, parse_log_line_apache, parse_log_line_ssh, parse_systemd_logs_sshd_all,
    },
    pgpool::PgPool,
    reports::get_country_count_recent,
};

embed_migrations!("migrations");

#[derive(Debug)]
pub enum ParseActions {
    Parse,
    Serialize,
    Sync,
    CountryPlot,
    AddHost,
    RunMigrations,
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
            "run-migrations" => Ok(Self::RunMigrations),
            _ => Err(format_err!("Invalid Action")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostName(pub StackString);

impl FromStr for HostName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let host_port_str = format!("{}:{}", s, 22);
        host_port_str.to_socket_addrs()?;
        Ok(Self(s.into()))
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
    pub username: Option<StackString>,
    #[structopt(long)]
    /// List of <host>:<country code> combinations i.e. 8.8.8.8:US
    pub host_codes: Vec<StackString>,
    #[structopt(short, long)]
    pub number_of_entries: Option<usize>,
}

impl ParseOpts {
    pub async fn process_args() -> Result<(), Error> {
        let opts = Self::from_args();

        let stdout = StdoutChannel::<StackString>::new();

        match opts.action {
            ParseActions::Parse => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for parse action"))?;
                debug!("got here {}", line!());
                let mut inserts = {
                    let metadata = metadata.clone();
                    let server = server.clone();
                    parse_systemd_logs_sshd_all(&metadata, &server.0).await?
                };
                stdout.send(format!("new lines ssh {}", inserts.len()));
                inserts.extend({
                    let metadata = metadata.clone();
                    parse_all_log_files(
                        &metadata,
                        "nginx",
                        &server.0,
                        &parse_log_line_apache,
                        "/var/log/nginx/access.log",
                    )
                    .await?
                });

                stdout.send(format!("new lines {}", inserts.len()));
                let new_hosts: HashSet<_> =
                    inserts.iter().map(|item| item.host.to_string()).collect();
                stdout.send(format!("new hosts {:#?}", new_hosts));
                let futures = new_hosts.into_iter().map(|host| {
                    let metadata = metadata.clone();
                    async move { metadata.get_country_info(&host).await }
                });
                try_join_all(futures).await?;
                IntrusionLog::insert(&pool, &inserts).await?;
            }
            ParseActions::Serialize => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let number_of_entries = opts.number_of_entries;
                let datetime = match opts.datetime {
                    Some(d) => d.0,
                    None => Utc::now(),
                };
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for ser action"))?;
                for service in &["ssh", "apache"] {
                    let results = IntrusionLog::get_intrusion_log_filtered(
                        &pool,
                        service,
                        &server.0,
                        Some(datetime),
                        None,
                        number_of_entries,
                    )
                    .await?;
                    for result in results {
                        stdout.send(serde_json::to_string(&result)?);
                    }
                }
            }
            ParseActions::Sync => {
                async fn get_max_datetime(
                    pool: &PgPool,
                    server: &HostName,
                ) -> Result<DateTime<Utc>, Error> {
                    let result = if let Some(dt) =
                        IntrusionLog::get_max_datetime(pool, "ssh", &server.0)
                            .await?
                            .as_ref()
                    {
                        if let Ok(Some(dt2)) =
                            IntrusionLog::get_max_datetime(pool, "nginx", &server.0).await
                        {
                            if *dt < dt2 {
                                *dt
                            } else {
                                dt2
                            }
                        } else {
                            *dt
                        }
                    } else {
                        Utc::now()
                    };
                    Ok(result)
                }

                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                debug!("{:?}", opts);
                let server = opts
                    .server
                    .ok_or_else(|| format_err!("Must specify server for sync action"))?;
                let username = opts
                    .username
                    .as_ref()
                    .map_or_else(|| config.username.as_str(), StackString::as_str);
                let user_host = format!("{}@{}", username, server.0);
                let command = format!("security-log-parse-rust parse -s {}", server.0);
                debug!("{}", command);
                let status = Command::new("ssh")
                    .args(&[&user_host, &command])
                    .status()
                    .await?;
                if !status.success() {
                    return Err(format_err!("{} failed", command));
                }

                let max_datetime = { get_max_datetime(&pool, &server).await? };
                debug!("{:?}", max_datetime);

                let user_host = format!("{}@{}", username, server.0);
                let command = format!(
                    "security-log-parse-rust ser -s {} -d {}",
                    server.0,
                    max_datetime.to_rfc3339(),
                );
                debug!("{}", command);
                let mut process = Command::new("ssh")
                    .args(&[&user_host, &command])
                    .stdout(Stdio::piped())
                    .spawn()?;

                let mut inserts = HashSet::new();
                if let Some(stdout) = process.stdout.take() {
                    let mut reader = BufReader::new(stdout);
                    let mut line = String::new();
                    loop {
                        if reader.read_line(&mut line).await? == 0 {
                            break;
                        }
                        let val: IntrusionLog = serde_json::from_str(&line)?;
                        inserts.insert(val);
                        line.clear();
                    }
                }

                process.wait().await?;

                let new_hosts: HashSet<_> =
                    inserts.iter().map(|item| item.host.to_string()).collect();

                let futures = new_hosts.into_iter().map(|host| {
                    let metadata = metadata.clone();
                    async move { metadata.get_country_info(&host).await }
                });
                try_join_all(futures).await?;

                let mut existing_entries = {
                    IntrusionLog::get_intrusion_log_filtered(
                        &pool,
                        "ssh",
                        &server.0,
                        Some(max_datetime),
                        None,
                        None,
                    )
                    .await?
                };
                existing_entries.extend_from_slice(&{
                    IntrusionLog::get_intrusion_log_filtered(
                        &pool,
                        "apache",
                        &server.0,
                        Some(max_datetime),
                        None,
                        None,
                    )
                    .await?
                });
                let existing_entries: HashSet<IntrusionLog> =
                    existing_entries.into_iter().map(Into::into).collect();
                let inserts: Vec<_> = inserts.difference(&existing_entries).cloned().collect();
                IntrusionLog::insert(&pool, &inserts).await?;
                stdout.send(format!("inserts {}", inserts.len()));
            }
            ParseActions::CountryPlot => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
                for service in &["ssh", "apache", "nginx"] {
                    for server_prefix in &["home", "cloud"] {
                        let server = format!("{}.ddboline.net", server_prefix);
                        let results = get_country_count_recent(&pool, service, &server, 30)
                            .await?
                            .into_iter()
                            .map(|cc| format!(r#"["{}", {}]"#, cc.country, cc.count))
                            .join(",");
                        let results =
                            template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);

                        if let Some(export_dir) = config.export_dir.as_ref() {
                            let outfname =
                                format!("{}_intrusion_attempts_{}.html", service, server_prefix);
                            let outpath = export_dir.join(&outfname);
                            let mut output = File::create(&outpath).await?;
                            output.write(results.as_bytes()).await?;
                        }
                    }
                }
            }
            ParseActions::AddHost => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                for host_country in &opts.host_codes {
                    let vals: SmallVec<[&str; 2]> = host_country.split(':').take(2).collect();
                    if vals.len() < 2 {
                        continue;
                    }
                    match vals.get(..2) {
                        Some([host, code]) => {
                            metadata.insert_host_code(host, code).await?;
                        }
                        _ => continue,
                    }
                }
            }
            ParseActions::RunMigrations => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let mut client = pool.get().await?;
                migrations::runner().run_async(&mut **client).await?;
            }
        }
        stdout.close().await
    }
}
