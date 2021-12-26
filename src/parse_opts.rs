use anyhow::{format_err, Error};
use chrono::{DateTime, Utc};
use futures::future::try_join_all;
use itertools::Itertools;
use log::debug;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use refinery::embed_migrations;
use rweb::Schema;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use stack_string::StackString;
use std::{
    collections::HashSet,
    env::var,
    fmt,
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    process::Stdio,
    str::FromStr,
};
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
    models::{get_max_datetime, IntrusionLog},
    parse_logs::{
        parse_all_log_files, parse_log_line_apache, parse_log_line_ssh, parse_systemd_logs_sshd_all,
    },
    pgpool::PgPool,
    polars_analysis::{insert_db_into_parquet, read_parquet_files, read_tsv_file},
    reports::get_country_count_recent,
    s3_sync::S3Sync,
    DateTimeInput, Host, Service,
};

embed_migrations!("migrations");

#[derive(StructOpt, Debug)]
pub enum ParseOpts {
    /// Parse logs
    Parse {
        #[structopt(short = "s", long = "server", parse(try_from_str))]
        server: Host,
    },
    /// Serialize entries
    Ser {
        #[structopt(short, long)]
        number_of_entries: Option<usize>,
        #[structopt(short = "d", long = "datetime", parse(try_from_str))]
        datetime: Option<DateTimeInput>,
        #[structopt(short = "s", long = "server", parse(try_from_str))]
        server: Host,
    },
    /// Create plot
    Plot,
    /// Add hosts
    AddHost {
        /// List of <host>:<country code> combinations i.e. 8.8.8.8:US
        host_codes: Vec<StackString>,
    },
    /// Run migrations
    RunMigrations,
    /// Sync database via SSH
    SshSync {
        #[structopt(short = "s", long = "server", parse(try_from_str))]
        server: Host,
        #[structopt(short = "u", long = "username")]
        username: Option<StackString>,
    },
    /// Sync files with S3
    Sync {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    /// Extract/transform/load TSV DB Data File
    Etl {
        #[structopt(short = "i", long = "input")]
        input: Option<PathBuf>,
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    /// Merge DB intrusion log entries with parquet files
    Db {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
    },
    /// Print most frequent countries
    Read {
        #[structopt(short = "d", long = "directory")]
        directory: Option<PathBuf>,
        #[structopt(short = "s", long = "service")]
        service: Option<Service>,
        #[structopt(short = "t", long = "server")]
        server: Option<Host>,
        #[structopt(short = "n", long = "ndays")]
        ndays: Option<i32>,
    },
}

impl ParseOpts {
    pub async fn process_args() -> Result<(), Error> {
        let default_input = Path::new(
            "/media/seagate4000/dilepton_tower_backup/intrusion_log_backup_20211216.sql.gz",
        )
        .to_path_buf();

        let opts = ParseOpts::from_args();
        let config = Config::init_config()?;
        let stdout = StdoutChannel::<StackString>::new();

        match opts {
            ParseOpts::Parse { server } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                debug!("got here {}", line!());
                let inserts = parse_systemd_logs_sshd_all(&metadata, server).await?;
                stdout.send(format!("new lines ssh {}", inserts.len()));
                let new_hosts: HashSet<_> =
                    inserts.iter().map(|item| item.host.to_string()).collect();
                stdout.send(format!("new hosts {:#?}", new_hosts));
                for host in new_hosts {
                    metadata.get_country_info(&host).await?;
                }
                IntrusionLog::insert(&pool, &inserts).await?;
            }
            ParseOpts::Sync { directory } => {
                let sync = S3Sync::new();
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                println!(
                    "{}",
                    sync.sync_dir("security-log-analysis", &directory, &config.s3_bucket, true,)
                        .await?
                );
            }
            ParseOpts::SshSync { server, username } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                let username = username
                    .as_ref()
                    .map_or_else(|| config.username.as_str(), StackString::as_str);
                let user_host = format!("{}@{}", username, server);
                let command = format!("security-log-parse-rust parse -s {}", server);
                debug!("{}", command);
                let status = Command::new("ssh")
                    .args(&[&user_host, &command])
                    .status()
                    .await?;
                if !status.success() {
                    return Err(format_err!("{} failed", command));
                }

                let max_datetime = { get_max_datetime(&pool, server).await? };
                debug!("{:?}", max_datetime);

                let user_host = format!("{}@{}", username, server);
                let command = format!(
                    "security-log-parse-rust ser -s {} -d {}",
                    server,
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

                let mut existing_entries = Vec::new();

                for service in [Service::Ssh, Service::Apache, Service::Nginx] {
                    existing_entries.extend_from_slice(
                        &IntrusionLog::get_intrusion_log_filtered(
                            &pool,
                            service,
                            server,
                            Some(max_datetime),
                            None,
                            None,
                        )
                        .await?,
                    )
                }

                let existing_entries: HashSet<IntrusionLog> =
                    existing_entries.into_iter().map(Into::into).collect();
                let inserts: Vec<_> = inserts.difference(&existing_entries).cloned().collect();
                IntrusionLog::insert(&pool, &inserts).await?;
                stdout.send(format!("inserts {}", inserts.len()));
            }
            ParseOpts::AddHost { host_codes } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                for host_country in &host_codes {
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
            ParseOpts::Plot => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
                for service in [Service::Ssh, Service::Apache, Service::Nginx] {
                    for server in [Host::Home, Host::Cloud] {
                        let results = get_country_count_recent(&pool, service, server, 30)
                            .await?
                            .into_iter()
                            .map(|cc| format!(r#"["{}", {}]"#, cc.country, cc.count))
                            .join(",");
                        let results =
                            template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);

                        if let Some(export_dir) = config.export_dir.as_ref() {
                            let outfname = format!(
                                "{}_intrusion_attempts_{}.html",
                                service,
                                server.get_prefix()
                            );
                            let outpath = export_dir.join(&outfname);
                            let mut output = File::create(&outpath).await?;
                            output.write(results.as_bytes()).await?;
                        }
                    }
                }
            }
            ParseOpts::RunMigrations => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let mut client = pool.get().await?;
                migrations::runner().run_async(&mut **client).await?;
            }
            ParseOpts::Ser {
                number_of_entries,
                datetime,
                server,
            } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let datetime = match datetime {
                    Some(d) => d.0,
                    None => Utc::now(),
                };
                for service in [Service::Ssh, Service::Apache, Service::Nginx] {
                    let results = IntrusionLog::get_intrusion_log_filtered(
                        &pool,
                        service,
                        server,
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
            ParseOpts::Etl { input, directory } => {
                let input = input.unwrap_or(default_input);
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                read_tsv_file(&input, &directory)?;
            }
            ParseOpts::Db { directory } => {
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                let pool = PgPool::new(&config.database_url);
                insert_db_into_parquet(&pool, &directory).await?;
            }
            ParseOpts::Read {
                directory,
                service,
                server,
                ndays,
            } => {
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                let body = read_parquet_files(&directory, service, server, ndays)?
                    .into_iter()
                    .map(|c| format!("country {} count {}", c.country, c.count))
                    .take(10)
                    .join("\n");
                println!("{}", body);
            }
        }
        Ok(())
    }
}
