use anyhow::Error;
use itertools::Itertools;
use log::debug;
use refinery::embed_migrations;
use smallvec::SmallVec;
use stack_string::{format_sstr, StackString};
use std::{collections::HashSet, path::PathBuf};
use stdout_channel::StdoutChannel;
use structopt::StructOpt;
use tokio::{
    fs::{read_to_string, File},
    io::{stdin, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

use crate::{
    config::Config,
    host_country_metadata::HostCountryMetadata,
    models::{HostCountry, IntrusionLog},
    parse_logs::parse_systemd_logs_sshd_all,
    pgpool::PgPool,
    polars_analysis::{insert_db_into_parquet, read_parquet_files},
    reports::get_country_count_recent,
    s3_sync::S3Sync,
    Host, Service,
};

embed_migrations!("migrations");

#[derive(StructOpt, Debug)]
pub enum ParseOpts {
    /// Parse logs
    Parse,
    /// Cleanup
    Cleanup,
    /// Create plot
    Plot,
    /// Add hosts
    AddHost {
        /// List of <host>:<country code> combinations i.e. 8.8.8.8:US
        host_codes: Vec<StackString>,
    },
    /// Run migrations
    RunMigrations,
    /// Sync files with S3
    Sync {
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
    Import {
        #[structopt(short, long)]
        /// table: allowed values: [`intrusion_log`, `host_country`]
        table: StackString,
        #[structopt(short, long)]
        filepath: Option<PathBuf>,
    },
    Export {
        #[structopt(short, long)]
        /// table: allowed values: [`intrusion_log`, `host_country`]
        table: StackString,
        #[structopt(short, long)]
        filepath: Option<PathBuf>,
    },
}

impl ParseOpts {
    /// # Errors
    /// Return error if db query fails
    pub async fn process_args() -> Result<(), Error> {
        let opts = ParseOpts::from_args();
        let config = Config::init_config()?;
        let stdout = StdoutChannel::<StackString>::new();

        match opts {
            ParseOpts::Parse => {
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                debug!("got here {}", line!());
                let inserts = parse_systemd_logs_sshd_all(&metadata, config.server).await?;
                stdout.send(format_sstr!("new lines ssh {}", inserts.len()));
                let new_hosts: HashSet<_> = inserts.iter().map(|item| item.host.clone()).collect();
                stdout.send(format_sstr!("new hosts {new_hosts:#?}"));
                for host in new_hosts {
                    metadata.get_country_info(&host).await?;
                }
                IntrusionLog::insert(&pool, &inserts).await?;
            }
            ParseOpts::Cleanup => {
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool).await?;
                for host in HostCountry::get_dangling_hosts(&pool).await? {
                    let host_country = metadata.get_country_info(&host).await?;
                    let output = serde_json::to_string(&host_country)?;
                    stdout.send(output);
                }
            }
            ParseOpts::Sync { directory } => {
                let sync = S3Sync::new();
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                stdout.send(
                    sync.sync_dir("security-log-analysis", &directory, &config.s3_bucket, true)
                        .await?,
                );
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
                let mut written = 0;
                for service in [Service::Ssh, Service::Apache, Service::Nginx] {
                    for server in [Host::Home, Host::Cloud] {
                        let results = get_country_count_recent(&pool, service, server, 30)
                            .await?
                            .into_iter()
                            .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
                            .join(",");
                        let results =
                            template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);

                        if let Some(export_dir) = config.export_dir.as_ref() {
                            let outfname = format_sstr!(
                                "{}_intrusion_attempts_{}.html",
                                service,
                                server.get_prefix()
                            );
                            let outpath = export_dir.join(&outfname);
                            let mut output = File::create(&outpath).await?;
                            written += output.write(results.as_bytes()).await?;
                        }
                    }
                }
                debug!("{written} bytes written");
            }
            ParseOpts::RunMigrations => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let mut client = pool.get().await?;
                migrations::runner().run_async(&mut **client).await?;
            }
            ParseOpts::Db { directory } => {
                let directory = directory.unwrap_or_else(|| config.cache_dir.clone());
                let pool = PgPool::new(&config.database_url);
                stdout.send(insert_db_into_parquet(&pool, &directory).await?.join("\n"));
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
                    .map(|c| format_sstr!("country {} count {}", c.country, c.count))
                    .take(10)
                    .join("\n");
                stdout.send(body);
            }
            ParseOpts::Import { table, filepath } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);

                let data = if let Some(filepath) = filepath {
                    read_to_string(&filepath).await?
                } else {
                    let mut stdin = stdin();
                    let mut buf = String::new();
                    stdin.read_to_string(&mut buf).await?;
                    buf
                };
                match table.as_str() {
                    "intrusion_log" => {
                        let results: Vec<IntrusionLog> = serde_json::from_str(&data)?;
                        let inserts = IntrusionLog::insert(&pool, &results).await?;
                        stdout.send(format_sstr!("Inserts {inserts}"));
                    }
                    "host_country" => {
                        let results: Vec<HostCountry> = serde_json::from_str(&data)?;
                        let mut inserts = 0;
                        for result in results {
                            inserts += result.insert_host_country(&pool).await?.map_or(0, |_| 1);
                        }
                        stdout.send(format_sstr!("Inserts {inserts}"));
                    }
                    _ => {}
                }
            }
            ParseOpts::Export { table, filepath } => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);

                let mut file: Box<dyn AsyncWrite + Unpin + Send + Sync> = if let Some(filepath) = filepath {
                    Box::new(File::create(&filepath).await?)
                } else {
                    Box::new(tokio::io::stdout())
                };
                match table.as_str() {
                    "intrusion_log" => {
                        let results = IntrusionLog::get_intrusion_log_filtered(
                            &pool,
                            None,
                            None,
                            None,
                            None,
                            Some(1000),
                            None,
                        )
                        .await?;
                        file.write_all(&serde_json::to_vec(&results)?).await?;
                    }
                    "host_country" => {
                        let results =
                            HostCountry::get_host_country(&pool, None, Some(1000), true).await?;
                        file.write_all(&serde_json::to_vec(&results)?).await?;
                    }
                    _ => {}
                }
            }
        }
        stdout.close().await?;
        Ok(())
    }
}
