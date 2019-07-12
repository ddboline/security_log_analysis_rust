use chrono::{DateTime, Utc};
use failure::{err_msg, Error};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::collections::HashSet;
use std::convert::TryInto;
use std::env::var;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
use std::str::FromStr;
use structopt::StructOpt;
use subprocess::Exec;

use crate::config::Config;
use crate::host_country_metadata::HostCountryMetadata;
use crate::map_result;
use crate::models::{
    get_intrusion_log_filtered, get_intrusion_log_max_datetime, insert_intrusion_log,
    IntrusionLogInsert, IntrusionLogSerde,
};
use crate::parse_logs::{parse_all_log_files, parse_log_line_apache, parse_log_line_ssh};
use crate::pgpool::PgPool;
use crate::pgpool_pg::PgPoolPg;
use crate::reports::get_country_count_recent;

#[derive(Debug)]
pub enum ParseActions {
    Parse,
    Serialize,
    Sync,
    CountryPlot,
}

impl FromStr for ParseActions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "parse" => Ok(ParseActions::Parse),
            "serialize" | "ser" => Ok(ParseActions::Serialize),
            "sync" => Ok(ParseActions::Sync),
            "plot" | "country_plot" => Ok(ParseActions::CountryPlot),
            _ => Err(err_msg("Invalid Action")),
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
        Ok(HostName(s.to_string()))
    }
}

#[derive(Debug)]
pub struct DateTimeInput(pub DateTime<Utc>);

impl FromStr for DateTimeInput {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DateTime::parse_from_rfc3339(s)
            .map(|d| d.with_timezone(&Utc))
            .map(DateTimeInput)
            .map_err(err_msg)
    }
}

#[derive(StructOpt, Debug)]
pub struct ParseOpts {
    /// parse, serialize|ser, sync, plot|country_plot
    #[structopt(parse(try_from_str), default_value = "parse")]
    pub action: ParseActions,
    #[structopt(short = "s", long = "server", parse(try_from_str))]
    pub server: Option<HostName>,
    #[structopt(short = "d", long = "datetime", parse(try_from_str))]
    pub datetime: Option<DateTimeInput>,
    #[structopt(short = "u", long = "username")]
    pub username: Option<String>,
}

impl ParseOpts {
    pub fn process_args() -> Result<(), Error> {
        let opts = ParseOpts::from_args();

        match opts.action {
            ParseActions::Parse => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool)?;
                let server = opts
                    .server
                    .ok_or_else(|| err_msg("Must specify server for parse action"))?;
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
                println!("new lines {}", inserts.len());
                let new_hosts: HashSet<_> = inserts.iter().map(|item| item.host.clone()).collect();
                let codes: Vec<_> = new_hosts
                    .into_par_iter()
                    .map(|host| metadata.get_country_info(&host))
                    .collect();
                let _: Vec<_> = map_result(codes)?;
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
                    .ok_or_else(|| err_msg("Must specify server for ser action"))?;
                for service in &["ssh", "apache"] {
                    let results = get_intrusion_log_filtered(&pool, service, &server.0, datetime)?;
                    for result in results {
                        let val: IntrusionLogSerde = result.into();
                        println!("{}", serde_json::to_string(&val)?);
                    }
                }
                Ok(())
            }
            ParseActions::Sync => {
                let config = Config::init_config()?;
                let pool = PgPool::new(&config.database_url);
                let metadata = HostCountryMetadata::from_pool(&pool)?;
                println!("{:?}", opts);
                let server = opts
                    .server
                    .ok_or_else(|| err_msg("Must specify server for sync action"))?;
                let username = opts.username.as_ref().unwrap_or_else(|| &config.username);
                let command = format!(
                    r#"ssh {}@{} "security-log-parse-rust parse -s {}""#,
                    username, server.0, server.0,
                );
                println!("{}", command);
                let status = Exec::shell(&command).join()?.success();
                if !status {
                    return Err(err_msg(format!("{} failed", command)));
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
                println!("{:?}", max_datetime);
                let command = format!(
                    r#"ssh {}@{} "security-log-parse-rust ser -s {} -d {}""#,
                    username,
                    server.0,
                    server.0,
                    max_datetime.to_rfc3339(),
                );
                println!("{}", command);
                let stream = Exec::shell(command).stream_stdout()?;
                let reader = BufReader::new(stream);
                let inserts: Vec<_> = reader
                    .lines()
                    .map(|line| {
                        let l = line?;
                        let val: IntrusionLogSerde = serde_json::from_str(&l)?;
                        let val: IntrusionLogInsert = val.try_into()?;
                        Ok(val)
                    })
                    .collect();
                let inserts: Vec<_> = map_result(inserts)?;
                let new_hosts: HashSet<_> = inserts.iter().map(|item| item.host.clone()).collect();
                let codes: Vec<_> = new_hosts
                    .into_par_iter()
                    .map(|host| metadata.get_country_info(&host))
                    .collect();
                let _: Vec<_> = map_result(codes)?;
                insert_intrusion_log(&pool, &inserts)?;

                println!("{}", inserts.len());
                Ok(())
            }
            ParseActions::CountryPlot => {
                let config = Config::init_config()?;
                let pool = PgPoolPg::new(&config.database_url);
                let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
                for service in &["ssh", "apache"] {
                    for server_prefix in &["home", "cloud"] {
                        let server = format!("{}.ddboline.net", server_prefix);
                        let results = get_country_count_recent(&pool, service, &server, 20)?;
                        let results: Vec<_> = results
                            .iter()
                            .map(|(x, y)| format!(r#"["{}", {}]"#, x, y))
                            .collect();
                        let results = template
                            .replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results.join(","));
                        let home_dir =
                            var("HOME").map_err(|e| err_msg(format!("No HOME directory {}", e)))?;
                        let outfname = format!(
                            "{}/public_html/{}_intrusion_attempts_{}.html",
                            home_dir, service, server_prefix
                        );
                        let mut output = File::create(&outfname)?;
                        write!(output, "{}", results)?;
                    }
                }
                Ok(())
            }
        }
    }
}