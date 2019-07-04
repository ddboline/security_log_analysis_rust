use failure::Error;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use structopt::StructOpt;

use crate::config::Config;
use crate::host_country_metadata::HostCountryMetadata;
use crate::parse_logs::{parse_all_log_files, parse_log_line_apache, parse_log_line_ssh};
use crate::pgpool::PgPool;

#[derive(Debug)]
pub struct HostName(pub String);

impl FromStr for HostName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let host_port_str = format!("{}:{}", s, 22);
        Ok(HostName(s.to_string()))
    }
}

#[derive(StructOpt, Debug)]
pub struct ParseOpts {
    #[structopt(short = "s", long = "server", parse(try_from_str))]
    pub server: HostName,
}

impl ParseOpts {
    pub fn process_args() -> Result<(), Error> {
        let opts = ParseOpts::from_args();

        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let hc = HostCountryMetadata::from_pool(&pool)?;
        let mut results = parse_all_log_files(
            &hc,
            "ssh",
            &opts.server.0,
            &parse_log_line_ssh,
            "/var/log/auth.log",
        )?;
        results.extend(parse_all_log_files(
            &hc,
            "apache",
            &opts.server.0,
            &parse_log_line_apache,
            "/var/log/apache2/access.log",
        )?);
        println!("new lines {}", results.len());
        // hc.cleanup_intrusion_log()?;
        Ok(())
    }
}
