#![allow(unused_imports)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::similar_names)]
#![allow(clippy::shadow_unrelated)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_panics_doc)]

pub mod config;
pub mod errors;
pub mod host_country_metadata;
pub mod iso_8601_datetime;
pub mod logged_user;
pub mod models;
pub mod parse_logs;
pub mod parse_opts;
pub mod pgpool;
pub mod polars_analysis;
pub mod reports;
pub mod s3_sync;

use anyhow::{format_err, Error};
use chrono::{DateTime, Utc};
use log::error;
use postgres_query::FromSqlRow;
use rand::{
    distributions::{Alphanumeric, Distribution, Uniform},
    thread_rng,
};
use rweb::Schema;
use stack_string::StackString;
use std::{fmt, future::Future, path::Path, str::FromStr, time::Duration};
use tokio::{process::Command, time::sleep};

pub async fn exponential_retry<T, U, F>(closure: T) -> Result<U, Error>
where
    T: Fn() -> F,
    F: Future<Output = Result<U, Error>>,
{
    let mut timeout: f64 = 1.0;
    let range = Uniform::from(0..1000);
    loop {
        match closure().await {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                sleep(Duration::from_millis((timeout * 1000.0) as u64)).await;
                timeout *= 4.0 * f64::from(range.sample(&mut thread_rng())) / 1000.0;
                if timeout >= 64.0 {
                    return Err(err);
                }
            }
        }
    }
}

pub async fn get_md5sum(filename: &Path) -> Result<StackString, Error> {
    if !Path::new("/usr/bin/md5sum").exists() {
        return Err(format_err!(
            "md5sum not installed (or not present at /usr/bin/md5sum"
        ));
    }
    let output = Command::new("/usr/bin/md5sum")
        .args(&[filename])
        .output()
        .await?;
    if output.status.success() {
        let buf = String::from_utf8_lossy(&output.stdout);
        for line in buf.split('\n') {
            if let Some(entry) = line.split_whitespace().next() {
                return Ok(entry.into());
            }
        }
    }
    Err(format_err!("Command failed"))
}

#[derive(FromSqlRow)]
pub struct CountryCount {
    pub country: StackString,
    pub count: i64,
}

#[derive(Debug, Clone, Copy, Schema)]
pub enum Host {
    Home,
    Cloud,
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "home" | "home.ddboline.net" => Ok(Self::Home),
            "cloud" | "cloud.ddboline.net" => Ok(Self::Cloud),
            _ => Err(format_err!("Not a valid Host")),
        }
    }
}

impl Host {
    pub fn get_prefix(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Cloud => "cloud",
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            Self::Home => "home.ddboline.net",
            Self::Cloud => "cloud.ddboline.net",
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

#[derive(Debug, Clone, Copy, Schema)]
pub enum Service {
    Apache,
    Nginx,
    Ssh,
}

impl FromStr for Service {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apache" => Ok(Self::Apache),
            "nginx" => Ok(Self::Nginx),
            "ssh" => Ok(Self::Ssh),
            _ => Err(format_err!("Not a valid service")),
        }
    }
}

impl Service {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Apache => "apache",
            Self::Nginx => "nginx",
            Self::Ssh => "ssh",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
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
