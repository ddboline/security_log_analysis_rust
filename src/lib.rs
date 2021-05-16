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

#[macro_use]
extern crate diesel;

pub mod config;
pub mod host_country_metadata;
pub mod iso_8601_datetime;
pub mod models;
pub mod parse_logs;
pub mod parse_opts;
pub mod pgpool;
pub mod pgpool_pg;
pub mod reports;
pub mod schema;

use anyhow::{format_err, Error};
use log::error;
// use retry::{
//     delay::{jitter, Exponential},
//     retry,
// };
use rand::{
    distributions::{Alphanumeric, Distribution, Uniform},
    thread_rng,
};
use std::{future::Future, time::Duration};
use tokio::time::sleep;

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
