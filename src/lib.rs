#[macro_use]
extern crate diesel;
#[macro_use]
extern crate serde_derive;

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
use retry::{delay::jitter, delay::Exponential, retry};

pub fn exponential_retry<T, U>(closure: T) -> Result<U, Error>
where
    T: Fn() -> Result<U, Error>,
{
    retry(
        Exponential::from_millis(2)
            .map(jitter)
            .map(|x| x * 500)
            .take(6),
        || {
            closure().map_err(|e| {
                error!("Got error {:?} , retrying", e);
                e
            })
        },
    )
    .map_err(|e| format_err!("{:?}", e))
}
