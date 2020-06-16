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
pub mod stack_string;
pub mod stdout_channel;

use anyhow::{format_err, Error};
use log::error;
use retry::{
    delay::{jitter, Exponential},
    retry,
};

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
