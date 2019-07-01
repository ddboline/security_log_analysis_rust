#[macro_use]
extern crate diesel;

pub mod config;
pub mod models;
pub mod parse_logs;
pub mod pgpool;
pub mod schema;

use failure::{err_msg, Error};
use std::iter::FromIterator;

pub fn map_result<T, U, V>(input: U) -> Result<V, Error>
where
    U: IntoIterator<Item = Result<T, Error>>,
    V: FromIterator<T>,
{
    let mut errors: Vec<_> = Vec::new();
    let output: V = input
        .into_iter()
        .filter_map(|item| match item {
            Ok(i) => Some(i),
            Err(e) => {
                errors.push(format!("{}", e));
                None
            }
        })
        .collect();
    if !errors.is_empty() {
        Err(err_msg(errors.join("\n")))
    } else {
        Ok(output)
    }
}
