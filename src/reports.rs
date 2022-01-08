use anyhow::{format_err, Error};
use postgres_query::FromSqlRow;
use rweb::Schema;
use stack_string::{format_sstr, StackString};
use std::{fmt, fmt::Write, str::FromStr};

use crate::{pgpool::PgPool, CountryCount, Host, Service};

pub async fn get_country_count_recent(
    pool: &PgPool,
    service: Service,
    server: Host,
    ndays: i32,
) -> Result<Vec<CountryCount>, Error> {
    let service = service.to_str();
    let server = server.to_str();
    let query = postgres_query::query_dyn!(
        &format_sstr!(
            r#"
        SELECT c.country, count(1) AS count
        FROM intrusion_log a
            JOIN host_country b ON a.host = b.host
            JOIN country_code c ON b.code = c.code
        WHERE a.datetime >= ('now'::text::date - '{} days'::interval)
            AND a.service = $service
            AND a.server = $server
        GROUP BY c.country
        ORDER BY (count(1)) DESC
    "#,
            ndays
        ),
        service = service,
        server = server
    )?;
    let conn = pool.get().await?;
    query.fetch(&conn).await.map_err(Into::into)
}
