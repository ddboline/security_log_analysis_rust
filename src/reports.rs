use anyhow::Error;

use crate::pgpool_pg::PgPoolPg;
use crate::stack_string::StackString;

pub async fn get_country_count_recent(
    pool: &PgPoolPg,
    service: &str,
    server: &str,
    ndays: i32,
) -> Result<Vec<(StackString, i64)>, Error> {
    let query = postgres_query::query_dyn!(
        &format!(
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
    pool.get()
        .await?
        .query(query.sql(), query.parameters())
        .await?
        .iter()
        .map(|row| {
            let country: StackString = row.try_get("country")?;
            let count: i64 = row.try_get("count")?;
            Ok((country, count))
        })
        .collect()
}
