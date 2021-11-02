use anyhow::Error;
use postgres_query::FromSqlRow;
use stack_string::StackString;

use crate::pgpool::PgPool;

#[derive(FromSqlRow)]
pub struct CountryCount {
    pub country: StackString,
    pub count: i64,
}

pub async fn get_country_count_recent(
    pool: &PgPool,
    service: &str,
    server: &str,
    ndays: i32,
) -> Result<Vec<CountryCount>, Error> {
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
    let conn = pool.get().await?;
    query.fetch(&conn).await.map_err(Into::into)
}
