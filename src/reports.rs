use failure::Error;

use crate::pgpool_pg::PgPoolPg;
use crate::row_index_trait::RowIndexTrait;

pub fn get_country_count_recent(
    pool: &PgPoolPg,
    service: &str,
    server: &str,
    ndays: i32,
) -> Result<Vec<(String, i64)>, Error> {
    let query = format!(
        r#"
        SELECT c.country, count(1) AS COUNT
        FROM intrusion_log a
            JOIN host_country b ON a.host = b.host
            JOIN country_code c ON b.code = c.code
        WHERE a.datetime >= ('now'::text::date - '{} days'::interval)
            AND a.service = $1
            AND a.server = $2
        GROUP BY c.country
        ORDER BY (count(1)) DESC
    "#,
        ndays
    );
    pool.get()?
        .query(query.as_str(), &[&service, &server])?
        .iter()
        .map(|row| {
            let country: String = row.get_idx(0)?;
            let count: i64 = row.get_idx(1)?;
            Ok((country, count))
        })
        .collect()
}
