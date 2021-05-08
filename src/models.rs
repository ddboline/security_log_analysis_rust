use anyhow::{format_err, Error};
use avro_rs::{from_value, Codec, Reader, Schema, Writer};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl};
use futures::future::try_join_all;
use log::debug;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{fs::File, path::Path};
use tokio::{fs::create_dir_all, task::spawn_blocking};

use crate::{
    iso_8601_datetime,
    pgpool::{PgPool, PgPoolConnection},
    pgpool_pg::PgPoolPg,
    schema::{country_code, host_country, intrusion_log},
};

pub const INTRUSION_LOG_AVRO_SCHEMA: &str = r#"
    {
        "namespace": "security_log_analysis.avro",
        "type": "record",
        "name": "IntrusionLog",
        "fields": [
            {"name": "service", "type": "string"},
            {"name": "server", "type": "string"},
            {"name": "datetime", "type": "string"},
            {"name": "host", "type": "string"},
            {"name": "username", "type": ["string", "null"]}
        ]
    }
"#;

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "country_code"]
pub struct CountryCode {
    pub code: StackString,
    pub country: StackString,
}

impl CountryCode {
    pub fn get_country_code_list(pool: &PgPool) -> Result<Vec<Self>, Error> {
        use crate::schema::country_code::dsl::country_code;

        let conn = pool.get()?;

        country_code.load(&conn).map_err(Into::into)
    }
}

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "host_country"]
pub struct HostCountry {
    pub host: StackString,
    pub code: StackString,
    pub ipaddr: Option<StackString>,
}

impl HostCountry {
    pub fn get_host_country(pool: &PgPool) -> Result<Vec<Self>, Error> {
        use crate::schema::host_country::dsl::host_country;

        let conn = pool.get()?;

        host_country.load(&conn).map_err(Into::into)
    }

    pub fn insert_host_country(&self, pool: &PgPool) -> Result<(), Error> {
        use crate::schema::host_country::dsl::{host, host_country};
        let conn = pool.get()?;

        conn.transaction(|| {
            let current_entry: Vec<Self> = host_country.filter(host.eq(&self.host)).load(&conn)?;
            if current_entry.is_empty() {
                diesel::insert_into(host_country)
                    .values(self)
                    .execute(&conn)?;
            }
            Ok(())
        })
    }
}

#[derive(Queryable, Clone, Debug, Serialize, Deserialize)]
pub struct IntrusionLog {
    pub id: i32,
    pub service: StackString,
    pub server: StackString,
    #[serde(with = "iso_8601_datetime")]
    pub datetime: DateTime<Utc>,
    pub host: StackString,
    pub username: Option<StackString>,
}

impl IntrusionLog {
    pub fn get_max_datetime(
        pool: &PgPool,
        service_val: &str,
        server_val: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let conn = pool.get()?;
        Self::_get_max_datetime(&conn, service_val, server_val)
    }

    fn _get_max_datetime(
        conn: &PgPoolConnection,
        service_val: &str,
        server_val: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        use crate::schema::intrusion_log::dsl::{datetime, intrusion_log, server, service};
        use diesel::dsl::max;

        intrusion_log
            .select(max(datetime))
            .filter(service.eq(service_val))
            .filter(server.eq(server_val))
            .first(conn)
            .map_err(Into::into)
    }

    fn _get_min_datetime(
        conn: &PgPoolConnection,
        service_val: &str,
        server_val: &str,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        use crate::schema::intrusion_log::dsl::{datetime, intrusion_log, server, service};
        use diesel::dsl::min;

        intrusion_log
            .select(min(datetime))
            .filter(service.eq(service_val))
            .filter(server.eq(server_val))
            .first(conn)
            .map_err(Into::into)
    }

    pub fn get_intrusion_log_filtered(
        pool: &PgPool,
        service_val: &str,
        server_val: &str,
        min_datetime: Option<DateTime<Utc>>,
        max_datetime: Option<DateTime<Utc>>,
        max_entries: Option<usize>,
    ) -> Result<Vec<Self>, Error> {
        use crate::schema::intrusion_log::dsl::{datetime, intrusion_log, server, service};
        use diesel::dsl::min;

        let conn = pool.get()?;

        let min_datetime = match min_datetime {
            Some(d) => d,
            None => {
                Self::_get_min_datetime(&conn, service_val, server_val)?.unwrap_or_else(Utc::now)
            }
        };
        let max_datetime = max_datetime.unwrap_or_else(Utc::now);

        let query = intrusion_log
            .filter(service.eq(service_val))
            .filter(server.eq(server_val))
            .filter(datetime.ge(min_datetime))
            .filter(datetime.lt(max_datetime))
            .order_by(datetime);

        max_entries.map_or_else(
            || query.load(&conn).map_err(Into::into),
            |max_entries| {
                query
                    .limit(max_entries as i64)
                    .load(&conn)
                    .map_err(Into::into)
            },
        )
    }
}

#[derive(
    Insertable, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord,
)]
#[table_name = "intrusion_log"]
pub struct IntrusionLogInsert {
    pub service: StackString,
    pub server: StackString,
    #[serde(with = "iso_8601_datetime")]
    pub datetime: DateTime<Utc>,
    pub host: StackString,
    pub username: Option<StackString>,
}

impl From<IntrusionLog> for IntrusionLogInsert {
    fn from(item: IntrusionLog) -> Self {
        Self {
            service: item.service,
            server: item.server,
            datetime: item.datetime,
            host: item.host,
            username: item.username,
        }
    }
}

impl IntrusionLogInsert {
    pub fn dump_avro<T: AsRef<Path>>(values: &[Self], output_filename: T) -> Result<(), Error> {
        let schema = Schema::parse_str(INTRUSION_LOG_AVRO_SCHEMA)?;
        let output_file = File::create(output_filename)?;
        let mut writer = Writer::with_codec(&schema, output_file, Codec::Snappy);
        writer.extend_ser(values)?;
        writer.flush()?;
        Ok(())
    }

    pub fn read_avro<T: AsRef<Path>>(input_filename: T) -> Result<Vec<Self>, Error> {
        let input_file = File::open(input_filename)?;
        Reader::new(input_file)?
            .next()
            .map(|record| {
                let record = record?;
                from_value::<Vec<Self>>(&record)
            })
            .transpose()
            .map(|x| x.unwrap_or_else(Vec::new))
            .map_err(Into::into)
    }

    pub fn insert(pool: &PgPool, il: &[IntrusionLogInsert]) -> Result<(), Error> {
        use crate::schema::intrusion_log::dsl::intrusion_log;
        let conn = pool.get()?;

        for i in il.chunks(100) {
            match diesel::insert_into(intrusion_log).values(i).execute(&conn) {
                Ok(_) => (),
                Err(e) => {
                    println!("chunk failed {}", e);
                    continue;
                }
            }
        }
        Ok(())
    }
}

pub async fn get_year_months(
    pool: &PgPoolPg,
    /* service_val: &str,
     * server_val: &str, */
) -> Result<Vec<(u16, u16)>, Error> {
    let query = postgres_query::query!(
        "
        SELECT extract(year from datetime) as year,
               extract(month from datetime) as month 
        FROM intrusion_log
        GROUP BY 1,2
        ORDER BY 1,2",
    );
    let conn = pool.get().await?;
    conn.query(query.sql(), query.parameters())
        .await?
        .into_iter()
        .map(|row| {
            let year: f64 = row.try_get("year")?;
            let month: f64 = row.try_get("month")?;
            Ok((year as u16, month as u16))
        })
        .collect()
}

pub async fn export_to_avro(
    pool: &PgPool,
    pgpool: &PgPoolPg,
    /* service_val: &str,
     * server_val: &str, */
) -> Result<(), Error> {
    let futures = get_year_months(pgpool) //, service_val, server_val)
        .await?
        .into_iter()
        .map(|(year, month)| {
            let pool = pool.clone();
            async move {
                let (next_year, next_month) = if month == 12 {
                    (year + 1, 1)
                } else if month == 11 {
                    (year, 12)
                } else {
                    (year, (month + 1) % 12)
                };
                println!(
                    "year {} month {} next_year {} next_month {}",
                    year, month, next_year, next_month
                );
                let min_datetime: DateTime<Utc> = DateTime::from_utc(
                    NaiveDateTime::new(
                        NaiveDate::from_ymd(i32::from(year), u32::from(month), 1),
                        NaiveTime::from_hms(0, 0, 0),
                    ),
                    Utc,
                );
                let max_datetime: DateTime<Utc> = DateTime::from_utc(
                    NaiveDateTime::new(
                        NaiveDate::from_ymd(i32::from(next_year), u32::from(next_month), 1),
                        NaiveTime::from_hms(0, 0, 0),
                    ),
                    Utc,
                );

                let pool = pool.clone();
                let logs: Vec<IntrusionLogInsert> = spawn_blocking(move || {
                    IntrusionLog::get_intrusion_log_filtered(
                        &pool,
                        "ssh",
                        "home.ddboline.net",
                        Some(min_datetime),
                        Some(max_datetime),
                        None,
                    )
                })
                .await??
                .into_iter()
                .map(Into::into)
                .collect();

                println!("{}", logs.len());

                let home_dir = dirs::home_dir().expect("No HOME directory");
                let output_filename = home_dir.join("tmp").join("security_log");

                create_dir_all(&output_filename).await?;

                let output_filename =
                    output_filename.join(&format!("{:04}_{:02}.avro", year, month));

                spawn_blocking(move || IntrusionLogInsert::dump_avro(&logs, output_filename))
                    .await??;
                Ok(())
            }
        });
    let results: Result<Vec<_>, Error> = try_join_all(futures).await;
    results?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
    use diesel::{QueryDsl, RunQueryDsl};
    use log::debug;
    use std::path::Path;

    use crate::{
        config::Config,
        models::{export_to_avro, CountryCode, HostCountry, IntrusionLog, IntrusionLogInsert},
        pgpool::PgPool,
        pgpool_pg::PgPoolPg,
    };

    #[test]
    #[ignore]
    fn test_country_code_query() {
        use crate::schema::country_code::dsl::country_code;
        let config = Config::init_config().unwrap();

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().unwrap();

        let country_code_list: Vec<CountryCode> = country_code.load(&conn).unwrap();

        for entry in &country_code_list {
            debug!("{:?}", entry);
        }
        assert_eq!(country_code_list.len(), 253);
    }

    #[test]
    #[ignore]
    fn test_host_country_query() {
        use crate::schema::host_country::dsl::host_country;
        let config = Config::init_config().unwrap();

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().unwrap();

        let host_country_list: Vec<HostCountry> = host_country.limit(10).load(&conn).unwrap();

        for entry in &host_country_list {
            debug!("{:?}", entry);
        }
        assert_eq!(host_country_list.len(), 10);
    }

    #[test]
    #[ignore]
    fn test_intrusion_log_query() {
        use crate::schema::intrusion_log::dsl::intrusion_log;
        let config = Config::init_config().unwrap();

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().unwrap();

        let intrusion_log_list: Vec<IntrusionLog> = intrusion_log.limit(10).load(&conn).unwrap();

        for entry in &intrusion_log_list {
            debug!("{:?}", entry);
        }
        assert_eq!(intrusion_log_list.len(), 10);
    }
}
