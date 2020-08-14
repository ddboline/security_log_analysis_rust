use anyhow::Error;
use chrono::{DateTime, Utc};
use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl};
use log::debug;
use serde::{Deserialize, Serialize};
use stack_string::StackString;

use crate::{
    iso_8601_datetime,
    pgpool::PgPool,
    schema::{country_code, host_country, intrusion_log},
};

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "country_code"]
pub struct CountryCode {
    pub code: StackString,
    pub country: StackString,
}

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "host_country"]
pub struct HostCountry {
    pub host: StackString,
    pub code: StackString,
    pub ipaddr: Option<StackString>,
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

#[derive(Insertable, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

pub fn get_country_code_list(pool: &PgPool) -> Result<Vec<CountryCode>, Error> {
    use crate::schema::country_code::dsl::country_code;

    let conn = pool.get()?;

    country_code.load(&conn).map_err(Into::into)
}

pub fn get_host_country(pool: &PgPool) -> Result<Vec<HostCountry>, Error> {
    use crate::schema::host_country::dsl::host_country;

    let conn = pool.get()?;

    host_country.load(&conn).map_err(Into::into)
}

pub fn get_intrusion_log_max_datetime(
    pool: &PgPool,
    service_val: &str,
    server_val: &str,
) -> Result<Option<DateTime<Utc>>, Error> {
    use crate::schema::intrusion_log::dsl::{datetime, intrusion_log, server, service};
    use diesel::dsl::max;

    let conn = pool.get()?;

    intrusion_log
        .select(max(datetime))
        .filter(service.eq(service_val))
        .filter(server.eq(server_val))
        .first(&conn)
        .map_err(Into::into)
}

pub fn get_intrusion_log_filtered(
    pool: &PgPool,
    service_val: &str,
    server_val: &str,
    max_datetime: DateTime<Utc>,
    max_entries: Option<usize>,
) -> Result<Vec<IntrusionLog>, Error> {
    use crate::schema::intrusion_log::dsl::{datetime, intrusion_log, server, service};
    let conn = pool.get()?;

    let query = intrusion_log
        .filter(service.eq(service_val))
        .filter(server.eq(server_val))
        .filter(datetime.gt(max_datetime))
        .order_by(datetime);

    if let Some(max_entries) = max_entries {
        query
            .limit(max_entries as i64)
            .load(&conn)
            .map_err(Into::into)
    } else {
        query.load(&conn).map_err(Into::into)
    }
}

pub fn insert_host_country(pool: &PgPool, hc: &HostCountry) -> Result<(), Error> {
    use crate::schema::host_country::dsl::{host, host_country};
    let conn = pool.get()?;

    conn.transaction(|| {
        let current_entry: Vec<HostCountry> = host_country.filter(host.eq(&hc.host)).load(&conn)?;
        if current_entry.is_empty() {
            diesel::insert_into(host_country)
                .values(hc)
                .execute(&conn)?;
        }
        Ok(())
    })
}

pub fn insert_intrusion_log(pool: &PgPool, il: &[IntrusionLogInsert]) -> Result<(), Error> {
    use crate::schema::intrusion_log::dsl::intrusion_log;
    let conn = pool.get()?;

    for i in il.chunks(10000) {
        diesel::insert_into(intrusion_log)
            .values(i)
            .execute(&conn)
            .map(|_| ())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use diesel::{QueryDsl, RunQueryDsl};
    use log::debug;

    use crate::{
        config::Config,
        models::{CountryCode, HostCountry, IntrusionLog},
        pgpool::PgPool,
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
        assert_eq!(country_code_list.len(), 252);
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
