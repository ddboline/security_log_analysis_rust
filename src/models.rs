use chrono::{DateTime, Utc};
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl};
use failure::{err_msg, Error};

use crate::pgpool::PgPool;
use crate::schema::{country_code, host_country, intrusion_log};

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "country_code"]
pub struct CountryCode {
    pub code: String,
    pub country: String,
}

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "host_country"]
pub struct HostCountry {
    pub host: String,
    pub code: String,
    pub ipaddr: Option<String>,
}

#[derive(Queryable, Clone, Debug)]
pub struct IntrusionLog {
    pub id: i32,
    pub service: String,
    pub server: String,
    pub datetime: DateTime<Utc>,
    pub host: String,
    pub username: Option<String>,
}

#[derive(Insertable, Clone, Debug, PartialEq, Eq, Hash)]
#[table_name = "intrusion_log"]
pub struct IntrusionLogInsert {
    pub service: String,
    pub server: String,
    pub datetime: DateTime<Utc>,
    pub host: String,
    pub username: Option<String>,
}

pub fn get_country_code_list(pool: &PgPool) -> Result<Vec<CountryCode>, Error> {
    use crate::schema::country_code::dsl::country_code;

    let conn = pool.get()?;

    let country_code_list: Vec<_> = country_code.load(&conn)?;

    Ok(country_code_list)
}

pub fn get_host_country(pool: &PgPool) -> Result<Vec<HostCountry>, Error> {
    use crate::schema::host_country::dsl::host_country;

    let conn = pool.get()?;

    let host_country_list: Vec<_> = host_country.load(&conn)?;

    Ok(host_country_list)
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
        .map_err(err_msg)
}

pub fn insert_host_country(pool: &PgPool, hc: &HostCountry) -> Result<(), Error> {
    use crate::schema::host_country::dsl::host_country;
    let conn = pool.get()?;

    diesel::insert_into(host_country)
        .values(hc)
        .execute(&conn)
        .map_err(err_msg)?;
    Ok(())
}

pub fn insert_intrusion_log(pool: &PgPool, il: &[IntrusionLogInsert]) -> Result<(), Error> {
    use crate::schema::intrusion_log::dsl::intrusion_log;
    let conn = pool.get()?;

    diesel::insert_into(intrusion_log)
        .values(il)
        .execute(&conn)
        .map_err(err_msg)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use diesel::{QueryDsl, RunQueryDsl};

    use crate::models::{CountryCode, HostCountry, IntrusionLog};
    use crate::pgpool::PgPool;

    #[test]
    fn test_country_code_query() {
        use crate::schema::country_code::dsl::country_code;

        let database_url = "postgresql://ddboline:BQGIvkKFZPejrKvX@localhost:5432/security_logs";

        let pool = PgPool::new(database_url);
        let conn = pool.get().unwrap();

        let country_code_list: Vec<CountryCode> = country_code.load(&conn).unwrap();

        for entry in &country_code_list {
            println!("{:?}", entry);
        }
        assert_eq!(country_code_list.len(), 251);
    }

    #[test]
    fn test_host_country_query() {
        use crate::schema::host_country::dsl::host_country;

        let database_url = "postgresql://ddboline:BQGIvkKFZPejrKvX@localhost:5432/security_logs";

        let pool = PgPool::new(database_url);
        let conn = pool.get().unwrap();

        let host_country_list: Vec<HostCountry> = host_country.limit(10).load(&conn).unwrap();

        for entry in &host_country_list {
            println!("{:?}", entry);
        }
        assert_eq!(host_country_list.len(), 10);
    }

    #[test]
    fn test_intrusion_log_query() {
        use crate::schema::intrusion_log::dsl::intrusion_log;

        let database_url = "postgresql://ddboline:BQGIvkKFZPejrKvX@localhost:5432/security_logs";

        let pool = PgPool::new(database_url);
        let conn = pool.get().unwrap();

        let intrusion_log_list: Vec<IntrusionLog> = intrusion_log.limit(10).load(&conn).unwrap();

        for entry in &intrusion_log_list {
            println!("{:?}", entry);
        }
        assert_eq!(intrusion_log_list.len(), 10);
    }
}
