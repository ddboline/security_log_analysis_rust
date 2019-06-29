use chrono::{DateTime, Utc};

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

#[derive(Queryable, Clone, Debug, Insertable)]
#[table_name = "intrusion_log"]
pub struct IntrusionLog {
    pub id: i32,
    pub service: String,
    pub server: String,
    pub datetime: Option<DateTime<Utc>>,
    pub host: String,
    pub username: Option<String>,
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
        assert_eq!(country_code_list.len(), 250);
    }

    #[test]
    fn test_host_country_query() {
        use crate::schema::host_country::dsl::host_country;

        let database_url = "postgresql://ddboline:BQGIvkKFZPejrKvX@localhost:5432/security_logs";

        let pool = PgPool::new(database_url);
        let conn = pool.get().unwrap();

        let host_country_list: Vec<HostCountry> =
            host_country.limit(10).load(&conn).unwrap();

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
