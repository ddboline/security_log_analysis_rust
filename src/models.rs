use anyhow::Error;
use derive_more::Into;
use postgres_query::{client::GenericClient, query, query_dyn, FromSqlRow, Parameter};
use rweb::Schema;
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::net::ToSocketAddrs;
use time::OffsetDateTime;

use crate::{
    pgpool::{PgPool, PgTransaction},
    DateTimeType, Host, Service,
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

#[derive(FromSqlRow, Clone, Debug)]
pub struct CountryCode {
    pub code: StackString,
    pub country: StackString,
}

impl CountryCode {
    /// # Errors
    /// Return error if db query fails
    pub async fn get_country_code_list(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM country_code");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, Schema)]
pub struct HostCountry {
    pub host: StackString,
    pub code: StackString,
    pub ipaddr: Option<StackString>,
    pub created_at: DateTimeType,
}

impl HostCountry {
    /// # Errors
    /// Return error if db query fails
    pub fn from_host_code(host: &str, code: &str) -> Result<Self, Error> {
        let ipaddr = (host, 22).to_socket_addrs()?.next().and_then(|s| {
            let ip = s.ip();
            if ip.is_ipv4() {
                let ip_str = StackString::from_display(ip);
                Some(ip_str)
            } else {
                None
            }
        });
        Ok(Self {
            host: host.into(),
            code: code.into(),
            ipaddr,
            created_at: OffsetDateTime::now_utc().into(),
        })
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_host_country(
        pool: &PgPool,
        offset: Option<usize>,
        limit: Option<usize>,
        order: bool,
    ) -> Result<Vec<Self>, Error> {
        let mut query = format_sstr!("SELECT * FROM host_country");
        if order {
            query.push_str(" ORDER BY created_at DESC");
        }
        if let Some(offset) = offset {
            query.push_str(&format_sstr!(" OFFSET {offset}"));
        }
        if let Some(limit) = limit {
            query.push_str(&format_sstr!(" LIMIT {limit}"));
        }
        let query = query_dyn!(&query)?;
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn insert_host_country(&self, pool: &PgPool) -> Result<Option<Self>, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;

        let existing = Self::get_by_host_conn(&self.host, conn).await?;
        if existing.is_none() {
            self.insert_host_country_conn(conn).await?;
        } else {
            self.update_host_country_conn(conn).await?;
        }

        tran.commit().await?;
        Ok(existing)
    }

    async fn get_by_host_conn<C>(host: &str, conn: &C) -> Result<Option<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!("SELECT * FROM host_country WHERE host=$host", host = host);
        query.fetch_opt(conn).await.map_err(Into::into)
    }

    async fn insert_host_country_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            r#"
                INSERT INTO host_country (host, code, ipaddr)
                VALUES ($host, $code, $ipaddr)
            "#,
            host = self.host,
            code = self.code,
            ipaddr = self.ipaddr,
        );
        query.execute(&conn).await?;
        Ok(())
    }

    async fn update_host_country_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            "UPDATE host_country SET code=$code, ipaddr=$ipaddr",
            code = self.code,
            ipaddr = self.ipaddr
        );
        query.execute(conn).await?;
        Ok(())
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_dangling_hosts(pool: &PgPool) -> Result<Vec<StackString>, Error> {
        #[derive(FromSqlRow)]
        struct Wrapper {
            host: StackString,
        }

        let query = query!(
            r#"
                SELECT distinct a.host
                FROM intrusion_log a
                LEFT JOIN host_country b ON a.host = b.host
                WHERE b.host IS NULL
            "#
        );
        let conn = pool.get().await?;
        let rows: Vec<Wrapper> = query.fetch(&conn).await?;
        Ok(rows.into_iter().map(|x| x.host).collect())
    }
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Schema)]
pub struct IntrusionLog {
    pub id: i32,
    pub service: StackString,
    pub server: StackString,
    pub datetime: DateTimeType,
    pub host: StackString,
    pub username: Option<StackString>,
}

impl IntrusionLog {
    async fn _get_by_datetime_service_server<C>(
        conn: &C,
        datetime: OffsetDateTime,
        service: &str,
        server: &str,
    ) -> Result<Vec<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            r#"
                SELECT * FROM intrusion_log
                WHERE datetime=$datetime
                  AND service=$service
                  AND server=$server
            "#,
            datetime = datetime,
            service = service,
            server = server,
        );
        query.fetch(conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_max_datetime(
        pool: &PgPool,
        service: Service,
        server: Host,
    ) -> Result<Option<OffsetDateTime>, Error> {
        let conn = pool.get().await?;
        Self::_get_max_datetime(&conn, service, server)
            .await
            .map_err(Into::into)
    }

    async fn _get_max_datetime<C>(
        conn: &C,
        service: Service,
        server: Host,
    ) -> Result<Option<OffsetDateTime>, Error>
    where
        C: GenericClient + Sync,
    {
        #[derive(FromSqlRow, Into)]
        struct Wrap(OffsetDateTime);

        let service = service.to_str();
        let server = server.to_str();

        let query = query!(
            r#"
                SELECT max(datetime) FROM intrusion_log
                WHERE service=$service
                  AND server=$server
            "#,
            service = service,
            server = server,
        );
        let result: Option<Wrap> = query.fetch_opt(conn).await?;
        Ok(result.map(Into::into))
    }

    async fn _get_min_datetime<C>(
        conn: &C,
        service: Service,
        server: Host,
    ) -> Result<Option<OffsetDateTime>, Error>
    where
        C: GenericClient + Sync,
    {
        #[derive(FromSqlRow, Into)]
        struct Wrap(OffsetDateTime);

        let service = service.to_str();
        let server = server.to_str();

        let query = query!(
            r#"
                SELECT max(datetime) FROM intrusion_log
                WHERE service=$service
                    AND server=$server
            "#,
            service = service,
            server = server,
        );
        let result: Option<Wrap> = query.fetch_opt(conn).await?;
        Ok(result.map(Into::into))
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_intrusion_log_filtered(
        pool: &PgPool,
        service: Option<Service>,
        server: Option<Host>,
        min_datetime: Option<OffsetDateTime>,
        max_datetime: Option<OffsetDateTime>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<Self>, Error> {
        let conn = pool.get().await?;

        Self::get_intrusion_log_filtered_conn(
            &conn,
            service,
            server,
            min_datetime,
            max_datetime,
            limit,
            offset,
        )
        .await
        .map_err(Into::into)
    }

    async fn get_intrusion_log_filtered_conn<C>(
        conn: &C,
        service: Option<Service>,
        server: Option<Host>,
        min_datetime: Option<OffsetDateTime>,
        max_datetime: Option<OffsetDateTime>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let mut bindings = Vec::new();
        let mut constraints = Vec::new();
        let service = service.map(Service::to_str);
        let server = server.map(Host::to_str);
        if let Some(service) = &service {
            constraints.push(format_sstr!("service=$service"));
            bindings.push(("service", service as Parameter));
        }
        if let Some(server) = &server {
            constraints.push(format_sstr!("server=$server"));
            bindings.push(("server", server as Parameter));
        }
        if let Some(min_datetime) = &min_datetime {
            constraints.push(format_sstr!("datetime >= $min_datetime"));
            bindings.push(("min_datetime", min_datetime as Parameter));
        }
        if let Some(max_datetime) = &max_datetime {
            constraints.push(format_sstr!("datetine <= $max_datetime"));
            bindings.push(("max_datetime", max_datetime as Parameter));
        }
        let where_str = if constraints.is_empty() {
            "".into()
        } else {
            format_sstr!("WHERE {}", constraints.join(" AND "))
        };
        let limit = if let Some(limit) = limit {
            format_sstr!("LIMIT {limit}")
        } else {
            "".into()
        };
        let offset = if let Some(offset) = offset {
            format_sstr!("OFFSET {offset}")
        } else {
            "".into()
        };
        let query = format_sstr!(
            r#"
                SELECT * FROM intrusion_log
                {where_str}
                ORDER BY datetime DESC
                {limit} {offset}
            "#,
        );
        let query = query_dyn!(&query, ..bindings)?;
        query.fetch(conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn insert_single<C>(&self, conn: &C) -> Result<u64, Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            r#"
                INSERT INTO intrusion_log (
                    service, server, datetime, host, username
                ) VALUES (
                    $service, $server, $datetime, $host, $username
                ) ON CONFLICT DO NOTHING;
            "#,
            service = self.service,
            server = self.server,
            datetime = self.datetime,
            host = self.host,
            username = self.username,
        );
        query.execute(conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn insert(pool: &PgPool, il: &[IntrusionLog]) -> Result<u64, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let mut inserts = 0;
        for i_chunk in il.chunks(100) {
            for i in i_chunk {
                inserts += i.insert_single(conn).await?;
            }
        }
        tran.commit().await?;
        Ok(inserts)
    }
}

#[derive(FromSqlRow, Clone, Debug)]
pub struct AuthorizedUsers {
    pub email: StackString,
}

impl AuthorizedUsers {
    /// # Errors
    /// Return error if db query fails
    pub async fn get_authorized_users(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM authorized_users");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }
}

/// # Errors
/// Return error if db query fails
pub async fn get_max_datetime(pool: &PgPool, server: Host) -> Result<OffsetDateTime, Error> {
    let result = if let Some(dt) = IntrusionLog::get_max_datetime(pool, Service::Ssh, server)
        .await?
        .as_ref()
    {
        if let Ok(Some(dt2)) = IntrusionLog::get_max_datetime(pool, Service::Nginx, server).await {
            if *dt < dt2 {
                *dt
            } else {
                dt2
            }
        } else {
            *dt
        }
    } else {
        OffsetDateTime::now_utc()
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use log::debug;
    use postgres_query::query;

    use crate::{
        config::Config,
        models::{CountryCode, HostCountry, IntrusionLog},
        pgpool::PgPool,
    };

    #[tokio::test]
    #[ignore]
    async fn test_country_code_query() -> Result<(), Error> {
        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().await?;

        let query = query!("SELECT * FROM country_code");
        let country_code_list: Vec<CountryCode> = query.fetch(&conn).await?;

        for entry in &country_code_list {
            debug!("{:?}", entry);
        }
        assert_eq!(country_code_list.len(), 253);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_host_country_query() -> Result<(), Error> {
        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().await?;
        let query = query!("SELECT * FROM host_country LIMIT 10");
        let host_country_list: Vec<HostCountry> = query.fetch(&conn).await?;

        for entry in &host_country_list {
            debug!("{:?}", entry);
        }
        assert_eq!(host_country_list.len(), 10);
        Ok(())
    }

    #[tokio::test]
    #[ignore]
    async fn test_intrusion_log_query() -> Result<(), Error> {
        let config = Config::init_config()?;

        let pool = PgPool::new(&config.database_url);
        let conn = pool.get().await?;
        let query = query!("SELECT * FROM intrusion_log LIMIT 10");
        let intrusion_log_list: Vec<IntrusionLog> = query.fetch(&conn).await?;

        for entry in &intrusion_log_list {
            debug!("{:?}", entry);
        }
        assert_eq!(intrusion_log_list.len(), 10);
        Ok(())
    }
}
