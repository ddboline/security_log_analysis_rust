use anyhow::{format_err, Error};
use avro_rs::{from_value, Codec, Reader, Schema, Writer};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
use derive_more::Into;
use futures::{future::try_join_all, TryFutureExt};
use log::debug;
use postgres_query::{client::GenericClient, query, query_dyn, FromSqlRow, Parameter};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{fs::File, path::Path};
use tokio::{fs::create_dir_all, task::spawn_blocking};

use crate::{
    iso_8601_datetime,
    pgpool::{PgPool, PgTransaction},
    Host, Service,
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
    pub async fn get_country_code_list(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM country_code");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }
}

#[derive(FromSqlRow, Clone, Debug)]
pub struct HostCountry {
    pub host: StackString,
    pub code: StackString,
    pub ipaddr: Option<StackString>,
}

impl HostCountry {
    pub async fn get_host_country(pool: &PgPool) -> Result<Vec<Self>, Error> {
        let query = query!("SELECT * FROM host_country");
        let conn = pool.get().await?;
        query.fetch(&conn).await.map_err(Into::into)
    }

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
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
    async fn _get_by_datetime_service_server<C>(
        conn: &C,
        datetime: DateTime<Utc>,
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

    pub async fn get_max_datetime(
        pool: &PgPool,
        service: Service,
        server: Host,
    ) -> Result<Option<DateTime<Utc>>, Error> {
        let conn = pool.get().await?;
        Self::_get_max_datetime(&conn, service, server)
            .await
            .map_err(Into::into)
    }

    async fn _get_max_datetime<C>(
        conn: &C,
        service: Service,
        server: Host,
    ) -> Result<Option<DateTime<Utc>>, Error>
    where
        C: GenericClient + Sync,
    {
        #[derive(FromSqlRow, Into)]
        struct Wrap(DateTime<Utc>);

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
    ) -> Result<Option<DateTime<Utc>>, Error>
    where
        C: GenericClient + Sync,
    {
        #[derive(FromSqlRow, Into)]
        struct Wrap(DateTime<Utc>);

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

    pub async fn get_intrusion_log_filtered(
        pool: &PgPool,
        service: Service,
        server: Host,
        min_datetime: Option<DateTime<Utc>>,
        max_datetime: Option<DateTime<Utc>>,
        max_entries: Option<usize>,
    ) -> Result<Vec<Self>, Error> {
        let conn = pool.get().await?;

        let min_datetime = match min_datetime {
            Some(d) => d,
            None => Self::_get_min_datetime(&conn, service, server)
                .await?
                .unwrap_or_else(Utc::now),
        };
        let max_datetime = max_datetime.unwrap_or_else(Utc::now);

        Self::get_intrusion_log_filtered_conn(
            &conn,
            service,
            server,
            min_datetime,
            max_datetime,
            max_entries,
        )
        .await
        .map_err(Into::into)
    }

    async fn get_intrusion_log_filtered_conn<C>(
        conn: &C,
        service: Service,
        server: Host,
        min_datetime: DateTime<Utc>,
        max_datetime: DateTime<Utc>,
        max_entries: Option<usize>,
    ) -> Result<Vec<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let query = format!(
            r#"
                SELECT * FROM intrusion_log
                WHERE service=$service
                  AND server=$server
                  AND datetime >= $min_datetime
                  AND datetime <= $max_datetime
                {}
            "#,
            if let Some(max_entries) = max_entries {
                format!("LIMIT {}", max_entries)
            } else {
                "".into()
            },
        );
        let service = service.to_str();
        let server = server.to_str();

        let bindings = vec![
            ("service", &service as Parameter),
            ("server", &server as Parameter),
            ("min_datetime", &min_datetime as Parameter),
            ("max_datetime", &max_datetime as Parameter),
        ];
        let query = query_dyn!(&query, ..bindings)?;
        query.fetch(conn).await.map_err(Into::into)
    }

    pub async fn insert_single<C>(&self, conn: &C) -> Result<(), Error>
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
        query.execute(conn).await?;
        Ok(())
    }

    pub async fn insert(pool: &PgPool, il: &[IntrusionLog]) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        for i_chunk in il.chunks(100) {
            for i in i_chunk {
                i.insert_single(conn).await?;
            }
        }
        tran.commit().await?;
        Ok(())
    }
}

pub async fn get_max_datetime(pool: &PgPool, server: Host) -> Result<DateTime<Utc>, Error> {
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
        Utc::now()
    };
    Ok(result)
}

#[cfg(test)]
mod tests {
    use anyhow::Error;
    use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Utc};
    use log::debug;
    use postgres_query::query;
    use std::path::Path;

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
