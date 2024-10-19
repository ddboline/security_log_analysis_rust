use anyhow::{format_err, Error};
use bytes::BytesMut;
use derive_more::Into;
use futures::{Stream, TryStreamExt};
use log::debug;
use postgres_query::{
    client::GenericClient, query, query_dyn, Error as PgError, FromSqlRow, Parameter, Query,
};
use rweb::Schema;
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::{cmp::Ordering, convert::TryInto, fmt, net::ToSocketAddrs, str::FromStr};
use time::OffsetDateTime;
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};
use uuid::Uuid;

use crate::{
    pgpool::{PgPool, PgTransaction},
    DateTimeType, Host, Service,
};

#[derive(FromSqlRow, Clone, Debug)]
pub struct CountryCode {
    pub code: StackString,
    pub country: StackString,
}

impl CountryCode {
    /// # Errors
    /// Return error if db query fails
    pub async fn get_country_code_list(
        pool: &PgPool,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
        let query = query!("SELECT * FROM country_code");
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, Schema, PartialEq)]
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
    pub async fn get_host_country_total(pool: &PgPool) -> Result<usize, Error> {
        #[derive(FromSqlRow)]
        struct Count {
            count: i64,
        }

        let query = query!("SELECT count(*) FROM host_country");

        let conn = pool.get().await?;
        let count: Count = query.fetch_one(&conn).await?;

        Ok(count.count.try_into()?)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_host_country(
        pool: &PgPool,
        offset: Option<usize>,
        limit: Option<usize>,
        order: bool,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
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
        query.fetch_streaming(&conn).await.map_err(Into::into)
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
    pub async fn get_dangling_hosts(
        pool: &PgPool,
    ) -> Result<impl Stream<Item = Result<StackString, PgError>>, Error> {
        let query = query!(
            r#"
                SELECT distinct a.host
                FROM intrusion_log a
                LEFT JOIN host_country b ON a.host = b.host
                WHERE b.host IS NULL
            "#
        );
        let conn = pool.get().await?;
        query
            .query_streaming(&conn)
            .await
            .map(|stream| {
                stream.and_then(|row| async move {
                    let host: StackString =
                        row.try_get("host").map_err(PgError::BeginTransaction)?;
                    Ok(host)
                })
            })
            .map_err(Into::into)
    }
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct IntrusionLog {
    pub id: Uuid,
    pub service: StackString,
    pub server: StackString,
    pub datetime: DateTimeType,
    pub host: StackString,
    pub username: Option<StackString>,
}

impl IntrusionLog {
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

    fn get_intrusion_log_filtered_query<'a>(
        select_str: &'a str,
        order_str: &'a str,
        service: &'a Option<StackString>,
        server: &'a Option<StackString>,
        min_datetime: &'a Option<OffsetDateTime>,
        max_datetime: &'a Option<OffsetDateTime>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<Query<'a>, PgError> {
        let mut bindings = Vec::new();
        let mut constraints = Vec::new();
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
        let mut query = format_sstr!(
            r#"
                SELECT {select_str} FROM intrusion_log
                {where_str}
                {order_str}
            "#,
        );
        if let Some(offset) = &offset {
            query.push_str(&format_sstr!(" OFFSET {offset}"));
        }
        if let Some(limit) = &limit {
            query.push_str(&format_sstr!(" LIMIT {limit}"));
        }
        bindings.shrink_to_fit();
        debug!("query:\n{}", query);
        query_dyn!(&query, ..bindings)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_intrusion_log_filtered(
        pool: &PgPool,
        service: Option<Service>,
        server: Option<Host>,
        min_datetime: Option<OffsetDateTime>,
        max_datetime: Option<OffsetDateTime>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
        let service = service.map(Service::to_str).map(Into::into);
        let server = server.map(Host::to_str).map(Into::into);

        let query = Self::get_intrusion_log_filtered_query(
            "*",
            "ORDER BY datetime DESC",
            &service,
            &server,
            &min_datetime,
            &max_datetime,
            offset,
            limit,
        )?;
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_intrusion_log_filtered_total(
        pool: &PgPool,
        service: Option<Service>,
        server: Option<Host>,
        min_datetime: Option<OffsetDateTime>,
        max_datetime: Option<OffsetDateTime>,
    ) -> Result<usize, Error> {
        #[derive(FromSqlRow)]
        struct Count {
            count: i64,
        }

        let service = service.map(Service::to_str).map(Into::into);
        let server = server.map(Host::to_str).map(Into::into);

        let query = Self::get_intrusion_log_filtered_query(
            "count(*)",
            "",
            &service,
            &server,
            &min_datetime,
            &max_datetime,
            None,
            None,
        )?;
        let conn = pool.get().await?;
        let count: Count = query.fetch_one(&conn).await?;

        Ok(count.count.try_into()?)
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
    pub async fn get_authorized_users(
        pool: &PgPool,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
        let query = query!("SELECT * FROM authorized_users");
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
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

#[derive(Debug, Serialize, Deserialize, Clone, Eq, Copy, PartialEq, Schema)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Debug
    }
}

impl LogLevel {
    #[inline]
    fn ordering(self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warning => 2,
            Self::Error => 3,
        }
    }

    #[must_use]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warn",
            Self::Error => "error",
        }
    }

    #[must_use]
    pub fn line_contains_level(line: &str, level: Option<Self>) -> Option<Self> {
        let level = level.unwrap_or(Self::Debug).ordering();
        if line.contains("err") || line.contains("ERR") {
            return Some(Self::Error);
        }
        if level < 3 {
            if line.contains("warn") || line.contains("WARN") {
                return Some(Self::Warning);
            }
            if level < 2 {
                if line.contains("info") || line.contains("INFO") {
                    return Some(Self::Info);
                }
                if level < 1 && line.contains("debug") || line.contains("DEBUG") {
                    return Some(Self::Debug);
                }
            }
        }
        None
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_str(),)
    }
}

impl Ord for LogLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ordering().cmp(&other.ordering())
    }
}

impl PartialOrd for LogLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FromStr for LogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "debug" | "DEBUG" => Ok(Self::Debug),
            "info" | "INFO" => Ok(Self::Info),
            "warn" | "warning" | "WARN" | "WARNING" => Ok(Self::Warning),
            "error" | "err" | "ERR" | "ERROR" => Ok(Self::Error),
            _ => Err(format_err!("Not a valid log level")),
        }
    }
}

impl<'a> FromSql<'a> for LogLevel {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>> {
        let s = String::from_sql(ty, raw)?.parse()?;
        Ok(s)
    }

    fn accepts(ty: &Type) -> bool {
        <String as FromSql>::accepts(ty)
    }
}

impl ToSql for LogLevel {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        self.to_str().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool
    where
        Self: Sized,
    {
        <String as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        self.to_str().to_sql_checked(ty, out)
    }
}

#[derive(FromSqlRow, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SystemdLogMessages {
    pub id: Uuid,
    pub log_level: LogLevel,
    pub log_unit: Option<StackString>,
    pub log_message: StackString,
    pub log_timestamp: DateTimeType,
    pub processed_time: Option<DateTimeType>,
}

impl SystemdLogMessages {
    #[must_use]
    pub fn new(
        log_level: LogLevel,
        log_unit: Option<&str>,
        log_message: &str,
        log_timestamp: DateTimeType,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            log_level,
            log_unit: log_unit.map(Into::into),
            log_message: log_message.into(),
            log_timestamp,
            processed_time: None,
        }
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_by_id(pool: &PgPool, id: i32) -> Result<Option<Self>, Error> {
        let query = query!("SELECT * FROM systemd_log_messages WHERE id=$id", id = id);
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_oldest_message(pool: &PgPool) -> Result<Option<Self>, Error> {
        let conn = pool.get().await?;
        let query = query!(
            r#"
                SELECT * FROM systemd_log_messages
                WHERE id = (
                    SELECT id FROM systemd_log_messages
                    WHERE processed_time IS NULL
                    ORDER BY log_timestamp
                    LIMIT 1
                )
            "#
        );
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn set_message_processed(&self, pool: &PgPool) -> Result<u64, Error> {
        let query = query!(
            "UPDATE systemd_log_messages SET processed_time = now() WHERE id=$id",
            id = self.id
        );
        let conn = pool.get().await?;
        query.execute(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn insert(&self, pool: &PgPool) -> Result<u64, Error> {
        let query = query!(
            r#"
                INSERT INTO systemd_log_messages (
                    log_level, log_unit, log_message, log_timestamp
                ) VALUES (
                    $log_level, $log_unit, $log_message, $log_timestamp
                )
            "#,
            log_level = self.log_level,
            log_unit = self.log_unit,
            log_message = self.log_message,
            log_timestamp = self.log_timestamp,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn delete(pool: &PgPool, id: i32) -> Result<u64, Error> {
        let query = query!("DELETE FROM systemd_log_messages WHERE id=$id", id = id);
        let conn = pool.get().await?;
        query.execute(&conn).await.map_err(Into::into)
    }

    fn get_systemd_messages_query<'a>(
        select_str: &'a str,
        order_str: &'a str,
        log_level: &'a Option<LogLevel>,
        log_unit: &'a Option<&str>,
        min_timestamp: &'a Option<DateTimeType>,
        max_timestamp: &'a Option<DateTimeType>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<Query<'a>, PgError> {
        let mut constraints = Vec::new();
        let mut bindings = Vec::new();
        if let Some(log_level) = log_level {
            constraints.push(format_sstr!("log_level=$log_level"));
            bindings.push(("log_level", log_level as Parameter));
        }
        if let Some(log_unit) = log_unit {
            constraints.push(format_sstr!("log_unit=$log_unit"));
            bindings.push(("log_unit", log_unit as Parameter));
        }
        if let Some(min_timestamp) = min_timestamp {
            constraints.push(format_sstr!("log_timestamp > $min_timestamp"));
            bindings.push(("min_timestamp", min_timestamp as Parameter));
        }
        if let Some(max_timestamp) = max_timestamp {
            constraints.push(format_sstr!("log_timestamp > $max_timestamp"));
            bindings.push(("max_timestamp", max_timestamp as Parameter));
        }
        let where_str = if constraints.is_empty() {
            "".into()
        } else {
            format_sstr!("WHERE {}", constraints.join(" AND "))
        };
        let mut query = format_sstr!(
            r#"
                SELECT {select_str} FROM systemd_log_messages
                {where_str}
                {order_str}
            "#,
        );
        if let Some(offset) = offset {
            query.push_str(&format_sstr!(" OFFSET {offset}"));
        }
        if let Some(limit) = limit {
            query.push_str(&format_sstr!(" LIMIT {limit}"));
        }
        bindings.shrink_to_fit();
        debug!("query:\n{}", query);
        query_dyn!(&query, ..bindings)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_total(
        pool: &PgPool,
        log_level: Option<LogLevel>,
        log_unit: Option<&str>,
        min_timestamp: Option<DateTimeType>,
        max_timestamp: Option<DateTimeType>,
    ) -> Result<usize, Error> {
        #[derive(FromSqlRow)]
        struct Count {
            count: i64,
        }

        let query = Self::get_systemd_messages_query(
            "count(*)",
            "",
            &log_level,
            &log_unit,
            &min_timestamp,
            &max_timestamp,
            None,
            None,
        )?;
        let conn = pool.get().await?;
        let count: Count = query.fetch_one(&conn).await?;

        Ok(count.count.try_into()?)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_systemd_messages(
        pool: &PgPool,
        log_level: Option<LogLevel>,
        log_unit: Option<&str>,
        min_timestamp: Option<DateTimeType>,
        max_timestamp: Option<DateTimeType>,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
        let query = Self::get_systemd_messages_query(
            "*",
            "ORDER BY log_timestamp",
            &log_level,
            &log_unit,
            &min_timestamp,
            &max_timestamp,
            offset,
            limit,
        )?;
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }
}

#[derive(FromSqlRow, Serialize, Deserialize, Debug, Clone, Default)]
pub struct KeyItemCache {
    pub s3_key: StackString,
    pub s3_etag: Option<StackString>,
    pub s3_timestamp: Option<i64>,
    pub s3_size: Option<i64>,
    pub local_etag: Option<StackString>,
    pub local_timestamp: Option<i64>,
    pub local_size: Option<i64>,
    pub do_download: bool,
    pub do_upload: bool,
}

impl KeyItemCache {
    /// # Errors
    /// Return error if db query fails
    pub async fn get_by_key(pool: &PgPool, s3_key: &str) -> Result<Option<Self>, Error> {
        let query = query!(
            "SELECT * FROM key_item_cache WHERE s3_key = $s3_key",
            s3_key = s3_key
        );
        let conn = pool.get().await?;
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn get_files(
        pool: &PgPool,
        do_download: Option<bool>,
        do_upload: Option<bool>,
    ) -> Result<impl Stream<Item = Result<Self, PgError>>, Error> {
        let mut bindings = Vec::new();
        let mut constraints = Vec::new();
        if let Some(do_download) = &do_download {
            constraints.push(format_sstr!("do_download=$do_download"));
            bindings.push(("do_download", do_download as Parameter));
        }
        if let Some(do_upload) = &do_upload {
            constraints.push(format_sstr!("do_upload=$do_upload"));
            bindings.push(("do_upload", do_upload as Parameter));
        }
        let query = if constraints.is_empty() {
            query!("SELECT * FROM key_item_cache")
        } else {
            let query = format_sstr!(
                "SELECT * FROM key_item_cache WHERE {}",
                constraints.join(" AND ")
            );
            query_dyn!(&query, ..bindings)?
        };
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Return error if db query fails
    pub async fn insert(&self, pool: &PgPool) -> Result<u64, Error> {
        let query = query!(
            r#"
                INSERT INTO key_item_cache (
                    s3_key,
                    s3_etag,
                    s3_timestamp,
                    s3_size,
                    local_etag,
                    local_timestamp,
                    local_size,
                    do_download,
                    do_upload
                ) VALUES (
                    $s3_key,
                    $s3_etag,
                    $s3_timestamp,
                    $s3_size,
                    $local_etag,
                    $local_timestamp,
                    $local_size,
                    $do_download,
                    $do_upload
                ) ON CONFLICT (s3_key) DO UPDATE
                    SET s3_etag=$s3_etag,
                        s3_timestamp=$s3_timestamp,
                        s3_size=$s3_size,
                        local_etag=$local_etag,
                        local_timestamp=$local_timestamp,
                        local_size=$local_size,
                        do_download=$do_download,
                        do_upload=$do_upload
            "#,
            s3_key = self.s3_key,
            s3_etag = self.s3_etag,
            s3_timestamp = self.s3_timestamp,
            s3_size = self.s3_size,
            local_etag = self.local_etag,
            local_timestamp = self.local_timestamp,
            local_size = self.local_size,
            do_download = self.do_download,
            do_upload = self.do_upload,
        );
        let conn = pool.get().await?;
        query.execute(&conn).await.map_err(Into::into)
    }
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

        let pool = PgPool::new(&config.database_url)?;
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

        let pool = PgPool::new(&config.database_url)?;
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

        let pool = PgPool::new(&config.database_url)?;
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
