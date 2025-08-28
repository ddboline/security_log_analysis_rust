#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::needless_for_each)]

pub mod config;
pub mod errors;
pub mod host_country_metadata;
pub mod logged_user;
pub mod models;
pub mod parse_logs;
pub mod parse_opts;
pub mod pgpool;
pub mod polars_analysis;
pub mod reports;
pub mod s3_sync;
pub mod ses_client;

use anyhow::{format_err, Error};
use bytes::BytesMut;
use derive_more::{Deref, From, Into};
use postgres_query::FromSqlRow;
use postgres_types::{FromSql, IsNull, ToSql};
use rand::{
    distr::{Distribution, Uniform},
    rng as thread_rng,
};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{
    borrow::Cow, convert::TryFrom, fmt, future::Future, path::Path, str::FromStr, time::Duration,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};
use tokio::{process::Command, time::sleep};
use utoipa::{
    openapi::schema::{KnownFormat, ObjectBuilder, Type},
    PartialSchema, ToSchema,
};

/// # Errors
/// Return error after timeout
pub async fn exponential_retry<T, U, F>(closure: T) -> Result<U, Error>
where
    T: Fn() -> F,
    F: Future<Output = Result<U, Error>>,
{
    let mut timeout: f64 = 1.0;
    let range = Uniform::try_from(0..1000)?;
    loop {
        match closure().await {
            Ok(resp) => return Ok(resp),
            Err(err) => {
                sleep(Duration::from_millis((timeout * 1000.0) as u64)).await;
                timeout *= 4.0 * f64::from(range.sample(&mut thread_rng())) / 1000.0;
                if timeout >= 64.0 {
                    return Err(err);
                }
            }
        }
    }
}

/// # Errors
/// Return error if `md5sum` fails
pub async fn get_md5sum(filename: &Path) -> Result<StackString, Error> {
    if !Path::new("/usr/bin/md5sum").exists() {
        return Err(format_err!(
            "md5sum not installed (or not present at /usr/bin/md5sum"
        ));
    }
    let output = Command::new("/usr/bin/md5sum")
        .args([filename])
        .output()
        .await?;
    if output.status.success() {
        let buf = String::from_utf8_lossy(&output.stdout);
        for line in buf.split('\n') {
            if let Some(entry) = line.split_whitespace().next() {
                return Ok(entry.into());
            }
        }
    }
    Err(format_err!("Command failed"))
}

#[derive(FromSqlRow, PartialEq, Eq)]
pub struct CountryCount {
    pub country: StackString,
    pub count: i64,
}

#[derive(Debug, Clone, Copy, ToSchema, Serialize, Deserialize, PartialEq, Eq)]
#[serde(into = "StackString", try_from = "StackString")]
pub enum Host {
    Home,
    Cloud,
}

impl Default for Host {
    fn default() -> Self {
        Self::Home
    }
}

impl FromStr for Host {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "home" | "home.ddboline.net" => Ok(Self::Home),
            "cloud" | "cloud.ddboline.net" => Ok(Self::Cloud),
            _ => Err(format_err!("Not a valid Host")),
        }
    }
}

impl From<Host> for StackString {
    fn from(item: Host) -> Self {
        item.to_str().into()
    }
}

impl TryFrom<&str> for Host {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<StackString> for Host {
    type Error = Error;
    fn try_from(s: StackString) -> Result<Self, Self::Error> {
        Self::from_str(s.as_str())
    }
}

impl Host {
    #[must_use]
    pub fn get_prefix(self) -> &'static str {
        match self {
            Self::Home => "home",
            Self::Cloud => "cloud",
        }
    }

    #[must_use]
    pub fn abbreviation(self) -> &'static str {
        match self {
            Self::Home => "h",
            Self::Cloud => "c",
        }
    }

    #[must_use]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Home => "home.ddboline.net",
            Self::Cloud => "cloud.ddboline.net",
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

#[derive(Debug, Clone, Copy, ToSchema, Serialize, Deserialize)]
#[serde(into = "StackString", try_from = "StackString")]
pub enum Service {
    Apache,
    Nginx,
    Ssh,
}

impl FromStr for Service {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "apache" => Ok(Self::Apache),
            "nginx" => Ok(Self::Nginx),
            "ssh" => Ok(Self::Ssh),
            _ => Err(format_err!("Not a valid service")),
        }
    }
}

impl Service {
    #[must_use]
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Apache => "apache",
            Self::Nginx => "nginx",
            Self::Ssh => "ssh",
        }
    }

    #[must_use]
    pub fn abbreviation(self) -> &'static str {
        match self {
            Self::Apache => "a",
            Self::Nginx => "n",
            Self::Ssh => "s",
        }
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.to_str())
    }
}

impl From<Service> for StackString {
    fn from(item: Service) -> Self {
        item.to_str().into()
    }
}

impl TryFrom<&str> for Service {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::from_str(s)
    }
}

impl TryFrom<StackString> for Service {
    type Error = Error;
    fn try_from(s: StackString) -> Result<Self, Self::Error> {
        Self::from_str(s.as_str())
    }
}

#[derive(
    Into,
    From,
    Serialize,
    Deserialize,
    Deref,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
pub struct DateTimeType(#[serde(with = "iso8601")] OffsetDateTime);

impl FromStr for DateTimeType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        OffsetDateTime::parse(s, &Rfc3339)
            .map(|d| Self(d.to_offset(UtcOffset::UTC)))
            .map_err(Into::into)
    }
}

impl fmt::Display for DateTimeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = self.0.format(&Rfc3339) {
            write!(f, "{s}")?;
        }
        Ok(())
    }
}

impl PartialSchema for DateTimeType {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        ObjectBuilder::new()
            .format(Some(utoipa::openapi::SchemaFormat::KnownFormat(
                KnownFormat::DateTime,
            )))
            .schema_type(Type::String)
            .build()
            .into()
    }
}

impl ToSchema for DateTimeType {
    fn name() -> Cow<'static, str> {
        "datetime".into()
    }
}

mod iso8601 {
    use anyhow::Error;
    use serde::{de, Deserialize, Deserializer, Serializer};
    use stack_string::StackString;
    use std::borrow::Cow;
    use time::{
        format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime,
        UtcOffset,
    };

    #[must_use]
    pub fn convert_datetime_to_str(datetime: OffsetDateTime) -> StackString {
        datetime
            .to_offset(UtcOffset::UTC)
            .format(format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z"
            ))
            .unwrap_or_else(|_| String::new())
            .into()
    }

    /// # Errors
    /// Return error if `parse_from_rfc3339` fails
    pub fn convert_str_to_datetime(s: &str) -> Result<OffsetDateTime, Error> {
        let s: Cow<str> = if s.contains('Z') {
            s.replace('Z', "+00:00").into()
        } else {
            s.into()
        };
        OffsetDateTime::parse(&s, &Rfc3339)
            .map(|x| x.to_offset(UtcOffset::UTC))
            .map_err(Into::into)
    }

    /// # Errors
    /// Returns error if serialization fails
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&convert_datetime_to_str(*date))
    }

    /// # Errors
    /// Returns error if deserialization fails
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        convert_str_to_datetime(&s).map_err(de::Error::custom)
    }
}

impl FromSql<'_> for DateTimeType {
    fn from_sql(
        type_: &postgres_types::Type,
        raw: &[u8],
    ) -> Result<DateTimeType, Box<dyn std::error::Error + Sync + Send>> {
        OffsetDateTime::from_sql(type_, raw).map(Into::into)
    }

    fn accepts(ty: &postgres_types::Type) -> bool {
        <OffsetDateTime as FromSql>::accepts(ty)
    }
}

impl ToSql for DateTimeType {
    fn to_sql(
        &self,
        type_: &postgres_types::Type,
        w: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        OffsetDateTime::to_sql(&self.0, type_, w)
    }

    fn accepts(ty: &postgres_types::Type) -> bool {
        <OffsetDateTime as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &postgres_types::Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        OffsetDateTime::to_sql_checked(&self.0, ty, out)
    }
}
