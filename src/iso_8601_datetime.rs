use anyhow::Error;
use serde::{self, Deserialize, Deserializer, Serializer};
use stack_string::StackString;
use time::{format_description::well_known::Rfc3339, macros::datetime, OffsetDateTime, UtcOffset};

#[must_use]
pub fn sentinel_datetime() -> OffsetDateTime {
    datetime!(0000-01-01 00:00:00).assume_utc()
}

#[must_use]
pub fn convert_datetime_to_str(datetime: OffsetDateTime) -> StackString {
    datetime
        .format(&Rfc3339)
        .map_or_else(|_| "".into(), Into::into)
}

/// # Errors
/// Return error if parsing fails
pub fn convert_str_to_datetime(s: &str) -> Result<OffsetDateTime, Error> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map(|dt| dt.to_offset(UtcOffset::UTC))
        .map_err(Into::into)
}

/// # Errors
/// Return error if serialization fails
pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&convert_datetime_to_str(*date))
}

/// # Errors
/// Return error if deserialization fails
pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    convert_str_to_datetime(&s).map_err(serde::de::Error::custom)
}
