use chrono::{DateTime, TimeZone, Utc};
use failure::{err_msg, Error};
use serde::{self, Deserialize, Deserializer, Serializer};

pub fn sentinel_datetime() -> DateTime<Utc> {
    Utc.ymd(0, 1, 1).and_hms(0, 0, 0)
}

pub fn convert_datetime_to_str(datetime: DateTime<Utc>) -> String {
    datetime.to_rfc3339()
}

pub fn convert_str_to_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    DateTime::parse_from_rfc3339(&s)
        .map(|x| x.with_timezone(&Utc))
        .map_err(err_msg)
}

pub fn serialize<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&convert_datetime_to_str(*date))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    convert_str_to_datetime(&s).map_err(serde::de::Error::custom)
}