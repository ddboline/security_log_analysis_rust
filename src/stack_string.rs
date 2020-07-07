use anyhow::Error;
use bytes::BytesMut;
use derive_more::{Display, From, Into};
use diesel::{
    backend::Backend,
    deserialize::{FromSql as DeFromSql, Result as DeResult},
    serialize::{Output, Result as SerResult, ToSql as DeToSql},
    sql_types::Text,
};
use smartstring::alias::String as SmartString;
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use std::{
    borrow::{Borrow, Cow},
    io::Write,
    ops::{Deref, DerefMut},
    str::FromStr,
    fmt::{self, Display, Formatter},
    string::{FromUtf16Error, FromUtf8Error},
};
use tokio_postgres::types::{FromSql, IsNull, ToSql, Type};

#[derive(
    Debug,
    Clone,
    Into,
    From,
    PartialEq,
    Eq,
    Hash,
    Default,
    PartialOrd,
    Ord,
    FromSqlRow,
    AsExpression,
)]
#[sql_type = "Text"]
pub struct StackString(SmartString);

impl StackString {
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for StackString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for StackString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use ::serde::de::{Error, Visitor};

        struct SmartVisitor;

        impl<'a> Visitor<'a> for SmartVisitor {
            type Value = StackString;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(v.into())
            }

            fn visit_borrowed_str<E: Error>(self, v: &'a str) -> Result<Self::Value, E> {
                Ok(v.into())
            }

            fn visit_string<E: Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(v.into())
            }
        }

        deserializer.deserialize_str(SmartVisitor)
    }
}

impl Display for StackString {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<StackString> for String {
    fn from(item: StackString) -> Self {
        item.into()
    }
}

impl From<String> for StackString {
    fn from(item: String) -> Self {
        Self(item.into())
    }
}

impl From<&String> for StackString {
    fn from(item: &String) -> Self {
        Self(item.as_str().into())
    }
}

impl From<&str> for StackString {
    fn from(item: &str) -> Self {
        Self(item.into())
    }
}

impl Borrow<str> for StackString {
    fn borrow(&self) -> &str {
        self.0.borrow()
    }
}

impl<'a> FromSql<'a> for StackString {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>> {
        let s = <String as FromSql>::from_sql(ty, raw)?;
        Ok(s.into())
    }

    fn accepts(ty: &Type) -> bool {
        <String as FromSql>::accepts(ty)
    }
}

impl ToSql for StackString {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>>
    where
        Self: Sized,
    {
        ToSql::to_sql(&self.as_str(), ty, out)
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
        self.to_string().to_sql_checked(ty, out)
    }
}

impl<DB> DeToSql<Text, DB> for StackString
where
    DB: Backend,
    str: DeToSql<Text, DB>,
{
    fn to_sql<W: Write>(&self, out: &mut Output<W, DB>) -> SerResult {
        self.as_str().to_sql(out)
    }
}

impl<ST, DB> DeFromSql<ST, DB> for StackString
where
    DB: Backend,
    *const str: DeFromSql<ST, DB>,
{
    fn from_sql(bytes: Option<&DB::RawValue>) -> DeResult<Self> {
        let str_ptr = <*const str as DeFromSql<ST, DB>>::from_sql(bytes)?;
        let string = unsafe { &*str_ptr };
        Ok(string.into())
    }
}

impl Deref for StackString {
    type Target = str;

    #[inline]
    fn deref(&self) -> &str {
        self.0.as_ref()
    }
}

impl DerefMut for StackString {
    fn deref_mut(&mut self) -> &mut str {
        self.0.as_mut()
    }
}

impl AsRef<str> for StackString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for StackString {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl<'a> PartialEq<Cow<'a, str>> for StackString {
    #[inline]
    fn eq(&self, other: &Cow<'a, str>) -> bool {
        PartialEq::eq(&self[..], &other[..])
    }
}

impl<'a> PartialEq<String> for StackString {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        PartialEq::eq(&self[..], &other[..])
    }
}

impl<'a> PartialEq<str> for StackString {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        PartialEq::eq(&self[..], &other[..])
    }
}

impl<'a> PartialEq<&'a str> for StackString {
    #[inline]
    fn eq(&self, other: &&'a str) -> bool {
        PartialEq::eq(&self[..], &other[..])
    }
}
