pub use authorized_users::{
    get_random_key, get_secrets, token::Token, AuthorizedUser, AUTHORIZED_USERS, JWT_SECRET,
    KEY_LENGTH, SECRET_KEY, TRIGGER_DB_UPDATE,
};
use log::debug;
use rweb::{filters::cookie::cookie, Filter, Rejection, Schema};
use rweb_helper::UuidWrapper;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{
    convert::{TryFrom, TryInto},
    env::var,
    str::FromStr,
};
use uuid::Uuid;

use crate::{errors::ServiceError as Error, models::AuthorizedUsers, pgpool::PgPool};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Schema)]
pub struct LoggedUser {
    #[schema(description = "Email Address")]
    pub email: StackString,
    #[schema(description = "Session Id")]
    pub session: UuidWrapper,
}

impl LoggedUser {
    /// # Errors
    /// Return error if `session_id` matches `LoggedUser`
    pub fn verify_session_id(&self, session_id: Uuid) -> Result<(), Error> {
        let session_id = session_id.into();
        if self.session == session_id {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }

    #[must_use]
    pub fn filter() -> impl Filter<Extract = (Self,), Error = Rejection> + Copy {
        cookie("session-id")
            .and(cookie("jwt"))
            .and_then(|id: Uuid, user: Self| async move {
                user.verify_session_id(id)
                    .map(|_| user)
                    .map_err(rweb::reject::custom)
            })
    }
}

impl From<AuthorizedUser> for LoggedUser {
    fn from(user: AuthorizedUser) -> Self {
        Self {
            email: user.email,
            session: user.session.into(),
        }
    }
}

impl TryFrom<Token> for LoggedUser {
    type Error = Error;
    fn try_from(token: Token) -> Result<Self, Self::Error> {
        let user = token.try_into()?;
        if AUTHORIZED_USERS.is_authorized(&user) {
            Ok(user.into())
        } else {
            debug!("NOT AUTHORIZED {:?}", user);
            Err(Error::Unauthorized)
        }
    }
}

impl FromStr for LoggedUser {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut buf = StackString::new();
        buf.push_str(s);
        let token: Token = buf.into();
        token.try_into()
    }
}

/// # Errors
/// Return error if db query fails
pub async fn fill_from_db(pool: &PgPool) -> Result<(), Error> {
    debug!("{:?}", *TRIGGER_DB_UPDATE);
    let users: Vec<_> = if TRIGGER_DB_UPDATE.check() {
        AuthorizedUsers::get_authorized_users(pool)
            .await?
            .into_iter()
            .map(|user| user.email)
            .collect()
    } else {
        AUTHORIZED_USERS.get_users()
    };
    if let Ok("true") = var("TESTENV").as_ref().map(String::as_str) {
        AUTHORIZED_USERS.merge_users(["user@test"]);
    }
    AUTHORIZED_USERS.merge_users(&users);

    debug!("{:?}", *AUTHORIZED_USERS);
    Ok(())
}
