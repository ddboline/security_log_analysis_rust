use anyhow::Error as AnyhowError;
use postgres_query::Error as PqError;
use rweb::reject::Reject;
use thiserror::Error;
use tokio::task::JoinError;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("PqError {0}")]
    PqError(#[from] PqError),
}

impl Reject for ServiceError {}
