use anyhow::Error as AnyhowError;
use axum::{extract::Json, http::StatusCode};
use log::error;
use postgres_query::Error as PgError;
use serde::Serialize;
use stack_string::{format_sstr, StackString};
use std::fmt::Error as FmtError;
use thiserror::Error;
use tokio::task::JoinError;
use utoipa::{
    openapi::{
        content::ContentBuilder,
        response::{ResponseBuilder, ResponsesBuilder},
    },
    IntoResponses, PartialSchema, ToSchema,
};

use crate::logged_user::LOGIN_HTML;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
    #[error("PgError {0}")]
    PgError(#[from] PgError),
    #[error("FmtError {0}")]
    FmtError(#[from] FmtError),
}

impl axum::response::IntoResponse for ServiceError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Unauthorized => (StatusCode::OK, LOGIN_HTML).into_response(),
            e => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorMessage {
                    message: format_sstr!("Internal Server Error: {e}"),
                },
            )
                .into_response(),
        }
    }
}

#[derive(Serialize, ToSchema)]
struct ErrorMessage {
    message: StackString,
}

impl axum::response::IntoResponse for ErrorMessage {
    fn into_response(self) -> axum::response::Response {
        Json(self).into_response()
    }
}

impl IntoResponses for ServiceError {
    fn responses() -> std::collections::BTreeMap<
        String,
        utoipa::openapi::RefOr<utoipa::openapi::response::Response>,
    > {
        let error_message_content = ContentBuilder::new()
            .schema(Some(ErrorMessage::schema()))
            .build();
        ResponsesBuilder::new()
            .response(
                StatusCode::UNAUTHORIZED.as_str(),
                ResponseBuilder::new()
                    .description("Not Authorized")
                    .content(
                        "text/html",
                        ContentBuilder::new().schema(Some(String::schema())).build(),
                    ),
            )
            .response(
                StatusCode::BAD_REQUEST.as_str(),
                ResponseBuilder::new()
                    .description("Bad Request")
                    .content("application/json", error_message_content.clone()),
            )
            .response(
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                ResponseBuilder::new()
                    .description("Internal Server Error")
                    .content("application/json", error_message_content.clone()),
            )
            .build()
            .into()
    }
}
