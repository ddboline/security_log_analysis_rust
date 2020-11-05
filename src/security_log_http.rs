use actix_web::{
    error::ResponseError,
    web::{self, Data, Path, Query},
    App, HttpResponse, HttpServer,
};
use anyhow::Error as AnyhowError;
use itertools::Itertools;
use log::error;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::env::var;
use thiserror::Error;

use security_log_analysis_rust::{
    config::Config, pgpool_pg::PgPoolPg, reports::get_country_count_recent,
};

type HttpResult = Result<HttpResponse, ServiceError>;

#[derive(Error, Debug)]
enum ServiceError {
    #[error("Internal Server Error")]
    InternalServerError,
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
}

impl ResponseError for ServiceError {
    fn error_response(&self) -> HttpResponse {
        match self {
            Self::InternalServerError => {
                HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
            }
            Self::AnyhowError(err) => {
                error!("Received error {}", err);
                HttpResponse::InternalServerError().json("Internal Server Error, Please try later")
            }
        }
    }
}

fn form_http_response(body: String) -> HttpResult {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body))
}

#[derive(Serialize, Deserialize)]
struct ServiceLocation {
    service: StackString,
    location: StackString,
}

#[derive(Serialize, Deserialize)]
struct AttemptsQuery {
    ndays: Option<i32>,
}

async fn intrusion_attempts(path: Path<ServiceLocation>, query: Query<AttemptsQuery>, data: Data<AppState>) -> HttpResult {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let server = format!("{}.ddboline.net", path.location);
    let ndays = query.ndays.unwrap_or(30);
    let results = get_country_count_recent(&data.db, &path.service, &server, ndays)
        .await?
        .into_iter()
        .map(|(x, y)| format!(r#"["{}", {}]"#, x, y))
        .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    form_http_response(body)
}

struct AppState {
    db: PgPoolPg,
}

async fn start_app() -> Result<(), AnyhowError> {
    let config = Config::init_config()?;
    let pool = PgPoolPg::new(&config.database_url);

    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    HttpServer::new(move || {
        App::new().data(AppState { db: pool.clone() }).service(
            web::resource("/security_log/intrusion_attempts/{service}/{location}")
                .route(web::get().to(intrusion_attempts)),
        )
    })
    .bind(&format!("127.0.0.1:{}", port))?
    .run()
    .await?;
    Ok(())
}

#[actix_web::main]
async fn main() -> Result<(), AnyhowError> {
    start_app().await
}
