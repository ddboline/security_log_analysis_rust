use anyhow::Error as AnyhowError;
use http::StatusCode;
use itertools::Itertools;
use log::error;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{convert::Infallible, env::var, net::SocketAddr};
use thiserror::Error;
use warp::{reject::Reject, Filter, Rejection, Reply};

use security_log_analysis_rust::{
    config::Config, pgpool_pg::PgPoolPg, reports::get_country_count_recent,
};

type WarpResult<T> = Result<T, Rejection>;

#[derive(Error, Debug)]
enum ServiceError {
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
}

impl Reject for ServiceError {}

#[derive(Serialize)]
struct ErrorMessage {
    code: u16,
    message: String,
}

pub async fn error_response(err: Rejection) -> Result<Box<dyn Reply>, Infallible> {
    let code: StatusCode;
    let message: &str;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT FOUND";
    } else if let Some(service_error) = err.find::<ServiceError>() {
        error!("{:?}", service_error);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error, Please try again later";
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD NOT ALLOWED";
    } else {
        error!("Unknown error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error, Please try again later";
    };

    let reply = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message: message.to_string(),
    });
    let reply = warp::reply::with_status(reply, code);

    Ok(Box::new(reply))
}

#[derive(Serialize, Deserialize)]
struct AttemptsQuery {
    ndays: Option<i32>,
}

async fn intrusion_attempts(
    service: StackString,
    location: StackString,
    query: AttemptsQuery,
    data: AppState,
) -> WarpResult<impl Reply> {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let server = format!("{}.ddboline.net", location);
    let ndays = query.ndays.unwrap_or(30);
    let results = get_country_count_recent(&data.db, &service, &server, ndays)
        .await
        .map_err(Into::<ServiceError>::into)?
        .into_iter()
        .map(|(x, y)| format!(r#"["{}", {}]"#, x, y))
        .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    Ok(warp::reply::html(body))
}

#[derive(Clone)]
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

    let data = AppState { db: pool.clone() };
    let data = warp::any().map(move || data.clone());

    let intrusion_attemps_path =
        warp::path!("security_log" / "intrusion_attempts" / StackString / StackString)
            .and(warp::path::end())
            .and(warp::get())
            .and(warp::query())
            .and(data.clone())
            .and_then(intrusion_attempts);

    let cors = warp::cors()
        .allow_methods(vec!["GET"])
        .allow_header("content-type")
        .allow_any_origin()
        .build();

    let routes = intrusion_attemps_path.recover(error_response).with(cors);
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    warp::serve(routes).bind(addr).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AnyhowError> {
    start_app().await
}
