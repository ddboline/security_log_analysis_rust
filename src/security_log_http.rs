#![allow(unused_imports)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::similar_names)]
#![allow(clippy::shadow_unrelated)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::case_sensitive_file_extension_comparisons)]
#![allow(clippy::default_trait_access)]

use anyhow::Error as AnyhowError;
use http::StatusCode;
use itertools::Itertools;
use log::error;
use rweb::{get, reject::Reject, Filter, Query, Rejection, Reply, Schema};
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use std::{convert::Infallible, env::var, net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::{
    task::{spawn, spawn_blocking, JoinError},
    time::sleep,
};

use security_log_analysis_rust::{
    config::Config, parse_logs::parse_systemd_logs_sshd_daemon, pgpool::PgPool,
    polars_analysis::read_parquet_files, reports::get_country_count_recent, Host, Service,
};

type WarpResult<T> = Result<T, Rejection>;

#[derive(Error, Debug)]
enum ServiceError {
    #[error("AnyhowError {0}")]
    AnyhowError(#[from] AnyhowError),
    #[error("JoinError {0}")]
    JoinError(#[from] JoinError),
}

impl Reject for ServiceError {}

#[derive(Serialize)]
struct ErrorMessage<'a> {
    code: u16,
    message: &'a str,
}

#[allow(clippy::unused_async)]
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
    } else if err.find::<rweb::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD NOT ALLOWED";
    } else {
        error!("Unknown error: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error, Please try again later";
    };

    let reply = rweb::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message,
    });
    let reply = rweb::reply::with_status(reply, code);

    Ok(Box::new(reply))
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

#[derive(Serialize, Deserialize, Schema)]
struct AttemptsQuery {
    ndays: Option<i32>,
}

#[get("/security_log/intrusion_attempts/{service}/{location}")]
async fn intrusion_attempts(
    service: Service,
    location: Host,
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let ndays = query.into_inner().ndays.unwrap_or(30);
    let results = get_country_count_recent(&data.pool, service, location, ndays)
        .await
        .map_err(Into::<ServiceError>::into)?
        .into_iter()
        .map(|cc| format!(r#"["{}", {}]"#, cc.country, cc.count))
        .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    Ok(rweb::reply::html(body))
}

#[get("/security_log/intrusion_attempts/{service}/{location}/all")]
async fn intrusion_attempts_all(
    service: Service,
    location: Host,
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let query = query.into_inner();
    let config = data.config.clone();
    let results = spawn_blocking(move || {
        read_parquet_files(
            &config.cache_dir,
            Some(service),
            Some(location),
            query.ndays,
        )
    })
    .await
    .map_err(Into::<ServiceError>::into)?
    .map_err(Into::<ServiceError>::into)?
    .into_iter()
    .map(|cc| format!(r#"["{}", {}]"#, cc.country, cc.count))
    .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    Ok(rweb::reply::html(body))
}

async fn _run_daemon(config: Config) {
    loop {
        let pool = PgPool::new(&config.database_url);
        parse_systemd_logs_sshd_daemon(&config, &pool)
            .await
            .unwrap_or(());
        sleep(Duration::from_secs(1)).await;
    }
}

async fn start_app() -> Result<(), AnyhowError> {
    let config = Config::init_config()?;

    let daemon_task = {
        let config = config.clone();
        spawn(async move { _run_daemon(config).await })
    };

    let pool = PgPool::new(&config.database_url);

    let app = AppState { pool, config };

    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    let intrusion_attemps_path =
        intrusion_attempts(app.clone()).or(intrusion_attempts_all(app.clone()));

    let cors = rweb::cors()
        .allow_methods(vec!["GET"])
        .allow_header("content-type")
        .allow_any_origin()
        .build();

    let routes = intrusion_attemps_path.recover(error_response).with(cors);
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    rweb::serve(routes).bind(addr).await;

    daemon_task.await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AnyhowError> {
    start_app().await
}
