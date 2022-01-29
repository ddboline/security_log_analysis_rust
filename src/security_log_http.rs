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
use rweb::{get, post, reject::Reject, Filter, Json, Query, Rejection, Reply, Schema};
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::{convert::Infallible, env::var, fmt::Write, net::SocketAddr, time::Duration};
use structopt::clap::AppSettings;
use thiserror::Error;
use tokio::{
    task::{spawn, spawn_blocking, JoinError},
    time::{interval, sleep},
};

use security_log_analysis_rust::{
    config::Config,
    errors::ServiceError,
    logged_user::{fill_from_db, get_secrets, LoggedUser, TRIGGER_DB_UPDATE},
    models::{HostCountry, IntrusionLog},
    parse_logs::parse_systemd_logs_sshd_daemon,
    pgpool::PgPool,
    polars_analysis::read_parquet_files,
    reports::get_country_count_recent,
    Host, Service,
};

type WarpResult<T> = Result<T, Rejection>;

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
    service: Option<Service>,
    location: Option<Host>,
    ndays: Option<i32>,
}

#[get("/security_log/intrusion_attempts")]
async fn intrusion_attempts(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let query = query.into_inner();
    let ndays = query.ndays.unwrap_or(30);
    let service = query.service.unwrap_or(Service::Ssh);
    let location = query.location.unwrap_or(Host::Home);
    let results = get_country_count_recent(&data.pool, service, location, ndays)
        .await
        .map_err(Into::<ServiceError>::into)?
        .into_iter()
        .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
        .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    Ok(rweb::reply::html(body))
}

#[get("/security_log/intrusion_attempts/all")]
async fn intrusion_attempts_all(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let template = include_str!("../templates/COUNTRY_TEMPLATE.html");
    let query = query.into_inner();
    let config = data.config.clone();
    let results = spawn_blocking(move || {
        read_parquet_files(
            &config.cache_dir,
            query.service,
            query.location,
            query.ndays,
        )
    })
    .await
    .map_err(Into::<ServiceError>::into)?
    .map_err(Into::<ServiceError>::into)?
    .into_iter()
    .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
    .join(",");
    let body = template.replace("PUTLISTOFCOUNTRIESANDATTEMPTSHERE", &results);
    Ok(rweb::reply::html(body))
}

#[derive(Serialize, Deserialize, Schema)]
struct SyncQuery {
    service: Option<Service>,
    server: Option<Host>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[get("/security_log/intrusion_log")]
async fn intursion_log_get(
    query: Query<SyncQuery>,
    #[data] data: AppState,
    #[filter = "LoggedUser::filter"] _: LoggedUser,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let limit = query.limit.unwrap_or(1000);
    let results = IntrusionLog::get_intrusion_log_filtered(
        &data.pool,
        query.service,
        query.server,
        None,
        None,
        Some(limit),
        query.offset,
    )
    .await
    .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::json(&results))
}

#[derive(Serialize, Deserialize, Schema)]
struct IntrusionLogUpdate {
    updates: Vec<IntrusionLog>,
}

#[post("/security_log/intrusion_log")]
async fn intrusion_log_post(
    payload: Json<Vec<IntrusionLog>>,
    #[data] data: AppState,
    #[filter = "LoggedUser::filter"] _: LoggedUser,
) -> WarpResult<impl Reply> {
    let payload = payload.into_inner();
    let inserts = IntrusionLog::insert(&data.pool, &payload)
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::html(format_sstr!("Inserts {}", inserts)))
}

#[derive(Serialize, Deserialize, Schema)]
struct HostCountryQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[get("/security_log/host_country")]
async fn host_country_get(
    query: Query<HostCountryQuery>,
    #[data] data: AppState,
    #[filter = "LoggedUser::filter"] _: LoggedUser,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let results = HostCountry::get_host_country(&data.pool, query.offset, query.limit, true)
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::json(&results))
}

#[post("/security_log/host_country")]
async fn host_country_post(
    payload: Json<Vec<HostCountry>>,
    #[data] data: AppState,
    #[filter = "LoggedUser::filter"] _: LoggedUser,
) -> WarpResult<impl Reply> {
    let payload = payload.into_inner();
    let mut inserts = 0;
    for entry in payload {
        inserts += entry
            .insert_host_country(&data.pool)
            .await
            .map_err(Into::<ServiceError>::into)?
            .map_or(0, |_| 1);
    }
    Ok(rweb::reply::html(format_sstr!("Inserts {inserts}")))
}

#[allow(clippy::unused_async)]
#[get("/security_log/user")]
async fn user(#[filter = "LoggedUser::filter"] user: LoggedUser) -> WarpResult<impl Reply> {
    Ok(rweb::reply::json(&user))
}

async fn start_app() -> Result<(), AnyhowError> {
    async fn update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            fill_from_db(&pool).await.unwrap_or(());
            i.tick().await;
        }
    }

    async fn run_daemon(config: Config, pool: PgPool) {
        loop {
            parse_systemd_logs_sshd_daemon(&config, &pool)
                .await
                .unwrap_or(());
            sleep(Duration::from_secs(1)).await;
        }
    }

    TRIGGER_DB_UPDATE.set();

    let config = Config::init_config()?;
    get_secrets(&config.secret_path, &config.jwt_secret_path).await?;

    let pool = PgPool::new(&config.database_url);

    spawn(run_daemon(config.clone(), pool.clone()));
    spawn(update_db(pool.clone()));

    let app = AppState { pool, config };

    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    let intrusion_attemps_path = intrusion_attempts(app.clone())
        .or(intrusion_attempts_all(app.clone()))
        .or(intursion_log_get(app.clone()))
        .or(intrusion_log_post(app.clone()))
        .or(host_country_get(app.clone()))
        .or(host_country_post(app.clone()))
        .or(user());

    let cors = rweb::cors()
        .allow_methods(vec!["GET"])
        .allow_header("content-type")
        .allow_any_origin()
        .build();

    let routes = intrusion_attemps_path.recover(error_response).with(cors);
    let addr: SocketAddr = format_sstr!("127.0.0.1:{port}").parse()?;
    rweb::serve(routes).bind(addr).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AnyhowError> {
    start_app().await
}
