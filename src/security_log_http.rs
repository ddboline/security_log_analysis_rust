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
#![allow(clippy::unused_async)]
#![allow(clippy::ignored_unit_patterns)]

pub mod security_log_element;

use anyhow::Error as AnyhowError;
use cached::{proc_macro::cached, Cached, TimedSizedCache};
use derive_more::{From, Into};
use futures::TryStreamExt;
use http::StatusCode;
use itertools::Itertools;
use log::error;
use rweb::{delete, get, post, reject::Reject, Filter, Json, Query, Rejection, Reply, Schema};
use rweb_helper::{derive_rweb_schema, DateTimeType, UuidWrapper};
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::{convert::Infallible, env::var, fmt, fmt::Write, net::SocketAddr, time::Duration};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{
    task::{spawn, spawn_blocking, JoinError},
    time::{interval, sleep},
};

use security_log_analysis_rust::{
    config::Config,
    errors::ServiceError,
    host_country_metadata::HostCountryMetadata,
    logged_user::{fill_from_db, get_secrets, LoggedUser, TRIGGER_DB_UPDATE},
    models::{HostCountry, IntrusionLog, LogLevel, SystemdLogMessages},
    parse_logs::{parse_systemd_logs_sshd_daemon, process_systemd_logs},
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

/// # Errors
/// Never returns error
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

#[derive(Serialize, Deserialize, Schema, Debug)]
struct AttemptsQuery {
    service: Option<Service>,
    location: Option<Host>,
    ndays: Option<i32>,
}

impl fmt::Display for AttemptsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "q:")?;
        if let Some(service) = self.service {
            writeln!(f, "s={}", service.abbreviation())?;
        }
        if let Some(location) = self.location {
            writeln!(f, "l={}", location.abbreviation())?;
        }
        if let Some(ndays) = self.ndays {
            writeln!(f, "n={ndays}")?;
        }
        Ok(())
    }
}

#[cached(
    type = "TimedSizedCache<StackString, StackString>",
    create = "{ TimedSizedCache::with_size_and_lifespan(100, 3600) }",
    convert = r#"{ format_sstr!("{}", query) }"#,
    result = true
)]
async fn get_cached_country_count(
    pool: &PgPool,
    query: AttemptsQuery,
) -> Result<StackString, ServiceError> {
    let ndays = query.ndays.unwrap_or(30);
    let service = query.service.unwrap_or(Service::Ssh);
    let location = query.location.unwrap_or(Host::Home);
    let results = get_country_count_recent(pool, service, location, ndays)
        .await
        .map_err(Into::<ServiceError>::into)?
        .into_iter()
        .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
        .join(",");
    let body = format_sstr!("[['Country', 'Number'],{results}]");
    Ok(body)
}

#[get("/security_log/map_script.js")]
async fn map_script() -> WarpResult<impl Reply> {
    let body = include_str!("../templates/map_script.js");
    Ok(rweb::reply::html(body))
}

#[get("/security_log/intrusion_attempts")]
async fn intrusion_attempts(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let config = data.config.clone();
    let data = get_cached_country_count(&data.pool, query).await?;
    let body = security_log_element::index_body(data, config);
    Ok(rweb::reply::html(body))
}

#[cached(
    type = "TimedSizedCache<StackString, StackString>",
    create = "{ TimedSizedCache::with_size_and_lifespan(100, 3600) }",
    convert = r#"{ format_sstr!("{}", query) }"#,
    result = true
)]
async fn get_cached_country_count_all(
    config: Config,
    query: AttemptsQuery,
) -> Result<StackString, ServiceError> {
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
    let body = format_sstr!("[['Country', 'Number'],{results}]");
    Ok(body)
}

#[get("/security_log/intrusion_attempts/all")]
async fn intrusion_attempts_all(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let config = data.config.clone();
    let data = get_cached_country_count_all(config.clone(), query).await?;
    let body = security_log_element::index_body(data, config);
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
    _: LoggedUser,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let limit = query.limit.unwrap_or(1000);
    let results: Vec<_> = IntrusionLog::get_intrusion_log_filtered(
        &data.pool,
        query.service,
        query.server,
        None,
        None,
        Some(limit),
        query.offset,
    )
    .await
    .map_err(Into::<ServiceError>::into)?
    .try_collect()
    .await
    .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::json(&results))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct IntrusionLogWrapper(IntrusionLog);

derive_rweb_schema!(IntrusionLogWrapper, _IntrusionLogWrapper);

#[allow(dead_code)]
#[derive(Schema)]
struct _IntrusionLogWrapper {
    id: UuidWrapper,
    service: StackString,
    server: StackString,
    datetime: DateTimeType,
    host: StackString,
    username: Option<StackString>,
}

#[derive(Serialize, Deserialize, Schema)]
struct IntrusionLogUpdate {
    updates: Vec<IntrusionLogWrapper>,
}

#[post("/security_log/intrusion_log")]
async fn intrusion_log_post(
    payload: Json<IntrusionLogUpdate>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<impl Reply> {
    let payload = payload.into_inner();
    let updates: Vec<_> = payload.updates.into_iter().map(Into::into).collect();
    let inserts = IntrusionLog::insert(&data.pool, &updates)
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
    _: LoggedUser,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let limit = query.limit.unwrap_or(1000);
    let results: Vec<_> =
        HostCountry::get_host_country(&data.pool, query.offset, Some(limit), true)
            .await
            .map_err(Into::<ServiceError>::into)?
            .try_collect()
            .await
            .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::json(&results))
}

#[derive(Serialize, Deserialize, Schema)]
struct HostCountryUpdate {
    updates: Vec<HostCountry>,
}

#[post("/security_log/host_country")]
async fn host_country_post(
    payload: Json<HostCountryUpdate>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<impl Reply> {
    let payload = payload.into_inner();
    let mut inserts = 0;
    for entry in payload.updates {
        inserts += entry
            .insert_host_country(&data.pool)
            .await
            .map_err(Into::<ServiceError>::into)?
            .map_or(0, |_| 1);
    }
    Ok(rweb::reply::html(format_sstr!("Inserts {inserts}")))
}

#[get("/security_log/cleanup")]
async fn host_country_cleanup(#[data] data: AppState, _: LoggedUser) -> WarpResult<impl Reply> {
    let mut lines = Vec::new();
    let metadata = HostCountryMetadata::from_pool(data.pool.clone())
        .await
        .map_err(Into::<ServiceError>::into)?;
    let hosts: Vec<_> = HostCountry::get_dangling_hosts(&data.pool)
        .await
        .map_err(Into::<ServiceError>::into)?
        .try_collect()
        .await
        .map_err(Into::<ServiceError>::into)?;
    for host in hosts {
        if let Ok(code) = metadata.get_whois_country_info_ipwhois(&host).await {
            let host_country =
                HostCountry::from_host_code(&host, &code).map_err(Into::<ServiceError>::into)?;
            HostCountry::insert_host_country(&host_country, &data.pool)
                .await
                .map_err(Into::<ServiceError>::into)?;
            lines.push(host_country);
        }
    }
    Ok(rweb::reply::json(&lines))
}

#[get("/security_log/user")]
#[allow(clippy::unused_async)]
async fn user(user: LoggedUser) -> WarpResult<impl Reply> {
    Ok(rweb::reply::json(&user))
}

#[derive(Serialize, Deserialize, Schema)]
struct LogMessageQuery {
    log_level: Option<LogLevel>,
    log_unit: Option<StackString>,
    min_date: Option<DateTimeType>,
    max_date: Option<DateTimeType>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[get("/security_log/log_messages")]
async fn get_log_messages(
    #[data] data: AppState,
    _: LoggedUser,
    query: Query<LogMessageQuery>,
) -> WarpResult<impl Reply> {
    let query = query.into_inner();
    let min_date: Option<OffsetDateTime> = query.min_date.map(Into::into);
    let max_date: Option<OffsetDateTime> = query.max_date.map(Into::into);
    let messages: Vec<_> = SystemdLogMessages::get_systemd_messages(
        &data.pool,
        query.log_level,
        query.log_unit.as_ref().map(Into::into),
        min_date.map(Into::into),
        max_date.map(Into::into),
        query.limit,
        query.offset,
    )
    .await
    .map_err(Into::<ServiceError>::into)?
    .try_collect()
    .await
    .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::json(&messages))
}

#[delete("/security_log/log_messages/{id}")]
async fn delete_log_message(
    #[data] data: AppState,
    _: LoggedUser,
    id: i32,
) -> WarpResult<impl Reply> {
    let bytes = SystemdLogMessages::delete(&data.pool, id)
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(rweb::reply::html(format_sstr!(
        "deleted {id}, {bytes} modified"
    )))
}

async fn start_app() -> Result<(), AnyhowError> {
    async fn update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            fill_from_db(&pool).await.unwrap_or(());
            i.tick().await;
        }
    }

    TRIGGER_DB_UPDATE.set();

    let config = Config::init_config()?;
    get_secrets(&config.secret_path, &config.jwt_secret_path).await?;

    let pool = PgPool::new(&config.database_url);

    spawn(update_db(pool.clone()));

    let app = AppState { pool, config };

    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    let intrusion_attempts_path = intrusion_attempts(app.clone())
        .or(map_script())
        .or(intrusion_attempts_all(app.clone()))
        .or(intursion_log_get(app.clone()))
        .or(intrusion_log_post(app.clone()))
        .or(host_country_get(app.clone()))
        .or(host_country_post(app.clone()))
        .or(host_country_cleanup(app.clone()))
        .or(user())
        .or(get_log_messages(app.clone()))
        .or(delete_log_message(app.clone()));

    let cors = rweb::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_any_origin()
        .build();

    let routes = intrusion_attempts_path.recover(error_response).with(cors);
    let addr: SocketAddr = format_sstr!("127.0.0.1:{port}").parse()?;
    rweb::serve(routes).bind(addr).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AnyhowError> {
    tokio::spawn(async move { start_app().await })
        .await
        .unwrap()
}

#[cfg(test)]
mod test {
    use anyhow::Error;

    use security_log_analysis_rust::{Host, Service};

    use crate::AttemptsQuery;

    #[test]
    fn test_attempt_query_display() -> Result<(), Error> {
        let q = AttemptsQuery {
            service: Some(Service::Nginx),
            location: Some(Host::Cloud),
            ndays: Some(15),
        };
        let q_str = format!("{}", q);
        assert_eq!(16, q_str.len());
        assert_eq!(q_str, format!("q:\ns=n\nl=c\nn=15\n"));
        Ok(())
    }
}
