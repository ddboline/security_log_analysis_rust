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
use itertools::Itertools;
use log::error;
use rweb::{
    delete,
    filters::BoxedFilter,
    get,
    http::{header::CONTENT_TYPE, StatusCode},
    openapi,
    openapi::Info,
    post,
    reject::{InvalidHeader, MissingCookie, Reject},
    Filter, Json, Query, Rejection, Reply, Schema,
};
use rweb_helper::{
    derive_rweb_schema, html_response::HtmlResponse as HtmlBase,
    json_response::JsonResponse as JsonBase, DateTimeType, RwebResponse, UuidWrapper,
};
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::{
    convert::Infallible, env::var, fmt, fmt::Write, net::SocketAddr, sync::Arc, time::Duration,
};
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
    logged_user::{fill_from_db, get_secrets, LoggedUser, LOGIN_HTML, TRIGGER_DB_UPDATE},
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

fn login_html() -> impl Reply {
    rweb::reply::html(LOGIN_HTML)
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
    } else if err.find::<InvalidHeader>().is_some() {
        TRIGGER_DB_UPDATE.set();
        return Ok(Box::new(login_html()));
    } else if let Some(missing_cookie) = err.find::<MissingCookie>() {
        if missing_cookie.name() == "jwt" {
            TRIGGER_DB_UPDATE.set();
            return Ok(Box::new(login_html()));
        }
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error";
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
    ty = "TimedSizedCache<StackString, StackString>",
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

#[derive(RwebResponse)]
#[response(description = "Map Drawing Script", content = "js")]
struct MapScriptResponse(HtmlBase<&'static str, Infallible>);

#[get("/security_log/map_script.js")]
async fn map_script() -> WarpResult<MapScriptResponse> {
    let body = include_str!("../templates/map_script.js");
    Ok(HtmlBase::new(body).into())
}

#[derive(RwebResponse)]
#[response(description = "Intrusion Attempts", content = "html")]
struct IntrusionAttemptsResponse(HtmlBase<StackString, ServiceError>);

#[get("/security_log/intrusion_attempts")]
async fn intrusion_attempts(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<IntrusionAttemptsResponse> {
    let query = query.into_inner();
    let config = data.config.clone();
    let data = get_cached_country_count(&data.pool, query).await?;
    let body = security_log_element::index_body(data, config)?;
    Ok(HtmlBase::new(body.into()).into())
}

#[cached(
    ty = "TimedSizedCache<StackString, StackString>",
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

#[derive(RwebResponse)]
#[response(description = "All Intrusion Attempts", content = "html")]
struct IntrusionAttemptsAllResponse(HtmlBase<StackString, ServiceError>);

#[get("/security_log/intrusion_attempts/all")]
async fn intrusion_attempts_all(
    query: Query<AttemptsQuery>,
    #[data] data: AppState,
) -> WarpResult<IntrusionAttemptsAllResponse> {
    let query = query.into_inner();
    let config = data.config.clone();
    let data = get_cached_country_count_all(config.clone(), query).await?;
    let body = security_log_element::index_body(data, config)?;
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(Serialize, Deserialize, Schema)]
struct SyncQuery {
    service: Option<Service>,
    server: Option<Host>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Schema)]
#[schema(component = "Pagination")]
struct Pagination {
    #[schema(description = "Total Number of Entries")]
    total: usize,
    #[schema(description = "Number of Entries to Skip")]
    offset: usize,
    #[schema(description = "Number of Entries Returned")]
    limit: usize,
}

#[derive(Debug, Serialize, Deserialize, Schema)]
#[schema(component = "PaginatedIntrusionLog")]
struct PaginatedIntrusionLog {
    pagination: Pagination,
    data: Vec<IntrusionLogWrapper>,
}

#[derive(RwebResponse)]
#[response(description = "Intrusion Logs")]
struct IntrusionLogResponse(JsonBase<PaginatedIntrusionLog, ServiceError>);

#[get("/security_log/intrusion_log")]
async fn intursion_log_get(
    query: Query<SyncQuery>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<IntrusionLogResponse> {
    let query = query.into_inner();
    let total = IntrusionLog::get_intrusion_log_filtered_total(
        &data.pool,
        query.service,
        query.server,
        None,
        None,
    )
    .await
    .map_err(Into::<ServiceError>::into)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(10);
    let pagination = Pagination {
        total,
        offset,
        limit,
    };

    let data: Vec<_> = IntrusionLog::get_intrusion_log_filtered(
        &data.pool,
        query.service,
        query.server,
        None,
        None,
        Some(offset),
        Some(limit),
    )
    .await
    .map_err(Into::<ServiceError>::into)?
    .map_ok(Into::into)
    .try_collect()
    .await
    .map_err(Into::<ServiceError>::into)?;
    Ok(JsonBase::new(PaginatedIntrusionLog { pagination, data }).into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct IntrusionLogWrapper(IntrusionLog);

derive_rweb_schema!(IntrusionLogWrapper, _IntrusionLogWrapper);

#[allow(dead_code)]
#[derive(Schema)]
#[schema(component = "IntrusionLog")]
struct _IntrusionLogWrapper {
    id: UuidWrapper,
    service: StackString,
    server: StackString,
    datetime: DateTimeType,
    host: StackString,
    username: Option<StackString>,
}

#[derive(Serialize, Deserialize, Schema)]
#[schema(component = "IntrusionLogUpdate")]
struct IntrusionLogUpdate {
    updates: Vec<IntrusionLogWrapper>,
}

#[derive(RwebResponse)]
#[response(description = "Intrusion Log Post", status = "CREATED")]
struct IntrusionLogPostResponse(HtmlBase<StackString, ServiceError>);

#[post("/security_log/intrusion_log")]
async fn intrusion_log_post(
    payload: Json<IntrusionLogUpdate>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<IntrusionLogPostResponse> {
    let payload = payload.into_inner();
    let updates: Vec<_> = payload.updates.into_iter().map(Into::into).collect();
    let inserts = IntrusionLog::insert(&data.pool, &updates)
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(HtmlBase::new(format_sstr!("Inserts {}", inserts)).into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct HostCountryWrapper(HostCountry);

derive_rweb_schema!(HostCountryWrapper, _HostCountryWrapper);

#[allow(dead_code)]
#[derive(Schema)]
#[schema(component = "HostCountry")]
struct _HostCountryWrapper {
    #[schema(description = "Host")]
    pub host: StackString,
    #[schema(description = "Country Code")]
    pub code: StackString,
    #[schema(description = "IP Address")]
    pub ipaddr: Option<StackString>,
    #[schema(description = "Created At")]
    pub created_at: DateTimeType,
}

#[derive(Serialize, Deserialize, Schema)]
struct HostCountryQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Schema)]
#[schema(component = "PaginatedHostCountry")]
struct PaginatedHostCountry {
    pagination: Pagination,
    data: Vec<HostCountryWrapper>,
}

#[derive(RwebResponse)]
#[response(description = "Host Countries")]
struct HostCountryResponse(JsonBase<PaginatedHostCountry, ServiceError>);

#[get("/security_log/host_country")]
async fn host_country_get(
    query: Query<HostCountryQuery>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<HostCountryResponse> {
    let query = query.into_inner();
    let total = HostCountry::get_host_country_total(&data.pool)
        .await
        .map_err(Into::<ServiceError>::into)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(10);
    let pagination = Pagination {
        total,
        offset,
        limit,
    };

    let data: Vec<_> = HostCountry::get_host_country(&data.pool, query.offset, Some(limit), true)
        .await
        .map_err(Into::<ServiceError>::into)?
        .map_ok(Into::into)
        .try_collect()
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(JsonBase::new(PaginatedHostCountry { pagination, data }).into())
}

#[derive(Serialize, Deserialize, Schema)]
#[schema(component = "HostCountryUpdate")]
struct HostCountryUpdate {
    updates: Vec<HostCountry>,
}

#[derive(RwebResponse)]
#[response(description = "Host Country Post", status = "CREATED")]
struct HostCountryPostResponse(HtmlBase<StackString, ServiceError>);

#[post("/security_log/host_country")]
async fn host_country_post(
    payload: Json<HostCountryUpdate>,
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<HostCountryPostResponse> {
    let payload = payload.into_inner();
    let mut inserts = 0;
    for entry in payload.updates {
        inserts += entry
            .insert_host_country(&data.pool)
            .await
            .map_err(Into::<ServiceError>::into)?
            .map_or(0, |_| 1);
    }
    Ok(HtmlBase::new(format_sstr!("Inserts {inserts}")).into())
}

#[derive(RwebResponse)]
#[response(description = "Host Country Cleanup", status = "CREATED")]
struct HostCountryCleanupResponse(JsonBase<Vec<HostCountryWrapper>, ServiceError>);

#[post("/security_log/cleanup")]
async fn host_country_cleanup(
    #[data] data: AppState,
    _: LoggedUser,
) -> WarpResult<HostCountryCleanupResponse> {
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
            lines.push(host_country.into());
        }
    }
    Ok(JsonBase::new(lines).into())
}

#[derive(RwebResponse)]
#[response(description = "Logged User")]
struct LoggedUserResponse(JsonBase<LoggedUser, ServiceError>);

#[get("/security_log/user")]
#[allow(clippy::unused_async)]
async fn user(user: LoggedUser) -> WarpResult<LoggedUserResponse> {
    Ok(JsonBase::new(user).into())
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct SystemdLogMessagesWrapper(SystemdLogMessages);

derive_rweb_schema!(SystemdLogMessagesWrapper, _SystemdLogMessagesWrapper);

#[allow(dead_code)]
#[derive(Schema)]
#[schema(component = "SystemdLogMessages")]
struct _SystemdLogMessagesWrapper {
    #[schema(description = "ID")]
    id: UuidWrapper,
    #[schema(description = "Log Level")]
    log_level: LogLevel,
    #[schema(description = "Log Unit")]
    log_unit: Option<StackString>,
    #[schema(description = "Log Message")]
    log_message: StackString,
    #[schema(description = "Log Timestamp")]
    log_timestamp: DateTimeType,
    #[schema(description = "Log Processed At Time")]
    processed_time: Option<DateTimeType>,
}

#[derive(Debug, Serialize, Deserialize, Schema)]
#[schema(component = "PaginatedSystemdLogMessages")]
struct PaginatedSystemdLogMessages {
    pagination: Pagination,
    data: Vec<SystemdLogMessagesWrapper>,
}

#[derive(RwebResponse)]
#[response(description = "Log Messages")]
struct LogMessagesResponse(JsonBase<PaginatedSystemdLogMessages, ServiceError>);

#[get("/security_log/log_messages")]
async fn get_log_messages(
    #[data] data: AppState,
    _: LoggedUser,
    query: Query<LogMessageQuery>,
) -> WarpResult<LogMessagesResponse> {
    let query = query.into_inner();
    let min_date: Option<OffsetDateTime> = query.min_date.map(Into::into);
    let max_date: Option<OffsetDateTime> = query.max_date.map(Into::into);
    let log_level = query.log_level;
    let log_unit: Option<&str> = query.log_unit.as_ref().map(Into::into);
    let total = SystemdLogMessages::get_total(
        &data.pool,
        log_level,
        log_unit,
        min_date.map(Into::into),
        max_date.map(Into::into),
    )
    .await
    .map_err(Into::<ServiceError>::into)?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(10);
    let pagination = Pagination {
        total,
        offset,
        limit,
    };

    let data: Vec<_> = SystemdLogMessages::get_systemd_messages(
        &data.pool,
        log_level,
        log_unit,
        min_date.map(Into::into),
        max_date.map(Into::into),
        Some(offset),
        Some(limit),
    )
    .await
    .map_err(Into::<ServiceError>::into)?
    .map_ok(Into::into)
    .try_collect()
    .await
    .map_err(Into::<ServiceError>::into)?;
    Ok(JsonBase::new(PaginatedSystemdLogMessages { pagination, data }).into())
}

#[derive(RwebResponse)]
#[response(description = "Delete Log Messages", status = "NO_CONTENT")]
struct DeleteLogMessageResponse(HtmlBase<StackString, ServiceError>);

#[delete("/security_log/log_messages/{id}")]
async fn delete_log_message(
    #[data] data: AppState,
    _: LoggedUser,
    id: i32,
) -> WarpResult<DeleteLogMessageResponse> {
    let bytes = SystemdLogMessages::delete(&data.pool, id)
        .await
        .map_err(Into::<ServiceError>::into)?;
    Ok(HtmlBase::new(format_sstr!("deleted {id}, {bytes} modified")).into())
}

fn get_path(app: &AppState) -> BoxedFilter<(impl Reply,)> {
    intrusion_attempts(app.clone())
        .or(map_script())
        .or(intrusion_attempts_all(app.clone()))
        .or(intursion_log_get(app.clone()))
        .or(intrusion_log_post(app.clone()))
        .or(host_country_get(app.clone()))
        .or(host_country_post(app.clone()))
        .or(host_country_cleanup(app.clone()))
        .or(user())
        .or(get_log_messages(app.clone()))
        .or(delete_log_message(app.clone()))
        .boxed()
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

    let pool = PgPool::new(&config.database_url)?;

    spawn(update_db(pool.clone()));

    let app = AppState { pool, config };

    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    let (spec, intrusion_attempts_path) = openapi::spec()
        .info(Info {
            title: "Frontend for AWS".into(),
            description: "Web Frontend for AWS Services".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            ..Info::default()
        })
        .build(|| get_path(&app));
    let spec = Arc::new(spec);
    let spec_json_path = rweb::path!("security_log" / "openapi" / "json")
        .and(rweb::path::end())
        .map({
            let spec = spec.clone();
            move || rweb::reply::json(spec.as_ref())
        });

    let spec_yaml = serde_yaml::to_string(spec.as_ref())?;
    let spec_yaml_path = rweb::path!("security_log" / "openapi" / "yaml")
        .and(rweb::path::end())
        .map(move || {
            let reply = rweb::reply::html(spec_yaml.clone());
            rweb::reply::with_header(reply, CONTENT_TYPE, "text/yaml")
        });

    let cors = rweb::cors()
        .allow_methods(vec!["GET", "POST", "DELETE"])
        .allow_header("content-type")
        .allow_any_origin()
        .build();

    let routes = intrusion_attempts_path
        .or(spec_json_path)
        .or(spec_yaml_path)
        .recover(error_response)
        .with(cors);
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
