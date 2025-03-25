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
use axum::{
    extract::{Json, Path, Query, State},
    http::{Method, StatusCode},
};
use cached::{proc_macro::cached, Cached, TimedSizedCache};
use derive_more::{From, Into};
use futures::TryStreamExt;
use itertools::Itertools;
use log::error;
use serde::{Deserialize, Serialize};
use stack_string::{format_sstr, StackString};
use std::{
    convert::{Infallible, TryInto},
    env::var,
    fmt,
    fmt::Write,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    task::{spawn, spawn_blocking, JoinError},
    time::{interval, sleep},
};
use tower_http::cors::{Any, CorsLayer};
use utoipa::{OpenApi, PartialSchema, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_helper::{
    derive_utoipa_schema, html_response::HtmlResponse as HtmlBase,
    json_response::JsonResponse as JsonBase, UtoipaResponse,
};
use uuid::Uuid;

use security_log_analysis_rust::{
    config::Config,
    errors::ServiceError as Error,
    host_country_metadata::HostCountryMetadata,
    logged_user::{fill_from_db, get_secrets, LoggedUser, LOGIN_HTML},
    models::{HostCountry, IntrusionLog, LogLevel, SystemdLogMessages},
    parse_logs::{parse_systemd_logs_sshd_daemon, process_systemd_logs},
    pgpool::PgPool,
    polars_analysis::read_parquet_files,
    reports::get_country_count_recent,
    Host, Service,
};

type WarpResult<T> = Result<T, Error>;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Config,
}

#[derive(Serialize, Deserialize, ToSchema, Debug)]
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
) -> Result<StackString, Error> {
    let ndays = query.ndays.unwrap_or(30);
    let service = query.service.unwrap_or(Service::Ssh);
    let location = query.location.unwrap_or(Host::Home);
    let results = get_country_count_recent(pool, service, location, ndays)
        .await?
        .into_iter()
        .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
        .join(",");
    let body = format_sstr!("[['Country', 'Number'],{results}]");
    Ok(body)
}

#[derive(UtoipaResponse)]
#[response(description = "Map Drawing Script", content = "text/javascript")]
#[rustfmt::skip]
struct MapScriptResponse(HtmlBase::<&'static str>);

#[utoipa::path(
    get,
    path = "/security_log/map_script.js",
    responses(MapScriptResponse, Error)
)]
async fn map_script() -> WarpResult<MapScriptResponse> {
    let body = include_str!("../templates/map_script.js");
    Ok(HtmlBase::new(body).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Intrusion Attempts", content = "text/html")]
#[rustfmt::skip]
struct IntrusionAttemptsResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/security_log/intrusion_attempts",
    responses(IntrusionAttemptsResponse, Error)
)]
async fn intrusion_attempts(
    query: Query<AttemptsQuery>,
    data: State<Arc<AppState>>,
) -> WarpResult<IntrusionAttemptsResponse> {
    let Query(query) = query;
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
) -> WarpResult<StackString> {
    let results = spawn_blocking(move || {
        read_parquet_files(
            &config.cache_dir,
            query.service,
            query.location,
            query.ndays,
        )
    })
    .await??
    .into_iter()
    .map(|cc| format_sstr!(r#"["{}", {}]"#, cc.country, cc.count))
    .join(",");
    let body = format_sstr!("[['Country', 'Number'],{results}]");
    Ok(body)
}

#[derive(UtoipaResponse)]
#[response(description = "All Intrusion Attempts", content = "text/html")]
#[rustfmt::skip]
struct IntrusionAttemptsAllResponse(HtmlBase::<StackString>);

#[utoipa::path(
    get,
    path = "/security_log/intrusion_attempts/all",
    responses(IntrusionAttemptsAllResponse, Error)
)]
async fn intrusion_attempts_all(
    query: Query<AttemptsQuery>,
    data: State<Arc<AppState>>,
) -> WarpResult<IntrusionAttemptsAllResponse> {
    let Query(query) = query;
    let config = data.config.clone();
    let data = get_cached_country_count_all(config.clone(), query).await?;
    let body = security_log_element::index_body(data, config)?;
    Ok(HtmlBase::new(body.into()).into())
}

#[derive(Serialize, Deserialize, ToSchema)]
struct SyncQuery {
    service: Option<Service>,
    server: Option<Host>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
// Pagination
struct Pagination {
    // Total Number of Entries
    total: usize,
    // Number of Entries to Skip
    offset: usize,
    // Number of Entries Returned
    limit: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
// PaginatedIntrusionLog
struct PaginatedIntrusionLog {
    pagination: Pagination,
    data: Vec<IntrusionLogWrapper>,
}

#[derive(UtoipaResponse)]
#[response(description = "Intrusion Logs")]
#[rustfmt::skip]
struct IntrusionLogResponse(JsonBase::<PaginatedIntrusionLog>);

#[utoipa::path(
    get,
    path = "/security_log/intrusion_log",
    responses(IntrusionLogResponse, Error)
)]
async fn intursion_log_get(
    data: State<Arc<AppState>>,
    query: Query<SyncQuery>,
    _: LoggedUser,
) -> WarpResult<IntrusionLogResponse> {
    let Query(query) = query;
    let total = IntrusionLog::get_intrusion_log_filtered_total(
        &data.pool,
        query.service,
        query.server,
        None,
        None,
    )
    .await?;
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
    .await?
    .map_ok(Into::into)
    .try_collect()
    .await?;
    Ok(JsonBase::new(PaginatedIntrusionLog { pagination, data }).into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct IntrusionLogWrapper(IntrusionLog);

derive_utoipa_schema!(IntrusionLogWrapper, _IntrusionLogWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
// IntrusionLog")]
#[schema(as = IntrusionLog)]
struct _IntrusionLogWrapper {
    id: Uuid,
    service: StackString,
    server: StackString,
    datetime: OffsetDateTime,
    host: StackString,
    username: Option<StackString>,
}

#[derive(Serialize, Deserialize, ToSchema)]
// IntrusionLogUpdate")]
struct IntrusionLogUpdate {
    updates: Vec<IntrusionLogWrapper>,
}

#[derive(UtoipaResponse)]
#[response(description = "Intrusion Log Post", status = "CREATED")]
#[rustfmt::skip]
struct IntrusionLogPostResponse(HtmlBase::<StackString>);

#[utoipa::path(
    post,
    path = "/security_log/intrusion_log",
    responses(IntrusionLogPostResponse, Error)
)]
async fn intrusion_log_post(
    data: State<Arc<AppState>>,
    _: LoggedUser,
    payload: Json<IntrusionLogUpdate>,
) -> WarpResult<IntrusionLogPostResponse> {
    let Json(payload) = payload;
    let updates: Vec<_> = payload.updates.into_iter().map(Into::into).collect();
    let inserts = IntrusionLog::insert(&data.pool, &updates).await?;
    Ok(HtmlBase::new(format_sstr!("Inserts {}", inserts)).into())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct HostCountryWrapper(HostCountry);

derive_utoipa_schema!(HostCountryWrapper, _HostCountryWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
// HostCountry")]
#[schema(as = HostCountry)]
struct _HostCountryWrapper {
    // Host")]
    pub host: StackString,
    // Country Code")]
    pub code: StackString,
    // IP Address")]
    pub ipaddr: Option<StackString>,
    // Created At")]
    pub created_at: OffsetDateTime,
}

#[derive(Serialize, Deserialize, ToSchema)]
struct HostCountryQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
// PaginatedHostCountry")]
struct PaginatedHostCountry {
    pagination: Pagination,
    data: Vec<HostCountryWrapper>,
}

#[derive(UtoipaResponse)]
#[response(description = "Host Countries")]
#[rustfmt::skip]
struct HostCountryResponse(JsonBase::<PaginatedHostCountry>);

#[utoipa::path(
    get,
    path = "/security_log/host_country",
    responses(HostCountryResponse, Error)
)]
async fn host_country_get(
    query: Query<HostCountryQuery>,
    data: State<Arc<AppState>>,
    _: LoggedUser,
) -> WarpResult<HostCountryResponse> {
    let Query(query) = query;
    let total = HostCountry::get_host_country_total(&data.pool).await?;
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(10);
    let pagination = Pagination {
        total,
        offset,
        limit,
    };

    let data: Vec<_> = HostCountry::get_host_country(&data.pool, query.offset, Some(limit), true)
        .await?
        .map_ok(Into::into)
        .try_collect()
        .await?;
    Ok(JsonBase::new(PaginatedHostCountry { pagination, data }).into())
}

#[derive(Serialize, Deserialize, ToSchema)]
// HostCountryUpdate")]
struct HostCountryUpdate {
    updates: Vec<HostCountry>,
}

#[derive(UtoipaResponse)]
#[response(description = "Host Country Post", status = "CREATED")]
#[rustfmt::skip]
struct HostCountryPostResponse(HtmlBase::<StackString>);

#[utoipa::path(
    post,
    path = "/security_log/host_country",
    responses(HostCountryPostResponse, Error)
)]
async fn host_country_post(
    data: State<Arc<AppState>>,
    _: LoggedUser,
    payload: Json<HostCountryUpdate>,
) -> WarpResult<HostCountryPostResponse> {
    let Json(payload) = payload;
    let mut inserts = 0;
    for entry in payload.updates {
        inserts += entry
            .insert_host_country(&data.pool)
            .await?
            .map_or(0, |_| 1);
    }
    Ok(HtmlBase::new(format_sstr!("Inserts {inserts}")).into())
}

#[derive(Serialize, ToSchema, Into, From)]
struct HostCountryInner(Vec<HostCountryWrapper>);

#[derive(UtoipaResponse)]
#[response(description = "Host Country Cleanup", status = "CREATED")]
#[rustfmt::skip]
struct HostCountryCleanupResponse(JsonBase::<HostCountryInner>);

#[utoipa::path(
    post,
    path = "/security_log/cleanup",
    responses(HostCountryCleanupResponse, Error)
)]
async fn host_country_cleanup(
    data: State<Arc<AppState>>,
    _: LoggedUser,
) -> WarpResult<HostCountryCleanupResponse> {
    let mut lines = Vec::new();
    let metadata = HostCountryMetadata::from_pool(data.pool.clone()).await?;
    let hosts: Vec<_> = HostCountry::get_dangling_hosts(&data.pool)
        .await?
        .try_collect()
        .await?;
    for host in hosts {
        if let Ok(code) = metadata.get_whois_country_info_ipwhois(&host).await {
            let host_country = HostCountry::from_host_code(&host, &code)?;
            HostCountry::insert_host_country(&host_country, &data.pool).await?;
            lines.push(host_country.into());
        }
    }
    Ok(JsonBase::new(lines.into()).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Logged User")]
#[rustfmt::skip]
struct LoggedUserResponse(JsonBase::<LoggedUser>);

#[utoipa::path(get, path = "/security_log/user", responses(LoggedUserResponse, Error))]
#[allow(clippy::unused_async)]
async fn user(user: LoggedUser) -> WarpResult<LoggedUserResponse> {
    Ok(JsonBase::new(user).into())
}

#[derive(Serialize, Deserialize, ToSchema)]
struct LogMessageQuery {
    log_level: Option<LogLevel>,
    log_unit: Option<StackString>,
    min_date: Option<OffsetDateTime>,
    max_date: Option<OffsetDateTime>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Into, From)]
struct SystemdLogMessagesWrapper(SystemdLogMessages);

derive_utoipa_schema!(SystemdLogMessagesWrapper, _SystemdLogMessagesWrapper);

#[allow(dead_code)]
#[derive(ToSchema)]
// SystemdLogMessages")]
#[schema(as = SystemdLogMessages)]
struct _SystemdLogMessagesWrapper {
    // ID")]
    id: Uuid,
    // Log Level")]
    log_level: LogLevel,
    // Log Unit")]
    log_unit: Option<StackString>,
    // Log Message")]
    log_message: StackString,
    // Log Timestamp")]
    log_timestamp: OffsetDateTime,
    // Log Processed At Time")]
    processed_time: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
// PaginatedSystemdLogMessages")]
struct PaginatedSystemdLogMessages {
    pagination: Pagination,
    data: Vec<SystemdLogMessagesWrapper>,
}

#[derive(UtoipaResponse)]
#[response(description = "Log Messages")]
#[rustfmt::skip]
struct LogMessagesResponse(JsonBase::<PaginatedSystemdLogMessages>);

#[utoipa::path(
    get,
    path = "/security_log/log_messages",
    responses(LogMessagesResponse, Error)
)]
async fn get_log_messages(
    data: State<Arc<AppState>>,
    _: LoggedUser,
    query: Query<LogMessageQuery>,
) -> WarpResult<LogMessagesResponse> {
    let Query(query) = query;
    let min_date: Option<OffsetDateTime> = query.min_date;
    let max_date: Option<OffsetDateTime> = query.max_date;
    let log_level = query.log_level;
    let total = SystemdLogMessages::get_total(
        &data.pool,
        log_level,
        &query.log_unit,
        min_date.map(Into::into),
        max_date.map(Into::into),
    )
    .await?;
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
        &query.log_unit,
        min_date.map(Into::into),
        max_date.map(Into::into),
        Some(offset),
        Some(limit),
    )
    .await?
    .map_ok(Into::into)
    .try_collect()
    .await?;
    Ok(JsonBase::new(PaginatedSystemdLogMessages { pagination, data }).into())
}

#[derive(UtoipaResponse)]
#[response(description = "Delete Log Messages", status = "NO_CONTENT")]
#[rustfmt::skip]
struct DeleteLogMessageResponse(HtmlBase::<StackString>);

#[utoipa::path(
    delete,
    path = "/security_log/log_messages/{id}",
    responses(DeleteLogMessageResponse, Error)
)]
async fn delete_log_message(
    data: State<Arc<AppState>>,
    _: LoggedUser,
    id: Path<i32>,
) -> WarpResult<DeleteLogMessageResponse> {
    let Path(id) = id;
    let bytes = SystemdLogMessages::delete(&data.pool, id).await?;
    Ok(HtmlBase::new(format_sstr!("deleted {id}, {bytes} modified")).into())
}

fn get_path(app: &AppState) -> OpenApiRouter {
    let app = Arc::new(app.clone());

    OpenApiRouter::new()
        .routes(routes!(intrusion_attempts))
        .routes(routes!(map_script))
        .routes(routes!(intrusion_attempts_all))
        .routes(routes!(intursion_log_get))
        .routes(routes!(intrusion_log_post))
        .routes(routes!(host_country_get))
        .routes(routes!(host_country_post))
        .routes(routes!(host_country_cleanup))
        .routes(routes!(user))
        .routes(routes!(get_log_messages))
        .routes(routes!(delete_log_message))
        .with_state(app)
}

async fn start_app() -> Result<(), AnyhowError> {
    let config = Config::init_config()?;
    let port: u32 = var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4086);

    run_app(config, port).await
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Visualizations of Security Log Data",
        description = "Some maps showing the origins of breakin attempts to my servers",
    ),
    components(schemas(
        LoggedUser,
        HostCountryWrapper,
        Pagination,
        IntrusionLogWrapper,
        SystemdLogMessagesWrapper
    ))
)]
struct ApiDoc;

async fn run_app(config: Config, port: u32) -> Result<(), AnyhowError> {
    async fn update_db(pool: PgPool) {
        let mut i = interval(Duration::from_secs(60));
        loop {
            fill_from_db(&pool).await.unwrap_or(());
            i.tick().await;
        }
    }
    get_secrets(&config.secret_path, &config.jwt_secret_path).await?;

    let pool = PgPool::new(&config.database_url)?;

    spawn(update_db(pool.clone()));

    let app = AppState { pool, config };

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(["content-type".try_into()?, "jwt".try_into()?])
        .allow_origin(Any);

    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(get_path(&app))
        .split_for_parts();

    let spec_json = serde_json::to_string_pretty(&api)?;
    let spec_yaml = serde_yml::to_string(&api)?;

    let router = router
        .route(
            "/security_log/openapi/json",
            axum::routing::get(|| async move {
                (
                    StatusCode::OK,
                    [("content-type", "application/json")],
                    spec_json,
                )
            }),
        )
        .route(
            "/security_log/openapi/yaml",
            axum::routing::get(|| async move {
                (StatusCode::OK, [("content-type", "text/yaml")], spec_yaml)
            }),
        )
        .layer(cors);

    let addr: SocketAddr = format_sstr!("0.0.0.0:{port}").parse()?;
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, router.into_make_service()).await?;

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
    use stack_string::format_sstr;

    use security_log_analysis_rust::{Host, Service};

    use crate::{run_app, AttemptsQuery, Config};

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

    #[tokio::test]
    async fn test_run_app() -> Result<(), Error> {
        let config = Config::init_config()?;
        let test_port = 12345;
        tokio::task::spawn({
            let config = config.clone();
            async move {
                env_logger::init();
                run_app(config, test_port).await.unwrap()
            }
        });
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        let client = reqwest::Client::new();

        let url = format_sstr!("http://localhost:{test_port}/security_log/openapi/yaml");

        let spec_yaml = client
            .get(url.as_str())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tokio::fs::write("./scripts/openapi.yaml", &spec_yaml).await?;
        Ok(())
    }
}
