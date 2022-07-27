use anyhow::{format_err, Error};
use serde::Deserialize;
use stack_string::StackString;
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{models::LogLevel, Host};

#[derive(Default, Debug, Deserialize)]
pub struct ConfigInner {
    pub database_url: StackString,
    #[serde(default = "default_username")]
    pub username: StackString,
    pub export_dir: Option<PathBuf>,
    pub server: Host,
    #[serde(default = "default_bucket")]
    pub s3_bucket: StackString,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_secret_path")]
    pub secret_path: PathBuf,
    #[serde(default = "default_secret_path")]
    pub jwt_secret_path: PathBuf,
    #[serde(default = "default_alert_log_level")]
    pub alert_log_level: LogLevel,
    pub sending_email_address: Option<StackString>,
    pub alert_email_address: Option<StackString>,
    #[serde(default = "default_system_log_filters")]
    pub systemd_log_filters: Vec<StackString>,
    pub alert_log_delay: Option<usize>,
    pub alert_buffer_size: Option<usize>,
}

fn default_system_log_filters() -> Vec<StackString> {
    vec![
        "kex_exchange_identification".into(),
        "error: maximum authentication attempts exceeded for invalid user".into(),
        "Disconnected from invalid user".into(),
        "Failed password for invalid user".into(),
    ]
}
fn default_username() -> StackString {
    std::env::var("USER").expect("USER must be set").into()
}
fn default_bucket() -> StackString {
    "security-log-analysis-backup".into()
}
fn default_home_dir() -> PathBuf {
    dirs::home_dir().expect("No home directory")
}
fn default_cache_dir() -> PathBuf {
    default_home_dir().join(".security-log-cache")
}
fn default_secret_path() -> PathBuf {
    dirs::config_dir()
        .unwrap()
        .join("aws_app_rust")
        .join("secret.bin")
}
fn default_alert_log_level() -> LogLevel {
    LogLevel::Error
}

#[derive(Default, Debug, Clone)]
pub struct Config(Arc<ConfigInner>);

impl Config {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Errors
    /// Return error if initialization fails
    pub fn init_config() -> Result<Self, Error> {
        let fname = Path::new("config.env");
        let config_dir = dirs::config_dir().ok_or_else(|| format_err!("No Config directory"))?;
        let default_fname = config_dir
            .join("security_log_analysis_rust")
            .join("config.env");

        let env_file = if fname.exists() {
            fname
        } else {
            &default_fname
        };

        dotenv::dotenv().ok();

        if env_file.exists() {
            dotenv::from_path(env_file).ok();
        }

        let conf: ConfigInner = envy::from_env()?;

        Ok(Self(Arc::new(conf)))
    }
}

impl Deref for Config {
    type Target = ConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use anyhow::Error;
    use std::env::set_var;

    #[test]
    fn test_config_systemd_log_filters() -> Result<(), Error> {
        set_var(
            "SYSTEMD_LOG_FILTERS",
            "kex_exchange_identification,error: maximum authentication attempts exceeded for \
             invalid user,Disconnected from invalid user,Failed password for invalid \
             user,SSL_read() failed (SSL: error:0A000126:SSL routines::unexpected eof while \
             reading) while keepalive",
        );
        let config = Config::init_config()?;
        assert_eq!(config.systemd_log_filters.len(), 5);
        assert_eq!(
            &config.systemd_log_filters[0],
            "kex_exchange_identification"
        );
        assert_eq!(
            &config.systemd_log_filters[1],
            "error: maximum authentication attempts exceeded for invalid user"
        );
        assert_eq!(
            &config.systemd_log_filters[2],
            "Disconnected from invalid user"
        );
        assert_eq!(
            &config.systemd_log_filters[3],
            "Failed password for invalid user"
        );
        assert_eq!(
            &config.systemd_log_filters[4],
            "SSL_read() failed (SSL: error:0A000126:SSL routines::unexpected eof while reading) \
             while keepalive"
        );
        Ok(())
    }
}
