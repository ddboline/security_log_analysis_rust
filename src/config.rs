use anyhow::{format_err, Error};
use serde::Deserialize;
use stack_string::StackString;
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};
#[derive(Default, Debug, Deserialize)]
pub struct ConfigInner {
    pub database_url: StackString,
    #[serde(default = "default_username")]
    pub username: StackString,
    pub export_dir: Option<PathBuf>,
    pub server: StackString,
    #[serde(default = "default_bucket")]
    pub s3_bucket: StackString,
    #[serde(default = "default_cache_dir")]
    pub cache_dir: PathBuf,
    #[serde(default = "default_secret_path")]
    pub secret_path: PathBuf,
    #[serde(default = "default_secret_path")]
    pub jwt_secret_path: PathBuf,
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
