use anyhow::{format_err, Error};
use std::{
    env::{var, var_os},
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Default, Debug)]
pub struct ConfigInner {
    pub database_url: String,
    pub username: String,
    pub export_dir: Option<PathBuf>,
}

#[derive(Default, Debug, Clone)]
pub struct Config(Arc<ConfigInner>);

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

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

        let conf = ConfigInner {
            database_url: var("DATABASE_URL")
                .map_err(|e| format_err!("DATABASE_URL must be set {}", e))?,
            username: var("USER").map_err(|e| format_err!("USER must be set {}", e))?,
            export_dir: var_os("EXPORT_DIR").map(|s| s.into()),
        };

        Ok(Self(Arc::new(conf)))
    }
}

impl Deref for Config {
    type Target = ConfigInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
