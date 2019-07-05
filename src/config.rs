use failure::{err_msg, Error};
use std::env::var;
use std::path::Path;

#[derive(Default, Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub username: String,
}

impl Config {
    pub fn new() -> Config {
        Default::default()
    }

    pub fn init_config() -> Result<Config, Error> {
        let fname = "config.env";

        let home_dir = var("HOME").map_err(|e| err_msg(format!("No HOME directory {}", e)))?;

        let default_fname = format!("{}/.config/security_log_analysis_rust/config.env", home_dir);

        let env_file = if Path::new(fname).exists() {
            fname.to_string()
        } else {
            default_fname
        };

        dotenv::dotenv().ok();

        if Path::new(&env_file).exists() {
            dotenv::from_path(&env_file).ok();
        } else if Path::new("config.env").exists() {
            dotenv::from_filename("config.env").ok();
        }

        let conf = Config {
            database_url: var("DATABASE_URL")
                .map_err(|e| err_msg(format!("DATABASE_URL must be set {}", e)))?,
            username: var("USER").map_err(|e| err_msg(format!("USER must be set {}", e)))?,
        };

        Ok(conf)
    }
}
