use anyhow::{format_err, Error};
use deadpool::managed::Object;
use deadpool_postgres::{ClientWrapper, Config, Pool};
use std::env::set_var;
use std::fmt;
use std::sync::Arc;
use tokio_postgres::error::Error as PgError;
use tokio_postgres::{Config as PgConfig, NoTls};

/// Wrapper around `r2d2::Pool`
/// The only way to use `PgPoolPg` is through the get method, which returns a `PooledConnection` object
#[derive(Clone, Default)]
pub struct PgPoolPg {
    pgurl: Arc<String>,
    pool: Option<Pool>,
}

impl fmt::Debug for PgPoolPg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PgPoolPg {}", self.pgurl)
    }
}

impl PgPoolPg {
    pub fn new(pgurl: &str) -> Self {
        let pgconf: PgConfig = pgurl.parse().expect("Failed to parse Url");

        if let tokio_postgres::config::Host::Tcp(s) = &pgconf.get_hosts()[0] {
            set_var("PG_HOST", s);
        }
        pgconf.get_user().map(|u| set_var("PG_USER", u));
        pgconf
            .get_password()
            .map(|u| set_var("PG_PASSWORD", String::from_utf8_lossy(u).to_string()));
        pgconf.get_dbname().map(|u| set_var("PG_DBNAME", u));

        let config = Config::from_env("PG").expect("Failed to create config");
        Self {
            pgurl: Arc::new(pgurl.to_string()),
            pool: Some(
                config
                    .create_pool(NoTls)
                    .expect(&format!("Failed to create pool {}", pgurl)),
            ),
        }
    }

    pub async fn get(&self) -> Result<Object<ClientWrapper, PgError>, Error> {
        self.pool
            .as_ref()
            .ok_or_else(|| format_err!("No Pool Exists"))?
            .get()
            .await
            .map_err(Into::into)
    }
}
