use anyhow::Error;
use postgres::NoTls;
use r2d2::{Pool, PooledConnection};
use r2d2_postgres::PostgresConnectionManager;
use std::fmt;

#[derive(Clone)]
pub struct PgPoolPg {
    pgurl: String,
    pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl fmt::Debug for PgPoolPg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PgPoolPg {}", self.pgurl)
    }
}

impl PgPoolPg {
    pub fn new(pgurl: &str) -> PgPoolPg {
        let manager = PostgresConnectionManager::new(
            pgurl.parse().expect("Failed to open DB connection"),
            NoTls,
        );
        PgPoolPg {
            pgurl: pgurl.to_string(),
            pool: Pool::new(manager).expect("Failed to open DB connection"),
        }
    }

    pub fn get(&self) -> Result<PooledConnection<PostgresConnectionManager<NoTls>>, Error> {
        self.pool.get().map_err(Into::into)
    }
}
