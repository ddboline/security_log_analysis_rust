use anyhow::Error;

use security_log_analysis_rust::parse_opts::ParseOpts;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    tokio::spawn(async move { ParseOpts::process_args().await })
        .await
        .unwrap()
}
