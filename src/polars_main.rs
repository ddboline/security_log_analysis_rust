use anyhow::Error;

use security_log_analysis_rust::polars_analysis::AnalysisOpts;

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::init();
    AnalysisOpts::parse_opts().await
}
