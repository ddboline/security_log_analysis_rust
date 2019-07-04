use security_log_analysis_rust::config::Config;
use security_log_analysis_rust::host_country_metadata::HostCountryMetadata;
use security_log_analysis_rust::parse_logs::{
    parse_all_log_files, parse_log_line_apache, parse_log_line_ssh,
};
use security_log_analysis_rust::pgpool::PgPool;

fn main() {
    let config = Config::init_config().unwrap();
    let pool = PgPool::new(&config.database_url);
    let hc = HostCountryMetadata::from_pool(&pool).unwrap();
    let mut results = parse_all_log_files(
        &hc,
        "ssh",
        "home.ddboline.net",
        &parse_log_line_ssh,
        "/var/log/auth.log",
    )
    .unwrap();
    results.extend(
        parse_all_log_files(
            &hc,
            "apache",
            "home.ddboline.net",
            &parse_log_line_apache,
            "/var/log/apache2/access.log",
        )
        .unwrap(),
    );
    println!("new lines {}", results.len());
    // hc.cleanup_intrusion_log().unwrap();
}
