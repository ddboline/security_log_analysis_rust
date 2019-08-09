use security_log_analysis_rust::parse_opts::ParseOpts;

fn main() {
    env_logger::init();
    ParseOpts::process_args().unwrap();
}
