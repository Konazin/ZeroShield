//! Logging setup for the daemon.

use tracing_subscriber::EnvFilter;

pub fn init(level: &str, json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        let _ = builder.json().try_init();
    } else {
        let _ = builder.try_init();
    }
}
