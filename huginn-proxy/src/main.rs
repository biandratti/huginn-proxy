#![forbid(unsafe_code)]

use clap::Parser;
use huginn_proxy_lib::{config::load_from_path, tcp};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(author, version, about = "Huginn reverse proxy (fingerprinting-first)")]
struct Cli {
    /// Path to configuration TOML file
    #[arg(
        short,
        long,
        value_name = "FILE",
        default_value = "examples/config/basic.toml"
    )]
    config: PathBuf,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let cli = Cli::parse();
    match load_from_path(&cli.config) {
        Ok(cfg) => {
            info!(?cfg.listen, backends = cfg.backends.len(), "configuration loaded");
            let cfg = Arc::new(cfg);
            if let Err(err) = tcp::run(cfg.clone()).await {
                error!(%err, "tcp forwarder exited with error");
                std::process::exit(1);
            }
        }
        Err(err) => {
            error!(%err, "failed to load configuration");
            std::process::exit(1);
        }
    }
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}
