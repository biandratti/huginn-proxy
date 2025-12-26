#![forbid(unsafe_code)]

use std::env;
use std::sync::Arc;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::run;
use tracing::info;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = env::args();
    let _bin = args.next();
    let config_path = args.next().ok_or("usage: huginn-proxy <config-path>")?;

    let config = Arc::new(load_from_path(&config_path)?);

    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()))
        .with_target(false)
        .init();

    info!("huginn-proxy starting");
    run(config).await?;
    Ok(())
}
