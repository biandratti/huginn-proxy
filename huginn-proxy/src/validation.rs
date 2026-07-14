use std::io::{self, Write};
use std::path::Path;

use huginn_proxy_lib::config::{load_from_path, EffectiveConfigView};
use huginn_proxy_lib::telemetry::{init_validation_tracing, shutdown_tracing};

use crate::BoxError;

pub(crate) fn run(config_path: &Path, print_effective_config: bool) -> Result<(), BoxError> {
    init_validation_tracing()?;
    let result = validate_and_write(config_path, print_effective_config);
    shutdown_tracing();
    result
}

fn validate_and_write(config_path: &Path, print_effective_config: bool) -> Result<(), BoxError> {
    let config = load_from_path(config_path)?;
    config.validate_cross_refs()?;

    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    if print_effective_config {
        let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
        writeln!(
            stdout,
            "{}",
            EffectiveConfigView::new(&static_cfg, &dynamic_cfg).to_pretty_json()?
        )?;
    } else {
        writeln!(stdout, "Config OK: {}", config_path.display())?;
    }
    Ok(())
}
