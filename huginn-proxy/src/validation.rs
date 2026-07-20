use std::io::{self, Write};
use std::path::Path;

use huginn_proxy_lib::config::{
    all_warnings, load_from_path, proxy_protocol_trust_warnings, EffectiveConfigView,
};
use huginn_proxy_lib::telemetry::{init_validation_tracing, shutdown_tracing};

use crate::BoxError;

pub(crate) fn run(
    config_path: &Path,
    print_effective_config: bool,
    strict: bool,
) -> Result<(), BoxError> {
    init_validation_tracing()?;
    let result = validate_and_report(config_path, print_effective_config, strict);
    shutdown_tracing();
    result
}

/// Validate the config and, with `print_effective_config`, print the effective (secret-redacted)
/// view. `load_from_path` already logged the config-audit findings; the `proxy_protocol` trust-gap
/// check has its own runtime logger that never fires under `--validate`, so it is logged here and
/// folded into the warning count. With `strict`, a non-zero count makes this return an error.
fn validate_and_report(
    config_path: &Path,
    print_effective_config: bool,
    strict: bool,
) -> Result<(), BoxError> {
    let config = load_from_path(config_path)?;
    config.validate_cross_refs()?;

    let mut warning_count = all_warnings(&config).len();
    for w in proxy_protocol_trust_warnings(&config) {
        tracing::warn!(scope = %w.scope, "{}", w.message);
        warning_count = warning_count.saturating_add(1);
    }

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
        if warning_count > 0 {
            writeln!(stdout, "{warning_count} warning(s) found (see log output above)")?;
        }
    }

    if strict && warning_count > 0 {
        return Err(
            format!("strict validation failed: {warning_count} config warning(s) found").into()
        );
    }

    Ok(())
}
