use std::io;
use std::sync::{Arc, Mutex};

use huginn_proxy_lib::telemetry::default_log_filter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{EnvFilter, Registry};

type Buffer = Arc<Mutex<Vec<u8>>>;

struct CaptureWriter(Buffer);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CaptureMakeWriter(Buffer);

impl<'a> MakeWriter<'a> for CaptureMakeWriter {
    type Writer = CaptureWriter;

    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(Arc::clone(&self.0))
    }
}

fn captured_logs(filter: &str, emit: impl FnOnce()) -> String {
    let buffer: Buffer = Arc::new(Mutex::new(Vec::new()));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(CaptureMakeWriter(Arc::clone(&buffer)));
    let subscriber = Registry::default()
        .with(EnvFilter::new(filter))
        .with(fmt_layer);

    tracing::subscriber::with_default(subscriber, emit);

    let logs = match buffer.lock() {
        Ok(guard) => String::from_utf8_lossy(&guard).into_owned(),
        Err(poisoned) => String::from_utf8_lossy(&poisoned.into_inner()).into_owned(),
    };
    logs
}

/// The whole point of the default filter: `huginn-net-tls` logs a JA4 parse `error` for
/// every non-TLS byte on the TLS port, and none of it should reach the operator's log.
/// Asserting on behavior rather than on the directive string catches a target name that
/// parses but never matches (`huginn-net-tls` with hyphens, say).
#[test]
fn default_filter_drops_huginn_net_tls_events() {
    let logs = captured_logs(&default_log_filter("info"), || {
        tracing::error!(target: "huginn_net_tls", "TLS plaintext parsing failed");
        tracing::info!(target: "huginn_proxy_lib::proxy", "listener bound");
    });

    assert!(
        !logs.contains("TLS plaintext parsing failed"),
        "huginn-net-tls noise leaked into the log: {logs}"
    );
    assert!(
        logs.contains("listener bound"),
        "proxy's own events must still be logged: {logs}"
    );
}

/// `RUST_LOG` unset must fall through to our default filter. If `try_from_default_env`
/// ever returned `Ok` for a missing variable, the `unwrap_or_else` below it would never
/// run and `QUIET_TARGETS` would silently stop being applied.
#[test]
fn unset_rust_log_falls_through_to_the_default_filter() {
    assert!(
        tracing_subscriber::EnvFilter::try_from_default_env().is_err(),
        "the default filter is only installed when try_from_default_env fails"
    );
}
