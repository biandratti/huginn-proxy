use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::BodyExt;
use huginn_ebpf_agent::config::HealthFormat;
use huginn_ebpf_agent::healthchecks::REQUIRED_PINS;
use huginn_ebpf_agent::telemetry::router::dispatch;
use hyper::header::CONTENT_TYPE;
use prometheus::Registry;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

struct Case<'a> {
    path: &'a str,
    format: HealthFormat,
    pin_path: &'a str,
    expected: &'a [u8],
    status: u16,
    content_type: &'a str,
}

fn unique_dir() -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("huginn-agent-health-{nanos}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_required_pins(
    dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for name in REQUIRED_PINS {
        fs::write(dir.join(name), [])?;
    }
    Ok(())
}

async fn assert_case(registry: &Registry, case: Case<'_>) -> TestResult {
    let resp = dispatch(case.path, registry, case.pin_path, case.format);
    assert_eq!(resp.status().as_u16(), case.status, "{} {:?}", case.path, case.format);
    let got_ct = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(got_ct, case.content_type, "{} {:?} content-type", case.path, case.format);
    let bytes = resp.into_body().collect().await?.to_bytes();
    assert_eq!(bytes.as_ref(), case.expected, "{} {:?}", case.path, case.format);
    Ok(())
}

#[tokio::test]
async fn golden_bytes_json_and_text() -> TestResult {
    let registry = Registry::new();
    let pin_dir = unique_dir()?;
    write_required_pins(&pin_dir)?;
    let serving = pin_dir.display().to_string();
    let missing = pin_dir.join("missing").display().to_string();

    let json = "application/json";
    let text = "text/plain; charset=utf-8";

    for case in [
        Case {
            path: "/live",
            format: HealthFormat::Json,
            pin_path: &serving,
            expected: br#"{"status":"alive"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/live",
            format: HealthFormat::Text,
            pin_path: &serving,
            expected: b"ALIVE",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/health",
            format: HealthFormat::Json,
            pin_path: &serving,
            expected: br#"{"status":"healthy"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/health",
            format: HealthFormat::Text,
            pin_path: &serving,
            expected: b"HEALTHY",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Json,
            pin_path: &serving,
            expected: br#"{"status":"serving"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Text,
            pin_path: &serving,
            expected: b"SERVING",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Json,
            pin_path: &missing,
            expected: br#"{"status":"not_ready","reason":"pins_not_ready"}"#,
            status: 503,
            content_type: json,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Text,
            pin_path: &missing,
            expected: b"PINS_MISSING",
            status: 503,
            content_type: text,
        },
        Case {
            path: "/nope",
            format: HealthFormat::Json,
            pin_path: &serving,
            expected: br#"{"status":"not_found"}"#,
            status: 404,
            content_type: json,
        },
        Case {
            path: "/nope",
            format: HealthFormat::Text,
            pin_path: &serving,
            expected: b"NOT_FOUND",
            status: 404,
            content_type: text,
        },
    ] {
        assert_case(&registry, case).await?;
    }

    let _ = fs::remove_dir_all(&pin_dir);
    Ok(())
}
