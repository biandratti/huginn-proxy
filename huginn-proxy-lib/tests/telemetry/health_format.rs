use http_body_util::BodyExt;
use huginn_proxy_lib::config::HealthFormat;
use huginn_proxy_lib::telemetry::router::dispatch;
use huginn_proxy_lib::telemetry::{
    health_check_response, live_check_response, ready_check_response,
};
use huginn_proxy_lib::Readiness;
use hyper::header::CONTENT_TYPE;
use prometheus::Registry;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const HEALTHY: &[&str] = &["ALIVE", "HEALTHY", "SERVING"];
const UNHEALTHY: &[&str] = &["STARTING", "DRAINING", "PINS_MISSING", "NOT_FOUND", "ERROR"];

struct Case<'a> {
    path: &'a str,
    format: HealthFormat,
    readiness: &'a Readiness,
    expected: &'a [u8],
    status: u16,
    content_type: &'a str,
}

#[test]
fn healthy_tokens_are_ascii_upper_and_not_substrings_of_unhealthy() {
    for healthy in HEALTHY {
        assert!(
            healthy.chars().all(|c| c.is_ascii_uppercase()),
            "healthy token {healthy:?} must be [A-Z]+ so a body match cannot confuse it with another token"
        );
        for unhealthy in UNHEALTHY {
            assert!(
                !unhealthy.contains(healthy),
                "unhealthy {unhealthy:?} contains healthy {healthy:?}"
            );
            assert!(
                !healthy.contains(unhealthy),
                "healthy {healthy:?} contains unhealthy {unhealthy:?}"
            );
        }
    }
}

async fn assert_case(registry: &Registry, case: Case<'_>) -> TestResult {
    let resp = dispatch(case.path, registry, case.readiness, case.format);
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
    let starting = Readiness::new();
    let ready = Readiness::new();
    ready.mark_ready();
    let draining = Readiness::new();
    draining.mark_ready();
    draining.mark_draining();

    let json = "application/json";
    let text = "text/plain; charset=utf-8";

    for case in [
        Case {
            path: "/live",
            format: HealthFormat::Json,
            readiness: &ready,
            expected: br#"{"status":"alive"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/live",
            format: HealthFormat::Text,
            readiness: &ready,
            expected: b"ALIVE",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/health",
            format: HealthFormat::Json,
            readiness: &ready,
            expected: br#"{"status":"healthy"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/health",
            format: HealthFormat::Text,
            readiness: &ready,
            expected: b"HEALTHY",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Json,
            readiness: &ready,
            expected: br#"{"status":"serving"}"#,
            status: 200,
            content_type: json,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Text,
            readiness: &ready,
            expected: b"SERVING",
            status: 200,
            content_type: text,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Json,
            readiness: &starting,
            expected: br#"{"status":"not_ready","reason":"proxy_starting"}"#,
            status: 503,
            content_type: json,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Text,
            readiness: &starting,
            expected: b"STARTING",
            status: 503,
            content_type: text,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Json,
            readiness: &draining,
            expected: br#"{"status":"not_ready","reason":"proxy_draining"}"#,
            status: 503,
            content_type: json,
        },
        Case {
            path: "/ready",
            format: HealthFormat::Text,
            readiness: &draining,
            expected: b"DRAINING",
            status: 503,
            content_type: text,
        },
        Case {
            path: "/nope",
            format: HealthFormat::Json,
            readiness: &ready,
            expected: br#"{"status":"not_found"}"#,
            status: 404,
            content_type: json,
        },
        Case {
            path: "/nope",
            format: HealthFormat::Text,
            readiness: &ready,
            expected: b"NOT_FOUND",
            status: 404,
            content_type: text,
        },
    ] {
        assert_case(&registry, case).await?;
    }

    let live_text = live_check_response(HealthFormat::Text);
    let health_text = health_check_response(HealthFormat::Text);
    let ready_text = ready_check_response(None, HealthFormat::Text);
    assert_eq!(live_text.into_body().collect().await?.to_bytes().as_ref(), b"ALIVE");
    assert_eq!(health_text.into_body().collect().await?.to_bytes().as_ref(), b"HEALTHY");
    assert_eq!(ready_text.into_body().collect().await?.to_bytes().as_ref(), b"SERVING");
    Ok(())
}
