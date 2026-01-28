//! Chrome browser integration tests for fingerprinting
//!
//! These tests verify that real Chrome browsers can connect through the proxy
//! and that their TLS and HTTP/2 fingerprints are correctly captured and exposed.
//!
//! ## Requirements
//! - Chrome/Chromium browser installed (must match CHROME_FINGERPRINTS.version in lib.rs)
//! - chromedriver running on port 9515: `chromedriver --port=9515`
//! - huginn-proxy running on https://localhost:7000
//!
//!
//! ## Running
//! ```bash
//! # Terminal 1: Start chromedriver
//! chromedriver --port=9515
//!
//! # Terminal 2: Start huginn-proxy (via Docker Compose)
//! cd examples && docker compose up -d
//!
//! # Terminal 3: Run tests
//! cargo test --package tests-browsers --test chrome -- --nocapture --test-threads=1
//! ```

use tests_browsers::{
    get_chrome_json, parse_response, verify_chrome_version, verify_fingerprint_headers,
    CHROME_FINGERPRINTS, HEADER_HTTP2_AKAMAI, HEADER_TLS_JA4, PROXY_URL,
};
use thirtyfour::prelude::*;

const CHROMEDRIVER_URL: &str = "http://localhost:9515";

#[tokio::test]
async fn test_chrome_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::chrome();
    caps.add_arg("--ignore-certificate-errors")?;
    caps.add_arg("--headless=new")?;
    caps.add_arg("--no-sandbox")?;
    caps.add_arg("--disable-dev-shm-usage")?;

    let driver = WebDriver::new(CHROMEDRIVER_URL, caps).await.map_err(|e| {
        format!(
            "Chrome/chromedriver not available: {}. Start chromedriver: chromedriver --port=9515",
            e
        )
    })?;

    let result = async {
        verify_chrome_version(&driver).await?;
        let url = format!("{}/anything", PROXY_URL);
        driver.goto(&url).await?;

        let content = get_chrome_json(&driver).await?;
        let headers = parse_response(&content)?;

        let http2_fp = headers
            .get(HEADER_HTTP2_AKAMAI)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header", HEADER_HTTP2_AKAMAI))?;

        assert_eq!(
            http2_fp, CHROME_FINGERPRINTS.http2_akamai,
            "HTTP/2 fingerprint mismatch. Expected Chrome {} fingerprint: {}. Got: {}. Update CHROME_FINGERPRINTS in lib.rs if Chrome version changed.",
            CHROME_FINGERPRINTS.version, CHROME_FINGERPRINTS.http2_akamai, http2_fp
        );

        let ja4_fp = headers
            .get(HEADER_TLS_JA4)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header", HEADER_TLS_JA4))?;

        assert_eq!(
            ja4_fp, CHROME_FINGERPRINTS.tls_ja4,
            "JA4 fingerprint mismatch. Expected Chrome {} fingerprint: {}. Got: {}. Update CHROME_FINGERPRINTS in lib.rs if Chrome version changed.",
            CHROME_FINGERPRINTS.version, CHROME_FINGERPRINTS.tls_ja4, ja4_fp
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let _ = driver.quit().await;
    result
}

#[tokio::test]
async fn test_chrome_multiple_requests() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::chrome();
    caps.add_arg("--ignore-certificate-errors")?;
    caps.add_arg("--headless=new")?;

    let driver = WebDriver::new(CHROMEDRIVER_URL, caps).await.map_err(|e| {
        format!(
            "Chrome/chromedriver not available: {}. Start chromedriver: chromedriver --port=9515",
            e
        )
    })?;

    let result = async {
        for i in 1..=3 {
            let url = format!("{}/anything?request={}", PROXY_URL, i);
            driver.goto(&url).await?;

            let content = get_chrome_json(&driver).await?;
            let headers = parse_response(&content)?;
            verify_fingerprint_headers(&headers)?;
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let _ = driver.quit().await;
    result
}
