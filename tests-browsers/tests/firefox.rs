//! Firefox browser integration tests for fingerprinting
//!
//! These tests verify that real Firefox browsers can connect through the proxy
//! and that their TLS and HTTP/2 fingerprints are correctly captured and exposed.
//!
//! ## Requirements
//! - Firefox browser installed (must match FIREFOX_FINGERPRINTS.version in lib.rs)
//! - geckodriver installed and running on port 4444
//! - Docker Compose services running (proxy on https://localhost:7000)
//!
//! ## Running Locally
//!
//! ### Option 1: Docker Compose Already Running
//! ```bash
//! # Terminal 1: Start geckodriver (if not already running)
//! geckodriver --port 4444
//!
//! # Terminal 2: Run tests
//! cargo test --package tests-browsers \
//!   --test firefox \
//!   -- --nocapture --test-threads=1
//! ```
//!
//! ### Option 2: Manual Setup
//! ```bash
//! # Terminal 1: Start Docker Compose
//! cd examples
//! docker compose up -d
//!
//! # Terminal 2: Start geckodriver
//! geckodriver --port 4444
//!
//! # Terminal 3: Run tests
//! cargo test --package tests-browsers \
//!   --test firefox \
//!   -- --nocapture --test-threads=1
//! ```
//!
//! ### Installing geckodriver
//! ```bash
//! # Linux (using wget)
//! GECKODRIVER_VERSION=$(curl -s https://api.github.com/repos/mozilla/geckodriver/releases/latest | jq -r '.tag_name')
//! wget https://github.com/mozilla/geckodriver/releases/download/${GECKODRIVER_VERSION}/geckodriver-${GECKODRIVER_VERSION}-linux64.tar.gz
//! tar -xzf geckodriver-${GECKODRIVER_VERSION}-linux64.tar.gz
//! sudo mv geckodriver /usr/local/bin/
//! geckodriver --version
//!
//! # macOS (using Homebrew)
//! brew install geckodriver
//!
//! # Or download manually from: https://github.com/mozilla/geckodriver/releases
//! ```

use serial_test::serial;
use tests_browsers::{
    get_chrome_json, get_firefox_json, get_http2_fingerprint, parse_response,
    verify_fingerprint_headers, verify_firefox_version, FIREFOX_FINGERPRINTS, HEADER_HTTP2_AKAMAI,
    HEADER_TCP_SYN, HEADER_TLS_JA4, HEADER_TLS_JA4_RAW, PROXY_URL,
};
use thirtyfour::prelude::*;

const GECKODRIVER_URL: &str = "http://localhost:4444";

#[tokio::test]
#[serial]
async fn test_firefox_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::firefox();
    caps.add_arg("--headless")?;
    caps.accept_insecure_certs(true)?;

    let driver = WebDriver::new(GECKODRIVER_URL, caps).await?;

    let result = async {
        verify_firefox_version(&driver).await?;
        let url = format!("{}/anything", PROXY_URL);
        driver.goto(&url).await?;

        let content = get_firefox_json(&driver).await?;
        let headers = parse_response(&content)?;

        let http2_fp = headers
            .get(HEADER_HTTP2_AKAMAI)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header", HEADER_HTTP2_AKAMAI))?;

        assert!(
            !http2_fp.is_empty(),
            "HTTP/2 fingerprint should not be empty. Got: {}",
            http2_fp
        );

        let ja4_fp = headers
            .get(HEADER_TLS_JA4)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header", HEADER_TLS_JA4))?;

        let ja4_fp_raw = headers
            .get(HEADER_TLS_JA4_RAW)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header", HEADER_TLS_JA4_RAW))?;

        // TCP SYN fingerprint — present on the first navigation (new TCP connection)
        let tcp_syn_fp = headers
            .get(HEADER_TCP_SYN)
            .and_then(|v| v.as_str())
            .ok_or(format!("Missing {} header on first Firefox navigation", HEADER_TCP_SYN))?;
        assert!(!tcp_syn_fp.is_empty(), "TCP SYN fingerprint should not be empty");
        assert!(tcp_syn_fp.starts_with("4:"), "TCP SYN fingerprint should start with '4:' (IPv4)");

        println!("Firefox fingerprints:");
        println!("  TLS JA4: {}", ja4_fp);
        println!("  TLS JA4 Raw: {}", ja4_fp_raw);
        println!("  HTTP/2: {}", http2_fp);
        println!("  TCP SYN: {}", tcp_syn_fp);

        assert!(!ja4_fp_raw.is_empty(), "JA4 raw fingerprint should not be empty");

        assert_eq!(
            ja4_fp, FIREFOX_FINGERPRINTS.tls_ja4,
            "JA4 fingerprint mismatch. Expected Firefox {} fingerprint: {}. Got: {}. Update FIREFOX_FINGERPRINTS in lib.rs if Firefox version changed.",
            FIREFOX_FINGERPRINTS.version, FIREFOX_FINGERPRINTS.tls_ja4, ja4_fp
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let _ = driver.quit().await;
    result
}

#[tokio::test]
#[serial]
async fn test_firefox_multiple_requests() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::firefox();
    caps.add_arg("--headless")?;
    caps.accept_insecure_certs(true)?;

    let driver = WebDriver::new(GECKODRIVER_URL, caps).await?;

    let result = async {
        for i in 1..=3 {
            let url = format!("{}/anything?request={}", PROXY_URL, i);
            driver.goto(&url).await?;

            let content = get_firefox_json(&driver).await?;
            let headers = parse_response(&content)?;
            verify_fingerprint_headers(&headers)?;
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    let _ = driver.quit().await;
    result
}

#[tokio::test]
#[serial]
async fn test_firefox_vs_chrome_different_fingerprints() -> Result<(), Box<dyn std::error::Error>> {
    let mut firefox_caps = DesiredCapabilities::firefox();
    firefox_caps.add_arg("--headless")?;
    firefox_caps.accept_insecure_certs(true)?;

    let firefox_driver = WebDriver::new(GECKODRIVER_URL, firefox_caps).await?;

    let firefox_result = async {
        let firefox_url = format!("{}/anything", PROXY_URL);
        firefox_driver.goto(&firefox_url).await?;

        let firefox_content = get_firefox_json(&firefox_driver).await?;
        let firefox_headers = parse_response(&firefox_content)?;
        let firefox_http2 = get_http2_fingerprint(&firefox_headers).unwrap_or("");
        Ok::<String, Box<dyn std::error::Error>>(firefox_http2.to_string())
    }
    .await;

    let _ = firefox_driver.quit().await;
    let firefox_http2 = firefox_result?;

    let chrome_driver_result = async {
        let mut chrome_caps = DesiredCapabilities::chrome();
        chrome_caps.add_arg("--ignore-certificate-errors")?;
        chrome_caps.add_arg("--headless=new")?;
        WebDriver::new("http://localhost:9515", chrome_caps).await
    }
    .await;

    let chrome_driver = match chrome_driver_result {
        Ok(driver) => driver,
        Err(e) => {
            eprintln!("Chrome/chromedriver not available: {}. Skipping comparison test.", e);
            eprintln!("This test requires both browsers. In CI, run both chrome and firefox jobs.");
            return Ok(());
        }
    };

    let chrome_result = async {
        let chrome_url = format!("{}/anything", PROXY_URL);
        chrome_driver.goto(&chrome_url).await?;

        let chrome_content = get_chrome_json(&chrome_driver).await?;
        let chrome_headers = parse_response(&chrome_content)?;
        let chrome_http2 = get_http2_fingerprint(&chrome_headers).unwrap_or("");
        Ok::<String, Box<dyn std::error::Error>>(chrome_http2.to_string())
    }
    .await;

    let _ = chrome_driver.quit().await;
    let chrome_http2 = chrome_result?;

    assert_ne!(
        firefox_http2, chrome_http2,
        "Firefox and Chrome should have different HTTP/2 fingerprints. Firefox: {}, Chrome: {}",
        firefox_http2, chrome_http2
    );

    Ok(())
}
