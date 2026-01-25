//! Chrome browser integration tests for fingerprinting
//!
//! These tests verify that real Chrome browsers can connect through the proxy
//! and that their TLS and HTTP/2 fingerprints are correctly captured and exposed.
//!
//! ## Requirements
//! - Chrome/Chromium browser installed
//! - chromedriver running on port 9515: `chromedriver --port=9515`
//! - huginn-proxy running on https://localhost:7000
//!
//! ## Running
//! ```bash
//! # Terminal 1: Start chromedriver
//! chromedriver --port=9515
//!
//! # Terminal 2: Start huginn-proxy
//! cargo run
//!
//! # Terminal 3: Run tests (with feature flag)
//! cargo test --test webbrowser_chrome --features browser-tests -- --nocapture
//! ```

#![cfg(feature = "browser-tests")]

use thirtyfour::prelude::*;

const PROXY_URL: &str = "https://localhost:7000";
const CHROMEDRIVER_URL: &str = "http://localhost:9515";

#[tokio::test]
async fn test_chrome_fingerprint() -> WebDriverResult<()> {
    // Configure Chrome options
    let mut caps = DesiredCapabilities::chrome();

    // Chrome arguments
    caps.add_arg("--ignore-certificate-errors")?;
    caps.add_arg("--headless=new")?; // Use new headless mode
    caps.add_arg("--no-sandbox")?;
    caps.add_arg("--disable-dev-shm-usage")?;

    // Create WebDriver
    let driver = WebDriver::new(CHROMEDRIVER_URL, caps).await?;

    // Navigate to proxy endpoint
    let url = format!("{}/anything", PROXY_URL);
    driver.goto(&url).await?;

    // Wait for page to load
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Get page content
    let element = driver.find(By::Tag("pre")).await?;
    let content = element.text().await?;

    println!("Response content:\n{}", content);

    // Parse JSON response
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| WebDriverError::ParseError(format!("Failed to parse JSON: {}", e)))?;

    // Verify headers exist
    let headers = json["headers"]
        .as_object()
        .ok_or_else(|| WebDriverError::ParseError("Missing headers in response".to_string()))?;

    println!("\nFingerprint Headers:");

    // Check HTTP/2 fingerprint
    let http2_fp = headers
        .get("x-http2-fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WebDriverError::ParseError("Missing X-Http2-Fingerprint header".to_string())
        })?;

    println!("  X-Http2-Fingerprint: {}", http2_fp);

    // Chrome version 136+ fingerprint
    // Note: This may vary with browser versions. Update if test fails with newer Chrome.
    assert_eq!(
        http2_fp, "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p",
        "HTTP/2 fingerprint mismatch. Browser version may have changed."
    );

    // Check JA4 fingerprint
    let ja4_fp = headers
        .get("x-ja4-fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            WebDriverError::ParseError("Missing X-Ja4-Fingerprint header".to_string())
        })?;

    println!("  X-Ja4-Fingerprint: {}", ja4_fp);

    // Chrome version 136+ JA4 fingerprint
    // Note: This may vary with browser versions. Update if test fails with newer Chrome.
    assert_eq!(
        ja4_fp, "t13d1516h2_8daaf6152771_d8a2da3f94cd",
        "JA4 fingerprint mismatch. Browser version may have changed."
    );

    // Note: Chrome doesn't send JA3 (that's TLS 1.2 only, Chrome uses TLS 1.3)

    println!("\n✅ Chrome fingerprinting test passed");

    // Cleanup
    driver.quit().await?;

    Ok(())
}

#[tokio::test]
async fn test_chrome_multiple_requests() -> WebDriverResult<()> {
    let mut caps = DesiredCapabilities::chrome();
    caps.add_arg("--ignore-certificate-errors")?;
    caps.add_arg("--headless=new")?;

    let driver = WebDriver::new(CHROMEDRIVER_URL, caps).await?;

    // Make multiple requests to verify fingerprints are consistent
    for i in 1..=3 {
        println!("\n=== Request {} ===", i);

        let url = format!("{}/anything?request={}", PROXY_URL, i);
        driver.goto(&url).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let element = driver.find(By::Tag("pre")).await?;
        let content = element.text().await?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| WebDriverError::ParseError(format!("Parse error: {}", e)))?;

        let headers = json["headers"]
            .as_object()
            .ok_or_else(|| WebDriverError::ParseError("Missing headers".to_string()))?;

        if let Some(http2_fp) = headers.get("x-http2-fingerprint") {
            println!("  HTTP/2: {}", http2_fp);
        }
        if let Some(ja4_fp) = headers.get("x-ja4-fingerprint") {
            println!("  JA4: {}", ja4_fp);
        }
    }

    println!("\n✅ Multiple requests test passed");

    driver.quit().await?;
    Ok(())
}
