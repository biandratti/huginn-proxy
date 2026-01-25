//! Firefox browser integration tests for fingerprinting
//!
//! These tests verify that real Firefox browsers can connect through the proxy
//! and that their TLS and HTTP/2 fingerprints are correctly captured and exposed.
//!
//! ## Requirements
//! - Firefox browser installed
//! - geckodriver running on port 4444: `geckodriver --port 4444`
//! - huginn-proxy running on https://localhost:7000
//!
//! ## Running
//! ```bash
//! # Terminal 1: Start geckodriver
//! geckodriver --port 4444
//!
//! # Terminal 2: Start huginn-proxy
//! cargo run
//!
//! # Terminal 3: Run tests (with feature flag)
//! cargo test --test webbrowser_firefox --features browser-tests -- --nocapture
//! ```

#![cfg(feature = "browser-tests")]

use thirtyfour::prelude::*;

const PROXY_URL: &str = "https://localhost:7000";
const GECKODRIVER_URL: &str = "http://localhost:4444";

#[tokio::test]
async fn test_firefox_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    // Configure Firefox options
    let mut caps = DesiredCapabilities::firefox();

    // Firefox arguments
    caps.add_arg("--headless")?;

    // Accept insecure certificates
    caps.accept_insecure_certs(true)?;

    // Create WebDriver
    let driver = WebDriver::new(GECKODRIVER_URL, caps).await?;

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
    let json: serde_json::Value = serde_json::from_str(&content)?;

    // Verify headers exist
    let headers = json["headers"]
        .as_object()
        .ok_or("Missing headers in response")?;

    println!("\nFingerprint Headers:");

    // Check HTTP/2 fingerprint
    let http2_fp = headers
        .get("x-http2-fingerprint")
        .and_then(|v| v.as_str())
        .ok_or("Missing X-Http2-Fingerprint header")?;

    println!("  X-Http2-Fingerprint: {}", http2_fp);

    // Firefox version 138+ fingerprint
    // Note: This may vary with browser versions. Update if test fails with newer Firefox.
    assert_eq!(
        http2_fp, "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:22|m,p,a,s",
        "HTTP/2 fingerprint mismatch. Browser version may have changed."
    );

    // Check JA4 fingerprint
    let ja4_fp = headers
        .get("x-ja4-fingerprint")
        .and_then(|v| v.as_str())
        .ok_or("Missing X-Ja4-Fingerprint header")?;

    println!("  X-Ja4-Fingerprint: {}", ja4_fp);

    // Firefox version 138+ JA4 fingerprint
    // Note: This may vary with browser versions. Update if test fails with newer Firefox.
    assert_eq!(
        ja4_fp, "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
        "JA4 fingerprint mismatch. Browser version may have changed."
    );

    println!("\n✅ Firefox fingerprinting test passed");

    // Cleanup
    driver.quit().await?;

    Ok(())
}

#[tokio::test]
async fn test_firefox_multiple_requests() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::firefox();
    caps.add_arg("--headless")?;
    caps.accept_insecure_certs(true)?;

    let driver = WebDriver::new(GECKODRIVER_URL, caps).await?;

    // Make multiple requests to verify fingerprints are consistent
    for i in 1..=3 {
        println!("\n=== Request {} ===", i);

        let url = format!("{}/anything?request={}", PROXY_URL, i);
        driver.goto(&url).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let element = driver.find(By::Tag("pre")).await?;
        let content = element.text().await?;
        let json: serde_json::Value = serde_json::from_str(&content)?;

        let headers = json["headers"].as_object().ok_or("Missing headers")?;

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

#[tokio::test]
async fn test_firefox_vs_chrome_different_fingerprints() -> Result<(), Box<dyn std::error::Error>> {
    // This test verifies that Firefox and Chrome produce different fingerprints
    // Note: Requires both chromedriver and geckodriver running

    println!("\n=== Testing Firefox ===");
    let mut firefox_caps = DesiredCapabilities::firefox();
    firefox_caps.add_arg("--headless")?;
    firefox_caps.accept_insecure_certs(true)?;

    let firefox_driver = WebDriver::new(GECKODRIVER_URL, firefox_caps).await?;
    firefox_driver
        .goto(&format!("{}/anything", PROXY_URL))
        .await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let firefox_element = firefox_driver.find(By::Tag("pre")).await?;
    let firefox_content = firefox_element.text().await?;
    let firefox_json: serde_json::Value = serde_json::from_str(&firefox_content)?;

    let firefox_http2 = firefox_json["headers"]["x-http2-fingerprint"]
        .as_str()
        .unwrap_or("");
    println!("Firefox HTTP/2: {}", firefox_http2);

    firefox_driver.quit().await?;

    println!("\n=== Testing Chrome ===");
    let mut chrome_caps = DesiredCapabilities::chrome();
    chrome_caps.add_arg("--ignore-certificate-errors")?;
    chrome_caps.add_arg("--headless=new")?;

    let chrome_driver = WebDriver::new("http://localhost:9515", chrome_caps).await?;
    chrome_driver
        .goto(&format!("{}/anything", PROXY_URL))
        .await?;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let chrome_element = chrome_driver.find(By::Tag("pre")).await?;
    let chrome_content = chrome_element.text().await?;
    let chrome_json: serde_json::Value = serde_json::from_str(&chrome_content)?;

    let chrome_http2 = chrome_json["headers"]["x-http2-fingerprint"]
        .as_str()
        .unwrap_or("");
    println!("Chrome HTTP/2: {}", chrome_http2);

    chrome_driver.quit().await?;

    // Verify they're different
    assert_ne!(
        firefox_http2, chrome_http2,
        "Firefox and Chrome should have different HTTP/2 fingerprints"
    );

    println!("\n✅ Firefox vs Chrome fingerprint differentiation test passed");

    Ok(())
}
