//! Firefox browser integration tests for fingerprinting
//!
//! These tests verify that real Firefox browsers can connect through the proxy
//! and that their TLS and HTTP/2 fingerprints are correctly captured and exposed.
//!
//! ## Requirements
//! - Firefox browser installed
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
//! cargo test --package tests-e2e \
//!   --test webbrowser_firefox \
//!   --features browser-tests \
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
//! cargo test --package tests-e2e \
//!   --test webbrowser_firefox \
//!   --features browser-tests \
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

#![cfg(feature = "browser-tests")]

#[cfg(feature = "browser-tests")]
use serial_test::serial;
use thirtyfour::prelude::*;

const PROXY_URL: &str = "https://localhost:7000";
const GECKODRIVER_URL: &str = "http://localhost:4444";

const HEADER_HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
const HEADER_TLS_JA4: &str = "x-huginn-net-ja4";

async fn get_json_content(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(raw_tab) = driver.find(By::Id("rawdata-tab")).await {
        let _ = raw_tab.click().await;
    }
    
    let script = r#"
        const script = document.getElementById('data');
        if (script && script.textContent) {
            return script.textContent.trim();
        }
        return null;
    "#;
    
    if let Ok(result) = driver.execute(script, vec![]).await {
        if let Ok(json_str) = result.convert::<String>() {
            if let Some(json) = json_str.strip_prefix("null") {
                if !json.trim().is_empty() {
                    return Ok(json.trim().to_string());
                }
            } else if !json_str.is_empty() && json_str != "null" {
                return Ok(json_str);
            }
        }
    }
    
    let html = driver.source().await?;
    if let Some(start) = html.find(r#"<script id="data" type="application/json">"#) {
        let tag_len = r#"<script id="data" type="application/json">"#.len();
        let start_pos = start.checked_add(tag_len)
            .ok_or("HTML parsing: position overflow")?;
        if let Some(end) = html[start_pos..].find("</script>") {
            let end_pos = start_pos.checked_add(end)
                .ok_or("HTML parsing: end position overflow")?;
            let json_str = html[start_pos..end_pos].trim();
            if !json_str.is_empty() {
                return Ok(json_str.to_string());
            }
        }
    }
    
    if let Ok(panel) = driver.find(By::Id("rawdata-panel")).await {
        let text = panel.text().await?;
        if let Some(json_start) = text.find('{') {
            if let Some(json_end) = text.rfind('}') {
                let json_str = &text[json_start..=json_end];
                if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
                    return Ok(json_str.to_string());
                }
            }
        }
    }
    
    if let Ok(element) = driver.find(By::Tag("pre")).await {
        let text = element.text().await?;
        if let Some(json_start) = text.find('{') {
            if let Some(json_end) = text.rfind('}') {
                let json_str = &text[json_start..=json_end];
                if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
                    return Ok(json_str.to_string());
                }
            }
        }
    }
    
    if let Some(json_start) = html.find('{') {
        if let Some(json_end) = html.rfind('}') {
            let json_str = html[json_start..=json_end].trim();
            if serde_json::from_str::<serde_json::Value>(json_str).is_ok() {
                return Ok(json_str.to_string());
            }
        }
    }
    
    Err("Could not extract valid JSON from Firefox viewer".into())
}

#[tokio::test]
#[serial]
async fn test_firefox_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let mut caps = DesiredCapabilities::firefox();
    caps.add_arg("--headless")?;
    caps.accept_insecure_certs(true)?;

    let driver = WebDriver::new(GECKODRIVER_URL, caps).await?;

    let result = async {
        let url = format!("{}/anything", PROXY_URL);
        driver.goto(&url).await?;
        
        let content = get_json_content(&driver).await?;
        let json: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| format!("Failed to parse JSON: {}. Content: {}", e, content))?;

        let headers = json["headers"]
            .as_object()
            .ok_or("Missing headers in response")?;

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

        assert_eq!(
            ja4_fp, "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
            "JA4 fingerprint mismatch. Browser version may have changed. Got: {}",
            ja4_fp
        );

        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;

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
            
            let content = get_json_content(&driver).await?;
            let json: serde_json::Value = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse JSON in request {}: {}. Content: {}", i, e, content))?;

            let headers = json["headers"].as_object().ok_or("Missing headers")?;
            assert!(headers.contains_key(HEADER_HTTP2_AKAMAI));
            assert!(headers.contains_key(HEADER_TLS_JA4));
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;

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
        
        let firefox_content = get_json_content(&firefox_driver).await?;
        let firefox_json: serde_json::Value = serde_json::from_str(&firefox_content)
            .map_err(|e| format!("Failed to parse Firefox JSON: {}. Content: {}", e, firefox_content))?;

        let firefox_http2 = firefox_json["headers"][HEADER_HTTP2_AKAMAI]
            .as_str()
            .unwrap_or("");
        Ok::<String, Box<dyn std::error::Error>>(firefox_http2.to_string())
    }.await;

    let _ = firefox_driver.quit().await;
    let firefox_http2 = firefox_result?;

    let chrome_driver_result = async {
        let mut chrome_caps = DesiredCapabilities::chrome();
        chrome_caps.add_arg("--ignore-certificate-errors")?;
        chrome_caps.add_arg("--headless=new")?;
        WebDriver::new("http://localhost:9515", chrome_caps).await
    }.await;

    let chrome_driver = chrome_driver_result.map_err(|e| {
        format!("Chrome/chromedriver not available: {}. This test requires both Firefox and Chrome to compare fingerprints. Start chromedriver: chromedriver --port=9515", e)
    })?;
    
    let chrome_result = async {
        let chrome_url = format!("{}/anything", PROXY_URL);
        chrome_driver.goto(&chrome_url).await?;
        
        let chrome_content = chrome_driver.source().await?;
        let chrome_json: serde_json::Value = serde_json::from_str(&chrome_content)
            .map_err(|e| format!("Failed to parse Chrome JSON: {}. Content: {}", e, chrome_content))?;

        let chrome_http2 = chrome_json["headers"][HEADER_HTTP2_AKAMAI]
            .as_str()
            .unwrap_or("");
        Ok::<String, Box<dyn std::error::Error>>(chrome_http2.to_string())
    }.await;

    let _ = chrome_driver.quit().await;
    let chrome_http2 = chrome_result?;

    assert_ne!(
        firefox_http2, chrome_http2,
        "Firefox and Chrome should have different HTTP/2 fingerprints. Firefox: {}, Chrome: {}",
        firefox_http2, chrome_http2
    );

    Ok(())
}
