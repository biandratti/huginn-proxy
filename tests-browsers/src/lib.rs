//! Common utilities for browser integration tests

use std::collections::HashMap;
use thirtyfour::prelude::*;

pub const PROXY_URL: &str = "https://localhost:7000";
pub const HEADER_HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
pub const HEADER_TLS_JA4: &str = "x-huginn-net-ja4";
pub const HEADER_TLS_JA4_R: &str = "x-huginn-net-ja4_r";
pub const HEADER_TLS_JA4_O: &str = "x-huginn-net-ja4_o";
pub const HEADER_TLS_JA4_OR: &str = "x-huginn-net-ja4_or";
pub const HEADER_TCP_SYN: &str = "x-huginn-net-tcp";

#[derive(Debug, Clone)]
pub struct BrowserFingerprints {
    pub version: &'static str,
    pub http2_akamai: &'static str,
    pub tls_ja4: &'static str,
}

pub const CHROME_FINGERPRINTS: BrowserFingerprints = BrowserFingerprints {
    version: "latest",
    http2_akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    tls_ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
};

pub const FIREFOX_FINGERPRINTS: BrowserFingerprints = BrowserFingerprints {
    version: "147.0",
    http2_akamai: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
    tls_ja4: "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
};

// ── response parsing ──────────────────────────────────────────────────────────

/// Parse the plain-text body returned by traefik/whoami.
///
/// Whoami echoes the incoming request as:
/// ```text
/// Hostname: <name>
/// IP: …
/// RemoteAddr: …
/// GET /path HTTP/1.1
/// Host: …
/// Header-Name: value
/// ```
///
/// Returns a map of lowercase header name → value.
pub fn parse_backend_echo(
    text: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut headers = HashMap::new();
    let mut in_headers = false;

    for line in text.lines() {
        if !in_headers {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() == 3
                && matches!(
                    parts[0],
                    "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
                )
                && parts[2].starts_with("HTTP/")
            {
                in_headers = true;
            }
        } else if let Some((name, value)) = line.split_once(": ") {
            headers.insert(name.to_lowercase(), value.to_string());
        }
    }

    if in_headers {
        Ok(headers)
    } else {
        Err(
            format!("Failed to parse backend echo — no HTTP request line found. Content: {text}")
                .into(),
        )
    }
}

pub fn verify_fingerprint_headers(
    headers: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for key in [
        HEADER_HTTP2_AKAMAI,
        HEADER_TLS_JA4,
        HEADER_TLS_JA4_R,
        HEADER_TLS_JA4_O,
        HEADER_TLS_JA4_OR,
    ] {
        if !headers.contains_key(key) {
            return Err(format!("Missing {key} header").into());
        }
    }
    Ok(())
}

pub fn get_http2_fingerprint(headers: &HashMap<String, String>) -> Option<&str> {
    headers.get(HEADER_HTTP2_AKAMAI).map(|s| s.as_str())
}

// ── browser helpers ───────────────────────────────────────────────────────────

/// Verify Chrome version (informational — does not fail).
pub async fn verify_chrome_version(driver: &WebDriver) -> Result<(), Box<dyn std::error::Error>> {
    let user_agent: String = driver
        .execute("return navigator.userAgent;", vec![])
        .await?
        .convert()?;

    if let Some(chrome_start) = user_agent.find("Chrome/") {
        let version_start = chrome_start
            .checked_add(7)
            .ok_or("User-Agent parsing: position overflow")?;
        if let Some(version_end) = user_agent[version_start..].find(' ') {
            let end_pos = version_start
                .checked_add(version_end)
                .ok_or("User-Agent parsing: end position overflow")?;
            println!("Chrome version detected: {}", &user_agent[version_start..end_pos]);
        }
    }

    Ok(())
}

pub async fn verify_firefox_version(driver: &WebDriver) -> Result<(), Box<dyn std::error::Error>> {
    let user_agent: String = driver
        .execute("return navigator.userAgent;", vec![])
        .await?
        .convert()?;

    if let Some(firefox_start) = user_agent.find("Firefox/") {
        let version_start = firefox_start
            .checked_add(8)
            .ok_or("User-Agent parsing: position overflow")?;
        // Firefox UA ends at end-of-string, not a space
        let version = user_agent[version_start..].trim();
        if version != FIREFOX_FINGERPRINTS.version {
            return Err(format!(
                "Firefox version mismatch! Expected: {}, Got: {}. \
                 Browser fingerprints are version-specific. \
                 Install Firefox {} or update FIREFOX_FINGERPRINTS in lib.rs.",
                FIREFOX_FINGERPRINTS.version, version, FIREFOX_FINGERPRINTS.version
            )
            .into());
        }
    } else {
        return Err("Could not detect Firefox version from User-Agent".into());
    }

    Ok(())
}

/// Read the page body text from Chrome.
/// Chrome renders plain-text responses inside a `<pre>` element.
pub async fn get_chrome_json(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
    let element = driver.find(By::Tag("pre")).await?;
    Ok(element.text().await?)
}

/// Read the page body text from Firefox.
/// Firefox renders plain-text responses inside a `<pre>` element (same as Chrome).
/// Falls back to the full `<body>` text content if `<pre>` is absent or empty.
pub async fn get_firefox_json(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(element) = driver.find(By::Tag("pre")).await {
        let text = element.text().await?;
        if !text.is_empty() {
            return Ok(text);
        }
    }

    if let Ok(element) = driver.find(By::Tag("body")).await {
        let text = element.text().await?;
        if !text.is_empty() {
            return Ok(text);
        }
    }

    Err("Could not extract page text content from Firefox".into())
}
