//! Common utilities for browser integration tests

use serde_json::Value;
use thirtyfour::prelude::*;

pub const PROXY_URL: &str = "https://localhost:7000";
pub const HEADER_HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
pub const HEADER_TLS_JA4: &str = "x-huginn-net-ja4";

#[derive(Debug, Clone)]
pub struct BrowserFingerprints {
    pub version: &'static str,
    pub http2_akamai: &'static str,
    pub tls_ja4: &'static str,
}

pub const CHROME_FINGERPRINTS: BrowserFingerprints = BrowserFingerprints {
    version: "144",
    http2_akamai: "1:65536;2:0;4:6291456;6:262144|15663105|0|",
    tls_ja4: "t13d1516h2_8daaf6152771_d8a2da3f94cd",
};

pub const FIREFOX_FINGERPRINTS: BrowserFingerprints = BrowserFingerprints {
    version: "147.0",
    http2_akamai: "1:65536;2:0;4:131072;5:16384|12517377|0|",
    tls_ja4: "t13d1717h2_5b57614c22b0_3cbfd9057e0d",
};

/// Verify Chrome version matches expected version
pub async fn verify_chrome_version(driver: &WebDriver) -> Result<(), Box<dyn std::error::Error>> {
    let user_agent: String = driver
        .execute("return navigator.userAgent;", vec![])
        .await?
        .convert()?;

    if let Some(chrome_start) = user_agent.find("Chrome/") {
        let version_start = chrome_start
            .checked_add(7)
            .ok_or("User-Agent parsing: position overflow")?;
        if let Some(version_end) = user_agent[version_start..].find('.') {
            let end_pos = version_start
                .checked_add(version_end)
                .ok_or("User-Agent parsing: end position overflow")?;
            let version = &user_agent[version_start..end_pos];
            if version != CHROME_FINGERPRINTS.version {
                return Err(format!(
                    "Chrome version mismatch! Expected: {}, Got: {}. Browser fingerprints are version-specific. Install Chrome {} or update CHROME_FINGERPRINTS in lib.rs.",
                    CHROME_FINGERPRINTS.version, version, CHROME_FINGERPRINTS.version
                ).into());
            }
        }
    } else {
        return Err("Could not detect Chrome version from User-Agent".into());
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
        if let Some(version_end) = user_agent[version_start..].find(' ') {
            let end_pos = version_start
                .checked_add(version_end)
                .ok_or("User-Agent parsing: end position overflow")?;
            let version = &user_agent[version_start..end_pos];
            if version != FIREFOX_FINGERPRINTS.version {
                return Err(format!(
                    "Firefox version mismatch! Expected: {}, Got: {}. Browser fingerprints are version-specific. Install Firefox {} or update FIREFOX_FINGERPRINTS in lib.rs.",
                    FIREFOX_FINGERPRINTS.version, version, FIREFOX_FINGERPRINTS.version
                ).into());
            }
        }
    } else {
        return Err("Could not detect Firefox version from User-Agent".into());
    }

    Ok(())
}

pub async fn get_chrome_json(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
    let element = driver.find(By::Tag("pre")).await?;
    Ok(element.text().await?)
}

pub async fn get_firefox_json(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
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
        let start_pos = start
            .checked_add(tag_len)
            .ok_or("HTML parsing: position overflow")?;
        if let Some(end) = html[start_pos..].find("</script>") {
            let end_pos = start_pos
                .checked_add(end)
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
                if serde_json::from_str::<Value>(json_str).is_ok() {
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
                if serde_json::from_str::<Value>(json_str).is_ok() {
                    return Ok(json_str.to_string());
                }
            }
        }
    }

    if let Some(json_start) = html.find('{') {
        if let Some(json_end) = html.rfind('}') {
            let json_str = html[json_start..=json_end].trim();
            if serde_json::from_str::<Value>(json_str).is_ok() {
                return Ok(json_str.to_string());
            }
        }
    }

    Err("Could not extract valid JSON from Firefox viewer".into())
}

pub fn parse_response(
    content: &str,
) -> Result<serde_json::Map<String, Value>, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(content)
        .map_err(|e| format!("Failed to parse JSON: {}. Content: {}", e, content))?;

    json["headers"]
        .as_object()
        .cloned()
        .ok_or("Missing headers in response".into())
}

pub fn verify_fingerprint_headers(
    headers: &serde_json::Map<String, Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !headers.contains_key(HEADER_HTTP2_AKAMAI) {
        return Err(format!("Missing {} header", HEADER_HTTP2_AKAMAI).into());
    }
    if !headers.contains_key(HEADER_TLS_JA4) {
        return Err(format!("Missing {} header", HEADER_TLS_JA4).into());
    }
    Ok(())
}

pub fn get_http2_fingerprint(headers: &serde_json::Map<String, Value>) -> Option<&str> {
    headers.get(HEADER_HTTP2_AKAMAI)?.as_str()
}
