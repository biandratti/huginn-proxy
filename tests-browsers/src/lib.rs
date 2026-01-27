//! Common utilities for browser integration tests

use serde_json::Value;
use thirtyfour::prelude::*;

pub const PROXY_URL: &str = "https://localhost:7000";
pub const HEADER_HTTP2_AKAMAI: &str = "x-huginn-net-akamai";
pub const HEADER_TLS_JA4: &str = "x-huginn-net-ja4";

/// Extract JSON content from Chrome's page (Chrome shows JSON in <pre> tag)
pub async fn get_chrome_json(driver: &WebDriver) -> Result<String, Box<dyn std::error::Error>> {
    let element = driver.find(By::Tag("pre")).await?;
    Ok(element.text().await?)
}

/// Extract JSON content from Firefox's JSON viewer
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

/// Parse JSON response and extract headers
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

/// Verify that headers contain fingerprint headers
///
/// Returns an error if either fingerprint header is missing.
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

/// Get HTTP/2 fingerprint from headers
pub fn get_http2_fingerprint(headers: &serde_json::Map<String, Value>) -> Option<&str> {
    headers.get(HEADER_HTTP2_AKAMAI)?.as_str()
}
