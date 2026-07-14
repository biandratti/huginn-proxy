use huginn_proxy_lib::config::Secret;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn serialize_masks_value() -> TestResult {
    let secret = Secret::new("super-secret".to_string());
    let json = serde_json::to_string(&secret)?;
    assert_eq!(json, r#""<redacted>""#);
    assert!(!json.contains("super-secret"));
    Ok(())
}

#[test]
fn deserialize_is_transparent() -> TestResult {
    let secret: Secret<String> = serde_json::from_str(r#""hello""#)?;
    assert_eq!(secret.expose(), "hello");
    Ok(())
}

#[test]
fn debug_is_transparent_for_internal_fingerprint() {
    let secret = Secret::new("visible-in-debug".to_string());
    assert!(format!("{secret:?}").contains("visible-in-debug"));
}

#[test]
fn equality_compares_inner_value() {
    assert_eq!(Secret::new(1), Secret::new(1));
    assert_ne!(Secret::new(1), Secret::new(2));
}
