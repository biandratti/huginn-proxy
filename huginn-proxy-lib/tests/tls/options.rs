use huginn_proxy_lib::config::{TlsOptions, TlsVersion};
#[cfg(test)]
use huginn_proxy_lib::tls::acceptor::validate_tls_options;
use huginn_proxy_lib::tls::cipher_suites::supported_cipher_suites;
use huginn_proxy_lib::tls::curves::supported_curves;

#[test]
fn test_validate_tls_options_default() {
    let options = TlsOptions::default();
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_versions_only() {
    let options =
        TlsOptions { versions: vec![TlsVersion::V1_2, TlsVersion::V1_3], ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_min_max_version_valid() {
    let options = TlsOptions {
        versions: vec![], // Empty when using min/max
        min_version: Some(TlsVersion::V1_2),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_min_max_version_same() {
    let options = TlsOptions {
        versions: vec![], // Empty when using min/max
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_min_max_version_invalid() {
    let options = TlsOptions {
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_2),
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_versions_conflict_with_min() {
    let options = TlsOptions {
        versions: vec![TlsVersion::V1_2],
        min_version: Some(TlsVersion::V1_2),
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_versions_conflict_with_max() {
    let options = TlsOptions {
        versions: vec![TlsVersion::V1_3],
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_cipher_suites_valid() {
    let supported = supported_cipher_suites();
    let first_suite = supported
        .first()
        .unwrap_or_else(|| panic!("Should have at least one cipher suite"));

    let options = TlsOptions { cipher_suites: vec![first_suite.to_string()], ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_cipher_suites_multiple_valid() {
    let supported = supported_cipher_suites();
    let suites: Vec<String> = supported.iter().take(3).map(|s| s.to_string()).collect();

    let options = TlsOptions { cipher_suites: suites, ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_cipher_suites_invalid() {
    let options = TlsOptions {
        cipher_suites: vec!["INVALID_CIPHER_SUITE".to_string()],
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_cipher_suites_empty_string() {
    let options = TlsOptions { cipher_suites: vec!["".to_string()], ..Default::default() };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_curve_preferences_valid() {
    let supported = supported_curves();
    let first_curve = supported
        .first()
        .unwrap_or_else(|| panic!("Should have at least one curve"));

    let options =
        TlsOptions { curve_preferences: vec![first_curve.to_string()], ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_curve_preferences_multiple_valid() {
    let supported = supported_curves();
    let curves: Vec<String> = supported.iter().take(2).map(|s| s.to_string()).collect();

    let options = TlsOptions { curve_preferences: curves, ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_curve_preferences_invalid() {
    let options =
        TlsOptions { curve_preferences: vec!["INVALID_CURVE".to_string()], ..Default::default() };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_curve_preferences_empty_string() {
    let options = TlsOptions { curve_preferences: vec!["".to_string()], ..Default::default() };
    assert!(validate_tls_options(&options).is_err());
}

#[test]
fn test_validate_tls_options_all_options_valid() {
    let supported_suites = supported_cipher_suites();
    let supported_curves = supported_curves();

    let options = TlsOptions {
        versions: vec![TlsVersion::V1_2, TlsVersion::V1_3],
        cipher_suites: vec![supported_suites[0].to_string()],
        curve_preferences: vec![supported_curves[0].to_string()],
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_tls_options_default_values() {
    let options = TlsOptions::default();

    assert_eq!(options.versions.len(), 2, "Default versions should contain TLS 1.2 and 1.3");
    assert!(options.versions.contains(&TlsVersion::V1_2));
    assert!(options.versions.contains(&TlsVersion::V1_3));
    assert!(options.min_version.is_none());
    assert!(options.max_version.is_none());
    assert!(
        !options.cipher_suites.is_empty(),
        "Default cipher_suites should contain all supported suites"
    );
    assert!(
        !options.curve_preferences.is_empty(),
        "Default curve_preferences should contain all supported curves"
    );
}
