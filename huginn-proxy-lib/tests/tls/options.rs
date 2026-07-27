use huginn_proxy_lib::config::{SessionResumptionConfig, TlsConfig, TlsOptions, TlsVersion};
use huginn_proxy_lib::tls::{
    supported_cipher_suites, supported_curves, tls_build_options, validate_tls_options, KxGroupName,
};
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::SupportedProtocolVersion;

/// Resolve `TlsOptions` into the effective protocol-version list the cert builder
/// receives (via the public `tls_build_options` projection).
fn resolved_versions(options: TlsOptions) -> Vec<&'static SupportedProtocolVersion> {
    let cfg =
        TlsConfig { alpn: vec![], options, session_resumption: SessionResumptionConfig::default() };
    tls_build_options(&cfg).protocol_versions
}

fn contains_version(
    versions: &[&'static SupportedProtocolVersion],
    want: &'static SupportedProtocolVersion,
) -> bool {
    versions.iter().any(|got| std::ptr::eq(*got, want))
}

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
    let options =
        TlsOptions { curve_preferences: vec![KxGroupName::X25519MlKem768], ..Default::default() };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn test_validate_tls_options_curve_preferences_multiple_valid() {
    let options = TlsOptions {
        curve_preferences: vec![KxGroupName::X25519MlKem768, KxGroupName::X25519],
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn curve_preferences_reject_unknown_name_at_parse() {
    let result = toml::from_str::<TlsOptions>(
        r#"
        curve_preferences = ["INVALID_CURVE"]
        "#,
    );
    match result {
        Ok(_) => panic!("unknown curve name must fail at parse"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("INVALID_CURVE") || msg.contains("did not match"),
                "error should mention the bad value: {msg}"
            );
        }
    }
}

#[test]
fn curve_preferences_reject_empty_string_at_parse() {
    let result = toml::from_str::<TlsOptions>(
        r#"
        curve_preferences = [""]
        "#,
    );
    assert!(result.is_err(), "empty curve name must fail at parse");
}

#[test]
fn test_validate_tls_options_all_options_valid() {
    let supported_suites = supported_cipher_suites();

    let options = TlsOptions {
        versions: vec![TlsVersion::V1_2, TlsVersion::V1_3],
        cipher_suites: vec![supported_suites[0].to_string()],
        curve_preferences: vec![KxGroupName::X25519],
        ..Default::default()
    };
    assert!(validate_tls_options(&options).is_ok());
}

#[test]
fn resolve_versions_default_is_safe_defaults() {
    // Default (1.2 + 1.3) means "no restriction" → empty list → provider safe defaults.
    assert!(resolved_versions(TlsOptions::default()).is_empty());
}

#[test]
fn resolve_versions_single_version_restricts() {
    let only_13 =
        resolved_versions(TlsOptions { versions: vec![TlsVersion::V1_3], ..Default::default() });
    assert_eq!(only_13.len(), 1);
    assert!(contains_version(&only_13, &TLS13));
    assert!(!contains_version(&only_13, &TLS12));

    let only_12 =
        resolved_versions(TlsOptions { versions: vec![TlsVersion::V1_2], ..Default::default() });
    assert_eq!(only_12.len(), 1);
    assert!(contains_version(&only_12, &TLS12));
}

#[test]
fn resolve_versions_both_versions_is_safe_defaults() {
    let both = resolved_versions(TlsOptions {
        versions: vec![TlsVersion::V1_2, TlsVersion::V1_3],
        ..Default::default()
    });
    assert!(both.is_empty(), "both versions == no restriction == safe defaults");
}

#[test]
fn resolve_versions_min_max_bounds() {
    // min == max == 1.3 → only 1.3.
    let pinned_13 = resolved_versions(TlsOptions {
        versions: vec![],
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    });
    assert_eq!(pinned_13.len(), 1);
    assert!(contains_version(&pinned_13, &TLS13));

    // max = 1.2 → only 1.2.
    let capped_12 = resolved_versions(TlsOptions {
        versions: vec![],
        max_version: Some(TlsVersion::V1_2),
        ..Default::default()
    });
    assert_eq!(capped_12.len(), 1);
    assert!(contains_version(&capped_12, &TLS12));

    // min = 1.2 (max defaults to 1.3) → both → no restriction.
    let min_only = resolved_versions(TlsOptions {
        versions: vec![],
        min_version: Some(TlsVersion::V1_2),
        ..Default::default()
    });
    assert!(min_only.is_empty());
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
        options.curve_preferences.is_empty(),
        "Default curve_preferences should be empty so the provider defaults (incl. the \
         post-quantum hybrid) apply"
    );
}

#[test]
fn supported_curves_include_pq_hybrid_and_exclude_secp521() {
    assert!(supported_curves().contains(&"X25519MLKEM768"), "PQ hybrid must be selectable");
    assert!(
        !supported_curves().contains(&"secp521r1"),
        "secp521r1 is not an aws-lc-rs key-exchange group and must not validate"
    );
    // Consistency: the PQ hybrid validates, the dropped curve does not.
    assert!(huginn_proxy_lib::tls::is_curve_supported("X25519MLKEM768"));
    assert!(!huginn_proxy_lib::tls::is_curve_supported("secp521r1"));
    assert_eq!(KxGroupName::ALL.len(), supported_curves().len());
}
