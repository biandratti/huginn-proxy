use huginn_certs::CipherSuiteName;
use huginn_proxy_lib::config::{ConfigParser, TlsOptions, TlsVersion, TomlParser};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn config_with_tls_options(options: &str) -> String {
    format!(
        r#"listen = {{ addrs = ["127.0.0.1:7000"] }}
backends = [{{ address = "backend:9000" }}]

[[domains]]
host = "api.example.com"
routes = [{{ prefix = "/", backend = "backend:9000" }}]

[tls.options]
{options}
"#
    )
}

#[test]
fn accepts_no_version_settings() {
    assert!(TlsOptions::default().validate().is_ok());
}

#[test]
fn accepts_an_explicit_versions_list() {
    let options =
        TlsOptions { versions: vec![TlsVersion::V1_2, TlsVersion::V1_3], ..Default::default() };
    assert!(options.validate().is_ok());
}

#[test]
fn accepts_both_bounds() {
    let options = TlsOptions {
        min_version: Some(TlsVersion::V1_2),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(options.validate().is_ok());

    let pinned = TlsOptions {
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(pinned.validate().is_ok());
}

#[test]
fn accepts_a_lone_bound() -> TestResult {
    for options in [r#"min_version = "1.3""#, r#"max_version = "1.2""#] {
        let parsed: TlsOptions = toml::from_str(options)?;
        assert!(
            parsed.validate().is_ok(),
            "`{options}` alone must be a valid config, got: {:?}",
            parsed.validate()
        );
    }
    Ok(())
}

#[test]
fn rejects_min_above_max() {
    let options = TlsOptions {
        min_version: Some(TlsVersion::V1_3),
        max_version: Some(TlsVersion::V1_2),
        ..Default::default()
    };
    // Assert on the message: with a non-empty `versions` default this used to be rejected by the
    // mutual-exclusion check instead, so `is_err()` alone passed for the wrong reason.
    match options.validate() {
        Ok(()) => panic!("min 1.3 > max 1.2 must be rejected"),
        Err(e) => assert!(
            e.to_string().contains("cannot be greater than max_version"),
            "expected the min/max bound error, got: {e}"
        ),
    }
}

#[test]
fn rejects_an_explicit_list_combined_with_a_bound() {
    let with_min = TlsOptions {
        versions: vec![TlsVersion::V1_2],
        min_version: Some(TlsVersion::V1_2),
        ..Default::default()
    };
    assert!(with_min.validate().is_err());

    let with_max = TlsOptions {
        versions: vec![TlsVersion::V1_3],
        max_version: Some(TlsVersion::V1_3),
        ..Default::default()
    };
    assert!(with_max.validate().is_err());
}

#[test]
fn accepts_the_default_suites_for_any_version_range() {
    for options in [
        TlsOptions::default(),
        TlsOptions { min_version: Some(TlsVersion::V1_3), ..Default::default() },
        TlsOptions { versions: vec![TlsVersion::V1_2], ..Default::default() },
    ] {
        assert!(options.validate().is_ok(), "default suites must satisfy {:?}", options.versions);
    }
}

#[test]
fn rejects_suites_that_exclude_the_only_enabled_version() {
    let options = TlsOptions {
        min_version: Some(TlsVersion::V1_3),
        cipher_suites: vec![CipherSuiteName::TlsEcdheRsaWithAes128GcmSha256],
        ..Default::default()
    };
    match options.validate() {
        Ok(()) => panic!("TLS 1.3 only with a 1.2-only suite list must be rejected"),
        Err(e) => assert!(e.to_string().contains("TLS 1.3"), "expected the 1.3 error, got: {e}"),
    }
}

#[test]
fn rejects_a_version_left_without_any_suite() {
    let options = TlsOptions {
        cipher_suites: vec![CipherSuiteName::Tls13Aes128GcmSha256],
        ..Default::default()
    };
    match options.validate() {
        Ok(()) => panic!("TLS 1.2 enabled with only 1.3 suites must be rejected"),
        Err(e) => assert!(e.to_string().contains("TLS 1.2"), "expected the 1.2 error, got: {e}"),
    }
}

#[test]
fn accepts_tls13_only_suites_when_tls12_is_excluded() {
    let options = TlsOptions {
        min_version: Some(TlsVersion::V1_3),
        cipher_suites: vec![CipherSuiteName::Tls13Aes128GcmSha256],
        ..Default::default()
    };
    assert!(options.validate().is_ok());
}

#[test]
fn a_contradictory_tls_section_fails_config_validation() -> TestResult {
    let config = TomlParser
        .parse(&config_with_tls_options("min_version = \"1.3\"\nmax_version = \"1.2\""))?;
    assert!(config.validate_cross_refs().is_err(), "contradictory bounds must fail at load");

    let config = TomlParser.parse(&config_with_tls_options("min_version = \"1.3\""))?;
    config.validate_cross_refs()?;
    Ok(())
}
