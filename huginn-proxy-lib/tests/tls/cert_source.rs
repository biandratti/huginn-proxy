use huginn_proxy_lib::tls::cert_chain_hash;

#[test]
fn cert_chain_hash_changes_when_certificate_chain_changes(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls_pki_types::CertificateDer;

    let key_a = rcgen::generate_simple_self_signed(vec!["a.test".to_string()])?;
    let key_b = rcgen::generate_simple_self_signed(vec!["b.test".to_string()])?;

    let der_a: CertificateDer<'static> = key_a.cert.der().clone();
    let der_b: CertificateDer<'static> = key_b.cert.der().clone();

    let hash_a_first = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_a_second = cert_chain_hash(std::slice::from_ref(&der_a));
    let hash_b = cert_chain_hash(std::slice::from_ref(&der_b));

    assert_eq!(hash_a_first, hash_a_second, "same chain must produce a stable hash");
    assert_ne!(hash_a_first, hash_b, "different chains must produce different hashes");
    Ok(())
}
