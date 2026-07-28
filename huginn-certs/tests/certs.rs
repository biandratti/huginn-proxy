use huginn_certs::{cert_chain_hash, fnv1a_hash};
use rustls_pki_types::CertificateDer;

/// Canonical FNV-1a 64-bit test vectors.
///
/// The point of these values is that they are fixed by the spec, not by this implementation: the
/// hash is exported as a metric, so it has to survive a toolchain upgrade unchanged.
#[test]
fn fnv1a_matches_the_reference_vectors() {
    assert_eq!(fnv1a_hash(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a_hash(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a_hash(b"foobar"), 0x8594_4171_f739_67e8);
}

#[test]
fn chain_hash_is_order_sensitive_and_stable() {
    let a: CertificateDer<'static> = CertificateDer::from(b"cert-a".to_vec());
    let b: CertificateDer<'static> = CertificateDer::from(b"cert-b".to_vec());

    let ab = cert_chain_hash(&[a.clone(), b.clone()]);
    assert_eq!(ab, cert_chain_hash(&[a.clone(), b.clone()]), "same chain, same hash");
    assert_ne!(ab, cert_chain_hash(&[b, a]), "a reordered chain is a different chain");
}

/// A single-cert chain is just FNV-1a over its DER, i.e. the chain fold adds no framing.
#[test]
fn chain_hash_of_one_cert_is_the_hash_of_its_der() {
    let der = b"some-der-bytes";
    let cert: CertificateDer<'static> = CertificateDer::from(der.to_vec());

    assert_eq!(cert_chain_hash(&[cert]), fnv1a_hash(der));
}
