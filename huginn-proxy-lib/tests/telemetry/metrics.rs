use huginn_proxy_lib::telemetry::Metrics;

#[test]
fn acme_metrics_methods_do_not_panic() {
    let m = Metrics::new_noop();
    m.set_acme_domains(2);
    m.record_acme_renewal_success("api.example.com");
    m.record_acme_cached_cert("api.example.com");
    m.record_acme_cache_stored("api.example.com");
    m.record_acme_error("api.example.com");
}

#[test]
fn acme_metrics_multiple_domains() {
    let m = Metrics::new_noop();
    for domain in &["a.example.com", "b.example.com", "c.example.com"] {
        m.record_acme_renewal_success(domain);
        m.record_acme_error(domain);
        m.record_acme_cached_cert(domain);
        m.record_acme_cache_stored(domain);
    }
}

#[test]
fn acme_cert_ready_set_and_clear_do_not_panic() {
    let m = Metrics::new_noop();
    m.set_acme_cert_ready("api.example.com", false);
    m.set_acme_cert_ready("api.example.com", true);
    m.set_acme_cert_ready("api.example.com", false);
}

#[test]
fn acme_cert_ready_multiple_domains_do_not_panic() {
    let m = Metrics::new_noop();
    for domain in &["a.example.com", "b.example.com", "c.example.com"] {
        m.set_acme_cert_ready(domain, true);
    }
    for domain in &["a.example.com", "b.example.com", "c.example.com"] {
        m.set_acme_cert_ready(domain, false);
    }
}
