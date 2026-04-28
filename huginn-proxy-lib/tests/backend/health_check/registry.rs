use std::sync::Arc;

use huginn_proxy_lib::HealthRegistry;

#[test]
fn empty_registry_treats_unknown_as_healthy() {
    let r = HealthRegistry::new();
    assert!(r.is_healthy("anywhere:1234"));
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
}

#[test]
fn get_or_create_inserts_once() {
    let r = HealthRegistry::new();
    let h1 = r.get_or_create("backend:9000");
    let h2 = r.get_or_create("backend:9000");
    assert!(Arc::ptr_eq(&h1, &h2));
    assert_eq!(r.len(), 1);
}

#[test]
fn newly_created_backend_is_healthy() {
    let r = HealthRegistry::new();
    r.get_or_create("backend:9000");
    assert!(r.is_healthy("backend:9000"));
}

#[test]
fn unhealthy_backend_is_reported_unhealthy() {
    let r = HealthRegistry::new();
    let h = r.get_or_create("backend:9000");
    h.set(false);
    assert!(!r.is_healthy("backend:9000"));
}

#[test]
fn unknown_address_is_healthy_even_when_others_are_not() {
    let r = HealthRegistry::new();
    let h = r.get_or_create("known:9000");
    h.set(false);
    assert!(!r.is_healthy("known:9000"));
    assert!(r.is_healthy("other:9000"));
}

#[test]
fn remove_drops_entry() {
    let r = HealthRegistry::new();
    let h = r.get_or_create("backend:9000");
    h.set(false);
    assert!(!r.is_healthy("backend:9000"));

    r.remove("backend:9000");
    assert!(r.is_healthy("backend:9000"));
    assert_eq!(r.len(), 0);
}

#[test]
fn remove_idempotent() {
    let r = HealthRegistry::new();
    r.remove("never-registered:1");
    assert_eq!(r.len(), 0);
}

#[test]
fn addresses_returns_all_keys() {
    let r = HealthRegistry::new();
    r.get_or_create("a:1");
    r.get_or_create("b:2");
    r.get_or_create("c:3");

    let mut addrs = r.addresses();
    addrs.sort();
    assert_eq!(addrs, vec!["a:1".to_string(), "b:2".to_string(), "c:3".to_string()]);
}

#[test]
fn clone_shares_state() {
    let r1 = HealthRegistry::new();
    let r2 = r1.clone();

    let h = r1.get_or_create("shared:1");
    h.set(false);

    assert!(!r2.is_healthy("shared:1"));
    assert_eq!(r2.len(), 1);
}
