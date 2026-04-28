use huginn_proxy_lib::{BackendSelector, HealthRegistry};

#[test]
fn select_round_robin_across_healthy_candidates() {
    let selector = BackendSelector::new();
    let registry = HealthRegistry::new();
    let candidates = ["backend-a:9000", "backend-b:9000"];

    let first = selector
        .select("/api", &candidates, &registry)
        .unwrap_or_else(|| panic!("expected first candidate"));
    let second = selector
        .select("/api", &candidates, &registry)
        .unwrap_or_else(|| panic!("expected second candidate"));
    let third = selector
        .select("/api", &candidates, &registry)
        .unwrap_or_else(|| panic!("expected wraparound candidate"));

    assert_eq!(first, "backend-a:9000");
    assert_eq!(second, "backend-b:9000");
    assert_eq!(third, "backend-a:9000");
}

#[test]
fn select_skips_unhealthy_candidates() {
    let selector = BackendSelector::new();
    let registry = HealthRegistry::new();
    let a = registry.get_or_create("backend-a:9000");
    let _b = registry.get_or_create("backend-b:9000");
    a.set(false);
    let candidates = ["backend-a:9000", "backend-b:9000"];

    let selected = selector
        .select("/api", &candidates, &registry)
        .unwrap_or_else(|| panic!("expected healthy fallback candidate"));
    assert_eq!(selected, "backend-b:9000");
}

#[test]
fn select_returns_none_when_all_candidates_unhealthy() {
    let selector = BackendSelector::new();
    let registry = HealthRegistry::new();
    let a = registry.get_or_create("backend-a:9000");
    let b = registry.get_or_create("backend-b:9000");
    a.set(false);
    b.set(false);
    let candidates = ["backend-a:9000", "backend-b:9000"];

    assert!(selector.select("/api", &candidates, &registry).is_none());
}
