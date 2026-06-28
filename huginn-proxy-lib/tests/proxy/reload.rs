use std::sync::Arc;

use arc_swap::ArcSwap;
use huginn_proxy_lib::config::{load_from_path, ConfigParts, DynamicConfig};
use huginn_proxy_lib::{
    initial_client_pool, initial_rate_limiter, try_reload, HealthCheckSupervisor, HealthRegistry,
    Metrics, SharedClientPool, SharedRateLimiter, StaticConfig,
};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const LISTEN_PORT: u16 = 18080;

#[derive(Clone)]
struct RouteSpec {
    prefix: &'static str,
    backend: &'static str,
    rate_limit_rps: Option<u32>,
}

#[derive(Clone)]
struct DomainSpec {
    host: &'static str,
    rate_limit_rps: Option<u32>,
    ip_deny: Option<&'static str>,
    routes: Vec<RouteSpec>,
}

#[derive(Clone)]
struct Spec {
    backends: Vec<&'static str>,
    global_rate_limit_rps: Option<u32>,
    global_ip_deny: Option<&'static str>,
    pool_idle_timeout: Option<u64>,
    response_header: Option<(&'static str, &'static str)>,
    domains: Vec<DomainSpec>,
}

fn domain(host: &'static str, rate_limit_rps: Option<u32>, backend: &'static str) -> DomainSpec {
    DomainSpec {
        host,
        rate_limit_rps,
        ip_deny: None,
        routes: vec![RouteSpec { prefix: "/", backend, rate_limit_rps: None }],
    }
}

fn base() -> Spec {
    Spec {
        backends: vec!["127.0.0.1:9001"],
        global_rate_limit_rps: None,
        global_ip_deny: None,
        pool_idle_timeout: None,
        response_header: None,
        domains: vec![domain("127.0.0.1", None, "127.0.0.1:9001")],
    }
}

fn rate_limited() -> Spec {
    let mut spec = base();
    spec.global_rate_limit_rps = Some(1);
    spec
}

fn rl_table(path: &str, rps: u32) -> String {
    format!(
        "[{path}]\nenabled = true\nrequests_per_second = {rps}\nburst = 1\nwindow_seconds = 60\n\n"
    )
}

fn ip_filter_table(path: &str, cidr: &str) -> String {
    format!("[{path}]\nmode = \"denylist\"\ndenylist = [\"{cidr}\"]\n\n")
}

fn render(spec: &Spec) -> String {
    let mut out = format!("listen = {{ addrs = [\"127.0.0.1:{LISTEN_PORT}\"] }}\n");
    let backends = spec
        .backends
        .iter()
        .map(|b| format!("{{ address = \"{b}\" }}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!("backends = [{backends}]\n\n"));

    if let Some(idle) = spec.pool_idle_timeout {
        out.push_str(&format!(
            "[backend_pool]\nenabled = true\nidle_timeout = {idle}\npool_max_idle_per_host = 0\n\n"
        ));
    }
    if let Some(rps) = spec.global_rate_limit_rps {
        out.push_str(&rl_table("security.rate_limit", rps));
    }
    if let Some(cidr) = spec.global_ip_deny {
        out.push_str(&ip_filter_table("security.ip_filter", cidr));
    }
    if let Some((name, value)) = spec.response_header {
        out.push_str(&format!(
            "[security.headers]\ncustom = [{{ name = \"{name}\", value = \"{value}\" }}]\n\n"
        ));
    }
    for domain in &spec.domains {
        out.push_str(&format!("[[domains]]\nhost = \"{}\"\n\n", domain.host));
        if let Some(rps) = domain.rate_limit_rps {
            out.push_str(&rl_table("domains.security.rate_limit", rps));
        }
        if let Some(cidr) = domain.ip_deny {
            out.push_str(&ip_filter_table("domains.security.ip_filter", cidr));
        }
        for route in &domain.routes {
            out.push_str(&format!(
                "[[domains.routes]]\nprefix = \"{}\"\nbackend = \"{}\"\n\n",
                route.prefix, route.backend
            ));
            if let Some(rps) = route.rate_limit_rps {
                out.push_str(&rl_table("domains.routes.security.rate_limit", rps));
            }
        }
    }
    out
}

struct Harness {
    tmp: tempfile::NamedTempFile,
    static_cfg: Arc<StaticConfig>,
    dynamic: Arc<ArcSwap<DynamicConfig>>,
    rate_limiter: SharedRateLimiter,
    client_pool: SharedClientPool,
}

impl Harness {
    fn start(spec: &Spec) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
        std::fs::write(tmp.path(), render(spec))?;
        let config = load_from_path(tmp.path())?;
        let ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
        let static_cfg = Arc::new(static_cfg);
        let dynamic = Arc::new(ArcSwap::from_pointee(dynamic_cfg));
        let rate_limiter = initial_rate_limiter(&dynamic.load());
        let client_pool = initial_client_pool(&static_cfg, &dynamic.load().backend_pool);
        Ok(Self { tmp, static_cfg, dynamic, rate_limiter, client_pool })
    }

    async fn reload(&self, content: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        std::fs::write(self.tmp.path(), content)?;
        let reload_mutex = tokio::sync::Mutex::new(());
        let metrics = Metrics::new_noop();
        let health = HealthCheckSupervisor::new(Arc::new(HealthRegistry::new()));
        try_reload(
            self.tmp.path(),
            &self.static_cfg,
            &self.dynamic,
            &self.rate_limiter,
            &self.client_pool,
            &reload_mutex,
            &metrics,
            &health,
            None,
            false,
        )
        .await;
        Ok(())
    }

    async fn reload_spec(
        &self,
        spec: &Spec,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.reload(&render(spec)).await
    }
}

async fn assert_rate_limiter_rebuilt(before: &Spec, after: &Spec) -> TestResult {
    let h = Harness::start(before)?;
    let manager_before = h.rate_limiter.load_full();
    h.reload_spec(after).await?;
    let manager_after = h.rate_limiter.load_full();
    assert_ne!(Arc::as_ptr(&manager_before), Arc::as_ptr(&manager_after));
    Ok(())
}

async fn assert_rate_limiter_preserved(before: &Spec, after: &Spec) -> TestResult {
    let h = Harness::start(before)?;
    let manager_before = h.rate_limiter.load_full();
    h.reload_spec(after).await?;
    let manager_after = h.rate_limiter.load_full();
    assert_eq!(Arc::as_ptr(&manager_before), Arc::as_ptr(&manager_after));
    Ok(())
}

async fn assert_client_pool_rebuilt(before: &Spec, after: &Spec) -> TestResult {
    let h = Harness::start(before)?;
    let pool_before = h.client_pool.load_full();
    h.reload_spec(after).await?;
    let pool_after = h.client_pool.load_full();
    assert_ne!(Arc::as_ptr(&pool_before), Arc::as_ptr(&pool_after));
    Ok(())
}

async fn assert_client_pool_preserved(before: &Spec, after: &Spec) -> TestResult {
    let h = Harness::start(before)?;
    let pool_before = h.client_pool.load_full();
    h.reload_spec(after).await?;
    let pool_after = h.client_pool.load_full();
    assert_eq!(Arc::as_ptr(&pool_before), Arc::as_ptr(&pool_after));
    Ok(())
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_global_rate_limit_value_changes() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.global_rate_limit_rps = Some(5);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_global_rate_limit_disabled() -> TestResult {
    let before = rate_limited();
    let after = base();
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_domain_override_added() -> TestResult {
    let before = base();
    let mut after = before.clone();
    after.domains[0].rate_limit_rps = Some(2);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_domain_override_value_changes() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    let mut after = before.clone();
    after.domains[0].rate_limit_rps = Some(7);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_domain_override_removed() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    let after = base();
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_route_override_added() -> TestResult {
    let before = base();
    let mut after = before.clone();
    after.domains[0].routes[0].rate_limit_rps = Some(3);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_route_override_value_changes() -> TestResult {
    let mut before = base();
    before.domains[0].routes[0].rate_limit_rps = Some(3);
    let mut after = before.clone();
    after.domains[0].routes[0].rate_limit_rps = Some(9);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_config_unchanged() -> TestResult {
    let spec = rate_limited();
    assert_rate_limiter_preserved(&spec, &spec).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_backend_address_changes() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.backends = vec!["127.0.0.1:9002"];
    after.domains[0].routes[0].backend = "127.0.0.1:9002";
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_response_header_changes() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.response_header = Some(("X-Test", "1"));
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_unrelated_route_added() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.domains[0].routes.push(RouteSpec {
        prefix: "/extra",
        backend: "127.0.0.1:9001",
        rate_limit_rps: None,
    });
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_backend_pool_changes() -> TestResult {
    let mut before = rate_limited();
    before.pool_idle_timeout = Some(90);
    let mut after = before.clone();
    after.pool_idle_timeout = Some(30);
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_client_pool_when_backend_removed() -> TestResult {
    let mut before = base();
    before.backends = vec!["127.0.0.1:9001", "127.0.0.1:9002"];
    before.domains[0].routes.push(RouteSpec {
        prefix: "/b",
        backend: "127.0.0.1:9002",
        rate_limit_rps: None,
    });
    let after = base();
    assert_client_pool_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_client_pool_when_backend_pool_config_changes() -> TestResult {
    let mut before = base();
    before.pool_idle_timeout = Some(90);
    let mut after = before.clone();
    after.pool_idle_timeout = Some(30);
    assert_client_pool_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_client_pool_when_backend_added() -> TestResult {
    let before = base();
    let mut after = before.clone();
    after.backends = vec!["127.0.0.1:9001", "127.0.0.1:9002"];
    after.domains[0].routes.push(RouteSpec {
        prefix: "/b",
        backend: "127.0.0.1:9002",
        rate_limit_rps: None,
    });
    assert_client_pool_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_client_pool_when_config_unchanged() -> TestResult {
    let spec = base();
    assert_client_pool_preserved(&spec, &spec).await
}

#[tokio::test]
async fn reload_preserves_client_pool_when_rate_limit_changes() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.global_rate_limit_rps = Some(5);
    assert_client_pool_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_keeps_previous_dynamic_config_when_new_config_is_invalid() -> TestResult {
    let h = Harness::start(&rate_limited())?;
    let before = (*h.dynamic.load_full()).clone();
    h.reload("this is not valid toml !!!! @@@").await?;
    let after = (*h.dynamic.load_full()).clone();
    assert_eq!(before, after);
    Ok(())
}

#[tokio::test]
async fn reload_applies_new_dynamic_config_when_route_changes() -> TestResult {
    let before = base();
    let mut after = before.clone();
    after.domains[0].routes[0].prefix = "/api";
    let h = Harness::start(&before)?;
    h.reload_spec(&after).await?;
    let dynamic = h.dynamic.load_full();
    assert_eq!(dynamic.domains[0].routes[0].prefix, "/api");
    Ok(())
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_second_domain_override_value_changes() -> TestResult {
    let mut before = base();
    before
        .domains
        .push(domain("example.com", Some(2), "127.0.0.1:9001"));
    let mut after = before.clone();
    after.domains[1].rate_limit_rps = Some(8);
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_rate_limited_domain_added() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    let mut after = before.clone();
    after
        .domains
        .push(domain("example.com", Some(3), "127.0.0.1:9001"));
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_rebuilds_rate_limiter_when_rate_limited_domain_removed() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    before
        .domains
        .push(domain("example.com", Some(3), "127.0.0.1:9001"));
    let mut after = before.clone();
    after.domains.pop();
    assert_rate_limiter_rebuilt(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_other_domain_unrelated_field_changes() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    before
        .domains
        .push(domain("example.com", None, "127.0.0.1:9001"));
    let mut after = before.clone();
    after.backends.push("127.0.0.1:9002");
    after.domains[1].routes[0].backend = "127.0.0.1:9002";
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_global_ip_filter_changes() -> TestResult {
    let before = rate_limited();
    let mut after = before.clone();
    after.global_ip_deny = Some("10.0.0.0/8");
    assert_rate_limiter_preserved(&before, &after).await
}

#[tokio::test]
async fn reload_preserves_rate_limiter_when_domain_ip_filter_changes() -> TestResult {
    let mut before = base();
    before.domains[0].rate_limit_rps = Some(2);
    let mut after = before.clone();
    after.domains[0].ip_deny = Some("10.0.0.0/8");
    assert_rate_limiter_preserved(&before, &after).await
}
