use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use huginn_proxy_lib::Result as ProxyResult;
use huginn_proxy_lib::config::{ListenConfig, ListenSocket};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

fn listen(
    port: Option<u16>,
    port_tls: Option<u16>,
    ipv6: bool,
    v4: Option<Vec<&str>>,
    v6: Option<Vec<&str>>,
) -> ListenConfig {
    ListenConfig {
        port,
        port_tls,
        ipv6,
        address_v4: v4.map(|a| a.into_iter().map(str::to_string).collect()),
        address_v6: v6.map(|a| a.into_iter().map(str::to_string).collect()),
        ..Default::default()
    }
}

fn sock(addr: SocketAddr, tls_enabled: bool) -> ListenSocket {
    ListenSocket { addr, tls_enabled }
}

fn assert_sockets_err(result: ProxyResult<Vec<ListenSocket>>, needle: &str) {
    match result {
        Err(err) => assert!(err.to_string().contains(needle), "{err}"),
        Ok(sockets) => panic!("expected listen error containing {needle:?}, got {sockets:?}"),
    }
}

#[test]
fn http_only_defaults_to_unspecified_v4() -> TestResult {
    let sockets = listen(Some(80), None, false, None, None).sockets()?;
    assert_eq!(sockets, vec![sock(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)), false)]);
    Ok(())
}

#[test]
fn https_only() -> TestResult {
    let sockets = listen(None, Some(443), false, None, None).sockets()?;
    assert_eq!(sockets, vec![sock(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 443)), true)]);
    Ok(())
}

#[test]
fn both_ports_on_each_ip() -> TestResult {
    let sockets = listen(Some(80), Some(443), false, Some(vec!["127.0.0.1"]), None).sockets()?;
    assert_eq!(
        sockets,
        vec![
            sock(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)), false),
            sock(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)), true),
        ]
    );
    Ok(())
}

#[test]
fn ipv6_flag_adds_unspecified_v6() -> TestResult {
    let sockets = listen(Some(8080), None, true, None, None).sockets()?;
    assert_eq!(
        sockets,
        vec![
            sock(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8080)), false),
            sock(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8080)), false),
        ]
    );
    Ok(())
}

#[test]
fn neither_port_is_error() {
    assert_sockets_err(listen(None, None, false, None, None).sockets(), "port");
}

#[test]
fn equal_ports_are_error() {
    assert_sockets_err(listen(Some(80), Some(80), false, None, None).sockets(), "different");
}

#[test]
fn empty_address_v4_is_error() {
    assert_sockets_err(listen(Some(80), None, false, Some(vec![]), None).sockets(), "empty");
}

#[test]
fn wildcard_mixed_with_specific_v4_is_error() {
    assert_sockets_err(
        listen(Some(80), None, false, Some(vec!["0.0.0.0", "127.0.0.1"]), None).sockets(),
        "0.0.0.0",
    );
}

#[test]
fn bracketed_v6_is_accepted() -> TestResult {
    let sockets =
        listen(Some(80), None, false, Some(vec!["127.0.0.1"]), Some(vec!["[::1]"])).sockets()?;
    assert!(sockets.contains(&sock(SocketAddr::from((Ipv6Addr::LOCALHOST, 80)), false)));
    assert!(sockets.contains(&sock(SocketAddr::from((Ipv4Addr::LOCALHOST, 80)), false)));
    Ok(())
}
