//! Tests for [`AcmeEvent`] mapping and the [`OnAcmeEvent`] callback contract.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use huginn_acme::{acme_event_from_ok, AcmeEvent, OnAcmeEvent};
use rustls_acme::EventOk;

#[test]
fn acme_event_from_ok_deployed_new() {
    assert_eq!(acme_event_from_ok(&EventOk::DeployedNewCert), AcmeEvent::DeployedNewCert);
}

#[test]
fn acme_event_from_ok_deployed_cached() {
    assert_eq!(acme_event_from_ok(&EventOk::DeployedCachedCert), AcmeEvent::DeployedCachedCert);
}

#[test]
fn acme_event_from_ok_cert_cache_store() {
    assert_eq!(acme_event_from_ok(&EventOk::CertCacheStore), AcmeEvent::CacheStored);
}

#[test]
fn acme_event_from_ok_account_cache_store() {
    assert_eq!(acme_event_from_ok(&EventOk::AccountCacheStore), AcmeEvent::CacheStored);
}

#[test]
fn on_acme_event_callback_invoked() {
    let success_count = Arc::new(AtomicU32::new(0));
    let error_count = Arc::new(AtomicU32::new(0));
    let cache_count = Arc::new(AtomicU32::new(0));

    let sc = Arc::clone(&success_count);
    let ec = Arc::clone(&error_count);
    let cc = Arc::clone(&cache_count);

    let cb: OnAcmeEvent = Arc::new(move |_domain, ev| match ev {
        AcmeEvent::DeployedNewCert | AcmeEvent::DeployedCachedCert => {
            sc.fetch_add(1, Ordering::Relaxed);
        }
        AcmeEvent::Error => {
            ec.fetch_add(1, Ordering::Relaxed);
        }
        AcmeEvent::CacheStored => {
            cc.fetch_add(1, Ordering::Relaxed);
        }
    });

    cb("example.com", AcmeEvent::DeployedNewCert);
    cb("example.com", AcmeEvent::DeployedCachedCert);
    cb("example.com", AcmeEvent::Error);
    cb("example.com", AcmeEvent::CacheStored);
    cb("example.com", AcmeEvent::CacheStored);

    assert_eq!(success_count.load(Ordering::Relaxed), 2);
    assert_eq!(error_count.load(Ordering::Relaxed), 1);
    assert_eq!(cache_count.load(Ordering::Relaxed), 2);
}
