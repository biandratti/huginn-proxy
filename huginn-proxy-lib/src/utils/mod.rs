use tokio::time::{Duration, Instant};

/// Returns `base + duration`, falling back gracefully if the addition overflows.
///
/// Both overflow paths are unreachable in practice — they would require
/// durations measured in decades — but `Instant::checked_add` returns
/// `Option`, so a fallback is needed to avoid `unwrap`.
pub(crate) fn deadline_from(base: Instant, duration: Duration) -> Instant {
    base.checked_add(duration)
        .unwrap_or_else(|| base.checked_add(Duration::from_secs(60)).unwrap_or(base))
}
