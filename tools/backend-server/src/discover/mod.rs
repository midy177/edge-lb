//! Unified network discovery engine.
//!
//! * [`underlay`] — the underlay (private) IPv4: `UNDERLAY_IP` env, otherwise
//!   a UDP probe along the default route, then an interface scan
//! * [`publicip`] — the public IPv4/IPv6: `PUBLIC_IP` env, otherwise STUN
//!   (env-configured servers first, then built-ins), then HTTPS endpoints
//! * [`hostname`] — reverse DNS of the public IPv4
//! * [`stun`] — minimal RFC 5389 client used by `publicip`
//!
//! OS-specific plumbing (interface addresses, default route) lives in
//! `crate::system`.

pub mod hostname;
pub mod publicip;
pub mod stun;
pub mod underlay;

/// Read an environment variable, trimmed; `None` when unset or empty.
pub(crate) fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}
