//! Public IP discovery.
//!
//! Precedence (per user requirements):
//!   1. `PUBLIC_IP` environment variable (used directly when it parses as IPv4)
//!   2. STUN — servers from `STUN_SERVERS` / `STUN_SERVER` first, then a
//!      built-in list
//!   3. Plain-HTTPS endpoints such as `https://api.ip.sb/ip`

use super::env_nonempty;
use super::stun::{self, Family};
use crate::log::debug_if;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const BUILTIN_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

const HTTPS_V4_ENDPOINTS: &[&str] = &[
    "https://api.ip.sb/ip",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://api.ipify.org",
];

const HTTPS_V6_ENDPOINTS: &[&str] = &["https://api6.ip.sb/ip", "https://api64.ipify.org"];

const HTTPS_TIMEOUT: Duration = Duration::from_secs(5);

/// STUN servers to try: environment-configured first, then built-ins.
pub fn stun_server_list() -> Vec<String> {
    let configured = env_nonempty("STUN_SERVERS").or_else(|| env_nonempty("STUN_SERVER"));
    server_list_from(configured.as_deref())
}

/// Pure form of [`stun_server_list`] (unit-testable, no environment access).
pub fn server_list_from(configured: Option<&str>) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    if let Some(v) = configured {
        for part in v.split(',') {
            let s = stun::normalize_server(part);
            if !s.is_empty() && !list.contains(&s) {
                list.push(s);
            }
        }
    }
    for b in BUILTIN_STUN_SERVERS {
        let s = stun::normalize_server(b);
        if !list.contains(&s) {
            list.push(s);
        }
    }
    list
}

pub fn discover_v4(debug: bool) -> Result<Ipv4Addr, String> {
    if let Some(v) = env_nonempty("PUBLIC_IP") {
        if let Ok(IpAddr::V4(ip)) = v.parse::<IpAddr>() {
            return Ok(ip);
        }
        debug_if(
            debug,
            &format!("public: invalid PUBLIC_IP value {v:?}; discovering instead"),
        );
    }

    let servers = stun_server_list();
    match stun::discover(&servers, Family::IPv4, |m| debug_if(debug, m)) {
        Ok(IpAddr::V4(ip)) => return Ok(ip),
        Ok(IpAddr::V6(_)) => debug_if(debug, "public: STUN returned IPv6 for IPv4 query"),
        Err(e) => debug_if(
            debug,
            &format!("public: {e}; falling back to HTTPS endpoints"),
        ),
    }

    match https_lookup(HTTPS_V4_ENDPOINTS, Family::IPv4) {
        Ok(IpAddr::V4(ip)) => Ok(ip),
        Ok(IpAddr::V6(_)) => Err("HTTPS endpoint returned IPv6 for an IPv4 lookup".to_string()),
        Err(e) => Err(format!("all public IPv4 discovery methods failed: {e}")),
    }
}

pub fn discover_v6(debug: bool) -> Result<Ipv6Addr, String> {
    let servers = stun_server_list();
    match stun::discover(&servers, Family::IPv6, |m| debug_if(debug, m)) {
        Ok(IpAddr::V6(ip)) => return Ok(ip),
        Ok(IpAddr::V4(_)) => debug_if(debug, "public: STUN returned IPv4 for IPv6 query"),
        Err(e) => debug_if(
            debug,
            &format!("public: {e}; falling back to HTTPS endpoints"),
        ),
    }

    match https_lookup(HTTPS_V6_ENDPOINTS, Family::IPv6) {
        Ok(IpAddr::V6(ip)) => Ok(ip),
        Ok(IpAddr::V4(_)) => Err("HTTPS endpoint returned IPv4 for an IPv6 lookup".to_string()),
        Err(e) => Err(format!("all public IPv6 discovery methods failed: {e}")),
    }
}

/// Fetch each URL in order; accept a body that is exactly one IP address of
/// the wanted family. Mirrors the Go version's plain-text IP parsing.
fn https_lookup(urls: &[&str], family: Family) -> Result<IpAddr, String> {
    let agent = ureq::AgentBuilder::new().timeout(HTTPS_TIMEOUT).build();
    let mut errors: Vec<String> = Vec::new();

    for url in urls {
        let body = match agent.get(url).call() {
            Ok(resp) => {
                let status = resp.status();
                if !(200..=299).contains(&status) {
                    errors.push(format!("{url}: non-2XX response: {status}"));
                    continue;
                }
                match resp.into_string() {
                    Ok(b) => b,
                    Err(e) => {
                        errors.push(format!("{url}: failed to read response: {e}"));
                        continue;
                    }
                }
            }
            Err(e) => {
                errors.push(format!("{url}: {e}"));
                continue;
            }
        };

        let text = body.trim();
        match text.parse::<IpAddr>() {
            Ok(ip)
                if matches!(
                    (family, ip),
                    (Family::IPv4, IpAddr::V4(_)) | (Family::IPv6, IpAddr::V6(_))
                ) =>
            {
                return Ok(ip);
            }
            Ok(other) => errors.push(format!("{url}: unexpected address family: {other}")),
            Err(_) => errors.push(format!("{url}: invalid response: {text:?}")),
        }
    }

    Err(errors.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_servers_come_first_and_dedupe() {
        let list = server_list_from(Some("mystun.example.com, second.example.org:19302"));
        assert_eq!(list[0], "mystun.example.com:3478");
        assert_eq!(list[1], "second.example.org:19302");
        assert!(list.len() > 2); // built-ins follow
        assert_eq!(
            list.len(),
            list.iter().collect::<std::collections::HashSet<_>>().len()
        );

        // A configured server duplicating a built-in must appear once.
        let list = server_list_from(Some("stun.cloudflare.com"));
        assert_eq!(
            list.iter()
                .filter(|s| s.as_str() == "stun.cloudflare.com:3478")
                .count(),
            1
        );
        assert_eq!(list[0], "stun.cloudflare.com:3478");
    }

    #[test]
    fn no_env_means_builtins_only() {
        let list = server_list_from(None);
        assert_eq!(
            list,
            BUILTIN_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        );
    }
}
