use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow, bail};
use tonic::Status;

use crate::config::Config;

pub fn authorize(
    cfg: &Config,
    remote: Option<SocketAddr>,
    meta: &tonic::metadata::MetadataMap,
) -> std::result::Result<(), Status> {
    if let Some(token) = &cfg.control_plane.token {
        let expected = format!("Bearer {token}");
        let got = meta
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if got != expected {
            return Err(Status::unauthenticated("missing or invalid bearer token"));
        }
    }
    let Some(remote) = remote else {
        return Err(Status::permission_denied("missing peer address"));
    };
    if trusted_remote(cfg, remote.ip()) {
        Ok(())
    } else {
        Err(Status::permission_denied(format!(
            "peer {} is not trusted",
            remote.ip()
        )))
    }
}

pub fn trusted_source_cidrs(cfg: &Config) -> Vec<String> {
    if !cfg.control_plane.trusted_source_cidrs.is_empty() {
        return cfg.control_plane.trusted_source_cidrs.clone();
    }
    crate::linux::net::interface_ipv4_cidr(&cfg.network().underlay_dev, cfg.underlay_ip)
        .or_else(|| fallback_underlay_cidr(cfg.underlay_ip))
        .into_iter()
        .collect()
}

fn trusted_remote(cfg: &Config, ip: IpAddr) -> bool {
    if matches!(ip, IpAddr::V4(v) if v.is_loopback())
        || matches!(ip, IpAddr::V6(v) if v.is_loopback())
    {
        return true;
    }
    trusted_source_cidrs(cfg)
        .iter()
        .any(|cidr| ip_in_cidr(ip, cidr).unwrap_or(false))
}

fn fallback_underlay_cidr(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v) if !v.is_unspecified() => {
            let octets = v.octets();
            Some(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
        }
        IpAddr::V6(v) if !v.is_unspecified() => Some(format!("{v}/64")),
        _ => None,
    }
}

fn ip_in_cidr(ip: IpAddr, cidr: &str) -> Result<bool> {
    let (base, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("CIDR missing prefix"))?;
    let base: IpAddr = base.parse().context("bad CIDR address")?;
    let prefix: u8 = prefix.parse().context("bad CIDR prefix")?;
    match (ip, base) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => {
            if prefix > 32 {
                bail!("IPv4 prefix out of range");
            }
            Ok(masked_v4(ip, prefix) == masked_v4(base, prefix))
        }
        (IpAddr::V6(ip), IpAddr::V6(base)) => {
            if prefix > 128 {
                bail!("IPv6 prefix out of range");
            }
            Ok(masked_v6(ip, prefix) == masked_v6(base, prefix))
        }
        _ => Ok(false),
    }
}

fn masked_v4(ip: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    u32::from(ip) & mask
}

fn masked_v6(ip: std::net::Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix as u32)
    };
    u128::from(ip) & mask
}
