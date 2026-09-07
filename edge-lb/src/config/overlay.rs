use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result, anyhow, bail};

use super::defaults::{
    default_backend_overlay, default_gateway_overlay, old_default_backend_overlay,
    old_default_gateway_overlay,
};

pub(super) fn parse_prefix(s: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = s
        .split_once('/')
        .ok_or_else(|| anyhow!("missing /prefix"))?;
    let ip: IpAddr = ip.parse().context("bad address")?;
    let prefix: u8 = prefix.parse().context("bad prefix")?;
    match ip {
        IpAddr::V4(_) if prefix > 32 => bail!("IPv4 prefix out of range"),
        IpAddr::V6(_) if prefix > 128 => bail!("IPv6 prefix out of range"),
        _ => {}
    }
    Ok((ip, prefix))
}

pub(super) fn same_subnet(a: (IpAddr, u8), b: (IpAddr, u8)) -> bool {
    if a.1 != b.1 || !a.0.is_ipv4() || !b.0.is_ipv4() {
        return false;
    }
    if a.1 > 32 {
        return false;
    }
    let mask = if a.1 == 0 {
        0u32
    } else {
        u32::MAX << (32 - a.1 as u32)
    };
    let to_bits = |v: IpAddr| match v {
        IpAddr::V4(v) => u32::from(v),
        IpAddr::V6(_) => 0,
    };
    (to_bits(a.0) & mask) == (to_bits(b.0) & mask)
}

pub(super) fn overlay_needs_assignment(value: &str) -> bool {
    let value = value.trim();
    value.is_empty()
        || value.eq_ignore_ascii_case("auto")
        || value == default_gateway_overlay()
        || value == old_default_gateway_overlay()
        || value == default_backend_overlay()
        || value == old_default_backend_overlay()
}

pub(super) fn underlay_dev_is_auto(value: &str) -> bool {
    let value = value.trim();
    value.is_empty() || value.eq_ignore_ascii_case("auto")
}

pub(super) fn overlay_host(cidr: &str, host_index: u32) -> Result<String> {
    let (base, prefix) = parse_prefix(cidr)?;
    let IpAddr::V4(base) = base else {
        bail!("network.overlay_cidr must be IPv4");
    };
    if prefix > 30 {
        bail!("network.overlay_cidr prefix must be <= 30");
    }
    let host_bits = 32 - prefix as u32;
    let size = 1u64 << host_bits;
    if host_index == 0 || host_index as u64 >= size - 1 {
        bail!("network.overlay_cidr {cidr} does not have host index {host_index}");
    }
    let mask = u32::MAX << host_bits;
    let network = u32::from(base) & mask;
    Ok(format!(
        "{}/{}",
        Ipv4Addr::from(network + host_index),
        prefix
    ))
}

pub(super) fn validate_overlay_capacity(cidr: (IpAddr, u8), needed_hosts: usize) -> Result<()> {
    let IpAddr::V4(_) = cidr.0 else {
        bail!("network.overlay_cidr must be IPv4");
    };
    if cidr.1 > 30 {
        bail!("network.overlay_cidr prefix must be <= 30");
    }
    let usable = (1usize << (32 - cidr.1 as usize)).saturating_sub(2);
    if usable < needed_hosts {
        bail!("network.overlay_cidr needs at least {needed_hosts} usable addresses, got {usable}");
    }
    Ok(())
}
