//! End-to-end verification: VIP path, backend direct path, eBPF counters,
//! plus recommended capture commands for deeper debugging.

use anyhow::{Context, Result};

use std::net::IpAddr;

use crate::{cli::VerifyArgs, config::Config, linux::dscp};

pub struct VerifyOutcome {
    pub vip_ok: bool,
    pub backend_ok: bool,
    pub detail: String,
}

pub fn run_checks(cfg: &Config, args: &VerifyArgs) -> Result<VerifyOutcome> {
    let n = cfg.network();
    let mut detail = String::new();
    let mut vip_ok = false;
    let mut backend_ok = false;

    if !args.skip_vip {
        let url = format!("http://{}:{}/health", n.gateway_public_ip, vip_port(cfg));
        println!("== VIP path: {url}");
        match curl(&url, args.timeout) {
            Ok((code, body)) => {
                vip_ok = code == 200;
                detail.push_str(&format!("VIP {url} -> {code} {body}\n"));
                println!("   HTTP {code} {body}");
            }
            Err(e) => {
                detail.push_str(&format!("VIP {url} -> ERROR {e}\n"));
                println!("   ERROR: {e}");
            }
        }
    }
    if !args.skip_backend {
        let backend = first_backend_probe_target(cfg);
        let backend_public = cfg
            .backend_by_underlay(backend.address)
            .map(|b| b.public_ip)
            .or(n.backend_public_ip)
            .unwrap_or(backend.address);
        let url = format!("http://{}:{}/health", backend_public, backend.port);
        println!("== Backend direct path: {url}");
        match curl(&url, args.timeout) {
            Ok((code, body)) => {
                backend_ok = code == 200;
                detail.push_str(&format!("backend {url} -> {code} {body}\n"));
                println!("   HTTP {code} {body}");
            }
            Err(e) => {
                detail.push_str(&format!("backend {url} -> ERROR {e}\n"));
                println!("   ERROR: {e}");
            }
        }
    }
    if let Ok(stats) = dscp::stats(cfg) {
        println!(
            "== DSCP marker: matched={} changed={}",
            stats.matched, stats.changed
        );
        detail.push_str(format!("dscp stats: {stats:?}\n").as_str());
        if stats.matched == 0 {
            println!("   NOTE: no packets matched yet; generate VIP traffic first");
        }
    }
    println!("\n== Suggested capture");
    println!(
        "   tcpdump -ni any -vv 'port {} or port {} or udp port {}'",
        vip_port(cfg),
        first_backend_probe_target(cfg).port,
        n.vxlan_port,
    );
    println!(
        "   expect: forward tos 0x{:02x} (plus ECN bits); replies via {} outer udp {}",
        n.dscp << 2,
        n.vxlan_dev,
        n.vxlan_port
    );
    Ok(VerifyOutcome {
        vip_ok,
        backend_ok,
        detail,
    })
}

fn vip_port(cfg: &Config) -> u16 {
    cfg.listeners
        .first()
        .map(|listener| listener.port)
        .or_else(|| cfg.services.first().map(|service| service.vip_port))
        .unwrap_or(48080)
}

#[derive(Clone, Copy)]
struct BackendProbeTarget {
    address: IpAddr,
    port: u16,
}

fn first_backend_probe_target(cfg: &Config) -> BackendProbeTarget {
    for listener in &cfg.listeners {
        let Some(group) = cfg
            .target_groups
            .iter()
            .find(|group| group.name == listener.target_group)
        else {
            continue;
        };
        if let Some(target) = group.targets.first() {
            return BackendProbeTarget {
                address: cfg.resolve_backend_target_address(target),
                port: listener.target_port,
            };
        }
    }
    if let Some(service) = cfg.services.first() {
        return BackendProbeTarget {
            address: service.backend_ip,
            port: service.backend_port,
        };
    }
    BackendProbeTarget {
        address: cfg
            .backend_nodes_effective()
            .first()
            .map(|b| b.underlay_ip)
            .or(cfg.network().backend_ip)
            .unwrap_or_else(|| "127.0.0.1".parse().unwrap()),
        port: 58080,
    }
}

/// curl a URL; returns (status, body snippet).
fn curl(url: &str, timeout: u64) -> Result<(u32, String)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout))
        .build()
        .context("building verification HTTP client")?;
    let response = client
        .get(url)
        .send()
        .context("sending verification request")?;
    let code = response.status().as_u16() as u32;
    let body = response.text().unwrap_or_else(|_| "(no body)".to_string());
    Ok((code, body))
}
