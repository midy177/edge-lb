//! Backend nftables ruleset generation and application.

use anyhow::{Context, Result, bail};

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use crate::config::{Config, GatewayReturnPath};

use super::nftables;

const UDP_REPLY_TIMEOUT_SECS: u32 = 30;

/// Full ruleset for the agent-owned nft table. Runtime apply uses the
/// nft CLI to atomically load the same file that is written for inspection.
///
/// Backend return-path steering is derived from VXLAN/DSCP ingress packets.
/// Listener ports, target groups, and gateway active state are intentionally
/// not backend inputs.
pub fn ruleset(cfg: &Config) -> String {
    let n = cfg.network();
    let b = cfg.backend_cfg();
    let paths = cfg.backend_return_paths();
    let mut udp_sets = String::new();
    let mut forward_rules = String::new();
    let mut udp_learn_rules = String::new();
    let mut udp_reply_rules = String::new();
    for path in &paths {
        forward_rules.push_str(&format!(
            "        iifname \"{vx}\" ip dscp {dscp} counter ct mark set {mark:#x}\n",
            vx = n.vxlan_dev,
            dscp = path.dscp,
            mark = path.mark,
        ));
        let Some(overlay) = backend_overlay_ipv4(path) else {
            continue;
        };
        let set_name = udp_reply_set_name(path.mark);
        udp_sets.push_str(&format!(
            "    set {set_name} {{\n\
             type ipv4_addr . inet_service\n\
             flags dynamic,timeout\n\
             timeout {timeout}s\n\
             }}\n",
            timeout = UDP_REPLY_TIMEOUT_SECS,
        ));
        udp_learn_rules.push_str(&format!(
            "        iifname \"{vx}\" ip dscp {dscp} meta l4proto udp update @{set_name} {{ ip saddr . udp sport timeout {timeout}s }}\n",
            vx = n.vxlan_dev,
            dscp = path.dscp,
            timeout = UDP_REPLY_TIMEOUT_SECS,
        ));
        udp_reply_rules.push_str(&format!(
            "        meta l4proto udp ip daddr . udp dport @{set_name} counter ip saddr set {overlay} meta mark set {mark:#x}\n",
            mark = path.mark,
        ));
    }
    let mut reply_rules = String::new();
    for mark in return_marks(cfg) {
        reply_rules.push_str(&format!(
            "        ct mark {mark:#x} ct direction reply counter meta mark set {mark:#x}\n",
        ));
    }
    format!(
        "table inet {t}\ndelete table inet {t}\n\ntable inet {t} {{\n\
{udp_sets}\
         chain prerouting {{\n\
         type filter hook prerouting priority mangle; policy accept;\n\
         # Gateway-marked ingress traffic selects the return path by DSCP.\n{forward_rules}\
         # Learn UDP client tuples from DSCP-marked ingress packets; output\n\
         # repair stays datapath-derived rather than service-port-derived.\n{udp_learn_rules}\
         # Reply: marked reply-direction packets get the routing fwmark.\n\
{reply_rules}\
         }}\n\
         chain output {{\n\
         type route hook output priority mangle; policy accept;\n\
         # Repair only UDP replies whose client tuple was learned from a\n\
         # DSCP-marked ingress packet.\n\
{udp_reply_rules}\
         # Replies from host-native services.\n\
{reply_rules}\
         }}\n\
         chain forward {{\n\
         type filter hook forward priority mangle; policy accept;\n\
         oifname \"{vx}\" tcp flags & (fin | syn | rst | ack) == syn counter tcp option maxseg size set {mss}\n\
         }}\n\
        }}\n",
        t = b.nft_table,
        vx = n.vxlan_dev,
        mss = b.mss,
    )
}

fn backend_overlay_ipv4(path: &GatewayReturnPath) -> Option<Ipv4Addr> {
    let value = path.backend_overlay_ip.as_ref()?;
    let host = value.split('/').next().unwrap_or(value);
    match host.parse().ok()? {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    }
}

fn udp_reply_set_name(mark: u32) -> String {
    format!("udp_reply_{mark:x}")
}

fn return_marks(cfg: &Config) -> Vec<u32> {
    let mut marks = cfg
        .backend_return_paths()
        .into_iter()
        .map(|path| path.mark)
        .collect::<Vec<_>>();
    marks.sort_unstable();
    marks.dedup();
    marks
}

pub fn apply(cfg: &Config) -> Result<()> {
    let dir = std::path::Path::new(&*cfg.state_dir);
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let file = dir.join("backend-return.nft");
    std::fs::write(&file, ruleset(cfg)).with_context(|| format!("writing {}", file.display()))?;
    let output = Command::new("nft")
        .arg("-f")
        .arg(&file)
        .output()
        .with_context(|| format!("running nft -f {}", file.display()))?;
    if !output.status.success() {
        bail!(
            "nft -f {} failed with status {}: {}",
            file.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub fn table_exists(cfg: &Config) -> bool {
    nftables::table_exists(cfg)
}

pub fn delete_table(cfg: &Config) {
    nftables::delete_table(cfg).ok();
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{FileConfig, GatewayReturnPath, Listener, NetworkConfig, Protocol};

    #[test]
    fn udp_reply_repair_is_derived_from_ingress_dscp_not_service_ports() {
        let mark = crate::config::return_mark(46, 0);
        let file = FileConfig {
            network: NetworkConfig {
                vxlan_dev: "edge-return".to_string(),
                ..NetworkConfig::default()
            },
            listeners: vec![Listener {
                port: 80,
                target_port: 8080,
                protocols: vec![Protocol::Udp],
                ..Listener::default()
            }],
            backend_return_paths: vec![GatewayReturnPath {
                gateway: Some("gateway-a".to_string()),
                gateway_underlay_ip: "192.0.2.1".parse().unwrap(),
                gateway_overlay_ip: "10.44.0.1".parse().unwrap(),
                backend_overlay_ip: Some("10.44.0.2/24".to_string()),
                dscp: 46,
                mark,
                route_table_id: crate::config::return_table_id(46, 0),
            }],
            ..FileConfig::default()
        };
        let cfg = Config {
            file,
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };

        let rules = ruleset(&cfg);

        assert!(rules.contains("iifname \"edge-return\" ip dscp 46"));
        assert!(rules.contains("update @udp_reply_106e { ip saddr . udp sport timeout 30s }"));
        assert!(rules.contains("ip daddr . udp dport @udp_reply_106e"));
        assert!(rules.contains("ip saddr set 10.44.0.2"));
        assert!(!rules.contains("8080"));
    }
}
