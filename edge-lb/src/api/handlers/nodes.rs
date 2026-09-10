use serde_json::json;

use crate::{
    api::response::Reply,
    config::{Config, GatewayNode, NodeRole},
};

pub(in crate::api) fn control_backend_subscriptions() -> Reply {
    match crate::control::active_backend_subscriptions_status() {
        Ok(subs) => Reply::json(200, subs),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn gateway_nodes(cfg: &Config) -> Reply {
    Reply::json(200, json!(gateway_nodes_effective(cfg)))
}

pub(in crate::api) fn backend_nodes(cfg: &Config) -> Reply {
    let subscriptions =
        crate::control::active_backend_subscriptions_status().unwrap_or_else(|_| json!({}));
    let nodes = if matches!(cfg.node_role, NodeRole::Gateway) {
        active_backend_nodes(cfg, &subscriptions)
    } else {
        local_backend_nodes(cfg, &subscriptions)
    };
    Reply::json(200, json!(nodes))
}

pub(in crate::api) fn discover_public_ip(cfg: &Config) -> Reply {
    match crate::runtime::discovery::discover_public_ip(&cfg.file) {
        Ok(value) => Reply::json(200, json!(value)),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

fn gateway_nodes_effective(cfg: &Config) -> Vec<GatewayNode> {
    let mut nodes = cfg.gateway_nodes.clone();
    if !matches!(cfg.node_role, NodeRole::Gateway) {
        return nodes;
    }
    let Ok(ha_cfg) = crate::runtime::ha::load_for_state_dir(&cfg.state_dir) else {
        return nodes;
    };
    for peer in ha_cfg.peers {
        let Ok(underlay_ip) = peer.underlay_ip.trim().parse() else {
            continue;
        };
        let public_ip = peer
            .public_ip
            .as_deref()
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(underlay_ip);
        let overlay_ip = peer
            .overlay_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| cfg.gateway_cfg().overlay_ip.clone());
        if let Some(existing) = nodes
            .iter_mut()
            .find(|gateway| gateway.name == peer.name || gateway.underlay_ip == underlay_ip)
        {
            existing.name = peer.name;
            existing.underlay_ip = underlay_ip;
            existing.public_ip = public_ip;
            existing.overlay_ip = overlay_ip;
        } else {
            nodes.push(GatewayNode {
                name: peer.name,
                public_ip,
                underlay_ip,
                overlay_ip,
            });
        }
    }
    nodes
}

fn active_backend_nodes(cfg: &Config, subscriptions: &serde_json::Value) -> Vec<serde_json::Value> {
    let active_nodes = crate::control::active_backend_nodes(cfg).unwrap_or_default();
    let Some(subs) = subscriptions.as_object() else {
        return Vec::new();
    };
    active_nodes
        .into_iter()
        .map(|node| {
            let sub = subs.get(&node.name).unwrap_or(&serde_json::Value::Null);
            json!({
                "name": node.name,
                "public_ip": sub_str(sub, "public_ip")
                    .unwrap_or_else(|| node.public_ip.to_string()),
                "underlay_ip": sub_str(sub, "underlay_ip")
                    .unwrap_or_else(|| node.underlay_ip.to_string()),
                "overlay_ip": node.overlay_ip,
                "public_ip_mode": sub_str(sub, "public_ip_mode").unwrap_or_else(|| "unknown".to_string()),
                "public_ip_source": sub_str(sub, "public_ip_source").unwrap_or_else(|| "unknown".to_string()),
                "underlay_ip_mode": sub_str(sub, "underlay_ip_mode").unwrap_or_else(|| "unknown".to_string()),
                "underlay_ip_source": sub_str(sub, "underlay_ip_source").unwrap_or_else(|| "unknown".to_string()),
                "conflicts": sub
                    .get("conflicts")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            })
        })
        .collect()
}

fn local_backend_nodes(cfg: &Config, subscriptions: &serde_json::Value) -> Vec<serde_json::Value> {
    cfg.backend_nodes_effective()
        .into_iter()
        .map(|node| {
            let sub = subscriptions.get(&node.name);
            let is_local = node.name == cfg.node_name;
            json!({
                "name": node.name,
                "public_ip": node.public_ip,
                "underlay_ip": node.underlay_ip,
                "overlay_ip": node.overlay_ip,
                "public_ip_mode": sub
                    .and_then(|s| s.get("public_ip_mode"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| local_or_default_mode(is_local, &cfg.file.runtime_discovery.public_ip.mode, node.public_ip)),
                "public_ip_source": sub
                    .and_then(|s| s.get("public_ip_source"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| local_or_default_source(is_local, &cfg.file.runtime_discovery.public_ip.source, node.public_ip)),
                "underlay_ip_mode": sub
                    .and_then(|s| s.get("underlay_ip_mode"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| local_or_default_mode(is_local, &cfg.file.runtime_discovery.underlay_ip.mode, node.underlay_ip)),
                "underlay_ip_source": sub
                    .and_then(|s| s.get("underlay_ip_source"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| local_or_default_source(is_local, &cfg.file.runtime_discovery.underlay_ip.source, node.underlay_ip)),
                "conflicts": sub
                    .and_then(|s| s.get("conflicts"))
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            })
        })
        .collect()
}

fn sub_str(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(str::to_string)
}

fn local_or_default_mode(is_local: bool, local: &str, ip: std::net::IpAddr) -> String {
    if is_local && !local.trim().is_empty() {
        local.to_string()
    } else if ip.is_unspecified() {
        "auto".to_string()
    } else {
        "static".to_string()
    }
}

fn local_or_default_source(is_local: bool, local: &str, ip: std::net::IpAddr) -> String {
    if is_local && !local.trim().is_empty() {
        local.to_string()
    } else if ip.is_unspecified() {
        "unresolved".to_string()
    } else {
        "config".to_string()
    }
}
