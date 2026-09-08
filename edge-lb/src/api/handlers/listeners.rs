use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

use crate::{
    api::response::Reply,
    config::{Config, LbMode, LbSelect, Listener, Protocol},
};

use super::{
    common::require_gateway_role,
    proxy_config::{self, ProxyConfigOperation},
};

/// Stable control-plane representation. This is intentionally independent of
/// the native datapath representation: listeners bind target groups, while
/// backend targets and probes live under `/api/v1/target-groups`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ListenerConfigResource {
    #[serde(default)]
    name: String,
    vip_ips: Vec<IpAddr>,
    port: u16,
    target_port: u16,
    protocols: Vec<Protocol>,
    target_group: String,
    select: LbSelect,
    inactive_timeout: Option<u32>,
}

impl From<&Listener> for ListenerConfigResource {
    fn from(value: &Listener) -> Self {
        Self {
            name: value.name.clone(),
            vip_ips: value.vip_ips.clone(),
            port: value.port,
            target_port: value.target_port,
            protocols: value.protocols.clone(),
            target_group: value.target_group.clone(),
            select: value.select,
            inactive_timeout: value.inactive_timeout,
        }
    }
}

impl From<ListenerConfigResource> for Listener {
    fn from(value: ListenerConfigResource) -> Self {
        let mut protocols = if value.protocols.is_empty() {
            vec![Protocol::Tcp]
        } else {
            value.protocols
        };
        let mut deduped_protocols = Vec::new();
        for protocol in protocols {
            if !deduped_protocols.contains(&protocol) {
                deduped_protocols.push(protocol);
            }
        }
        protocols = deduped_protocols;
        let generated_name = native_generated_listener_name(
            &protocols
                .iter()
                .map(|protocol| protocol.as_str())
                .collect::<Vec<_>>()
                .join("-"),
            value.port,
        );
        let auto_prefix = value.name.trim().starts_with("auto-");
        Self {
            name: if auto_prefix {
                format!("auto-{generated_name}")
            } else {
                generated_name
            },
            vip_ips: value.vip_ips,
            port: value.port,
            target_port: value.target_port,
            protocols,
            target_group: value.target_group,
            select: value.select,
            mode: LbMode::Default,
            inactive_timeout: value.inactive_timeout,
        }
    }
}

pub(in crate::api) fn list_configs(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match persisted_listeners(cfg) {
        Ok(listeners) => Reply::json(200, serde_json::to_value(listeners).unwrap()),
        Err(e) => Reply::error(500, format!("loading listeners: {e:#}")),
    }
}

pub(in crate::api) fn export_configs(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    Reply::json(
        200,
        serde_json::json!({
            "version": 1,
            "listeners": persisted_listeners(cfg).unwrap_or_default()
        }),
    )
}

fn coalesce_listener_resources(
    resources: Vec<ListenerConfigResource>,
) -> Vec<ListenerConfigResource> {
    let mut result = Vec::new();
    for resource in resources {
        if let Some(existing) = result
            .iter_mut()
            .find(|existing: &&mut ListenerConfigResource| {
                existing.name == resource.name
                    && existing.port == resource.port
                    && existing.target_port == resource.target_port
                    && existing.protocols == resource.protocols
                    && existing.target_group == resource.target_group
                    && existing.select == resource.select
                    && existing.inactive_timeout == resource.inactive_timeout
            })
        {
            for vip in resource.vip_ips {
                if !existing.vip_ips.contains(&vip) {
                    existing.vip_ips.push(vip);
                }
            }
        } else {
            result.push(resource);
        }
    }
    result
}

pub(in crate::api) fn import_configs(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad listener import JSON: {e}")),
    };
    let entries = value.get("listeners").cloned().unwrap_or(value);
    let entries: Vec<ListenerConfigResource> = match serde_json::from_value(entries) {
        Ok(entries) => entries,
        Err(e) => return Reply::error(400, format!("bad listener import payload: {e}")),
    };
    let mut imported = 0;
    for entry in entries {
        let reply = create_config(cfg, &serde_json::to_string(&entry).unwrap());
        if !(200..300).contains(&reply.status) {
            return reply;
        }
        imported += 1;
    }
    Reply::json(
        200,
        serde_json::json!({ "status": "imported", "count": imported }),
    )
}

pub(in crate::api) fn create_config(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerCreate {
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn update_config(cfg: &Config, name: &str, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerUpdate {
            name: name.to_string(),
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn delete_config(cfg: &Config, name: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::ListenerDelete {
            name: name.to_string(),
        },
    )
}

fn persisted_listeners(cfg: &Config) -> anyhow::Result<Vec<ListenerConfigResource>> {
    let fallback = || {
        coalesce_listener_resources(
            cfg.file
                .listeners
                .iter()
                .map(ListenerConfigResource::from)
                .collect(),
        )
    };
    let Ok(repository) = crate::storage::repository() else {
        return Ok(fallback());
    };
    let Some(payload) = repository.get("listeners", "config")? else {
        let value = fallback();
        if !value.is_empty() {
            repository.put(
                "listeners",
                "config",
                crate::storage::next_revision(),
                serde_json::to_string(&value).context("encoding listeners")?,
            )?;
        }
        return Ok(value);
    };
    serde_json::from_str(&payload).context("parsing stored listeners")
}

pub(crate) fn load_for_runtime(cfg: &Config) -> anyhow::Result<Vec<Listener>> {
    Ok(persisted_listeners(cfg)?
        .into_iter()
        .map(Into::into)
        .collect())
}

fn save_persisted_listeners(listeners: &[ListenerConfigResource]) -> anyhow::Result<()> {
    let repository = crate::storage::repository()?;
    repository.put(
        "listeners",
        "config",
        crate::storage::next_revision(),
        serde_json::to_string(listeners).context("encoding listeners")?,
    )?;
    Ok(())
}

fn upsert_persisted_listener(
    cfg: &Config,
    listener: &Listener,
    old_name: Option<&str>,
) -> anyhow::Result<()> {
    let mut listeners = persisted_listeners(cfg)?;
    if let Some(old_name) = old_name {
        listeners.retain(|item| item.name != old_name);
    }
    let resource = ListenerConfigResource::from(listener);
    listeners.retain(|item| item.name != resource.name);
    listeners.push(resource);
    save_persisted_listeners(&listeners)
}

fn delete_persisted_listener(cfg: &Config, name: &str) -> anyhow::Result<()> {
    let mut listeners = persisted_listeners(cfg)?;
    listeners.retain(|item| item.name != name);
    save_persisted_listeners(&listeners)
}

pub(in crate::api) fn create_config_local(cfg: &Config, body: &str) -> Reply {
    match normalize_listener_body(cfg, body, None) {
        Ok(listener) => {
            if let Err(e) = crate::provider::native::create_or_update_listener(cfg, &listener) {
                return Reply::error(500, format!("applying listener datapath: {e:#}"));
            }
            if let Err(e) = upsert_persisted_listener(cfg, &listener, None) {
                return Reply::error(500, format!("persisting listener: {e:#}"));
            }
            Reply::json(
                201,
                serde_json::to_value(ListenerConfigResource::from(&listener)).unwrap(),
            )
        }
        Err(e) => Reply::error(400, e),
    }
}

pub(in crate::api) fn update_config_local(cfg: &Config, name: &str, body: &str) -> Reply {
    match normalize_listener_body(cfg, body, Some(name)) {
        Ok(listener) => {
            if let Err(e) = crate::provider::native::delete_listener(cfg, name) {
                return Reply::error(500, format!("removing old listener datapath: {e:#}"));
            }
            if let Err(e) = crate::provider::native::create_or_update_listener(cfg, &listener) {
                return Reply::error(500, format!("applying listener datapath: {e:#}"));
            }
            if let Err(e) = upsert_persisted_listener(cfg, &listener, Some(name)) {
                return Reply::error(500, format!("persisting listener: {e:#}"));
            }
            Reply::json(
                200,
                serde_json::to_value(ListenerConfigResource::from(&listener)).unwrap(),
            )
        }
        Err(e) => Reply::error(400, e),
    }
}

pub(in crate::api) fn delete_config_local(cfg: &Config, name: &str) -> Reply {
    match crate::provider::native::delete_listener(cfg, name) {
        Ok(true) => {
            if let Err(error) = delete_persisted_listener(cfg, name) {
                return Reply::error(500, format!("persisting listener deletion: {error:#}"));
            }
            Reply::json(
                200,
                serde_json::json!({ "status": "deleted", "name": name }),
            )
        }
        Ok(false) => Reply::error(404, format!("no listener {name}")),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn create_or_replace_config_local(cfg: &Config, body: &str) -> Reply {
    match normalize_listener_body(cfg, body, None) {
        Ok(listener) => update_config_local(
            cfg,
            &listener.name,
            &serde_json::to_string(&ListenerConfigResource::from(&listener)).unwrap_or_default(),
        ),
        Err(e) => Reply::error(400, e),
    }
}

fn normalize_listener_body(
    cfg: &Config,
    body: &str,
    old_name: Option<&str>,
) -> Result<Listener, String> {
    let resource: ListenerConfigResource =
        serde_json::from_str(body).map_err(|e| format!("bad listener config JSON: {e}"))?;
    let listener: Listener = resource.into();
    validate_listener_config(cfg, &listener, old_name)
        .map_err(|e| format!("invalid listener config: {e:#}"))?;
    Ok(listener)
}

fn validate_listener_config(
    cfg: &Config,
    listener: &Listener,
    old_name: Option<&str>,
) -> anyhow::Result<()> {
    if listener.name.trim().is_empty() {
        bail!("listener name is required");
    }
    if listener.port == 0 {
        bail!("listener port must be in range 1..=65535");
    }
    if listener.target_port == 0 {
        bail!("listener target port must be in range 1..=65535");
    }
    if listener.protocols.is_empty() {
        bail!("listener must select at least one protocol");
    }
    let groups =
        crate::provider::native::target_groups_native(cfg).context("loading target groups")?;
    if !groups
        .iter()
        .any(|group| group.name == listener.target_group)
    {
        bail!("target group {} not found", listener.target_group);
    }

    let existing = persisted_listeners(cfg)?;
    for item in &existing {
        if old_name.is_some_and(|old| item.name == old) {
            continue;
        }
        if listener_resource_conflicts(cfg, item, &ListenerConfigResource::from(listener))? {
            bail!(
                "listener {} conflicts with existing listener {} on port {}",
                listener.name,
                item.name,
                listener.port
            );
        }
    }
    Ok(())
}

fn native_generated_listener_name(protocol: &str, port: u16) -> String {
    format!("{protocol}-{port}")
}

fn listener_resource_conflicts(
    cfg: &Config,
    existing: &ListenerConfigResource,
    want: &ListenerConfigResource,
) -> anyhow::Result<bool> {
    if existing.port != want.port {
        return Ok(false);
    }
    if !existing
        .protocols
        .iter()
        .any(|protocol| want.protocols.contains(protocol))
    {
        return Ok(false);
    }
    let existing_ips = effective_listener_ips(cfg, existing)?;
    let want_ips = effective_listener_ips(cfg, want)?;
    Ok(existing_ips.iter().any(|ip| want_ips.contains(ip)))
}

fn effective_listener_ips(
    cfg: &Config,
    resource: &ListenerConfigResource,
) -> anyhow::Result<HashSet<IpAddr>> {
    crate::provider::native::effective_vip_ips(cfg, &resource.vip_ips)
        .map(|ips| ips.into_iter().map(IpAddr::V4).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FileConfig};
    use std::path::PathBuf;

    fn test_cfg() -> Config {
        Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig::default(),
        }
    }

    #[test]
    fn empty_target_group_can_back_a_listener_before_backend_registration() {
        let mut cfg = test_cfg();
        cfg.file.node_role = crate::config::NodeRole::Gateway;
        cfg.file.target_groups.push(crate::config::TargetGroup {
            name: "pending".to_string(),
            ..crate::config::TargetGroup::default()
        });
        let listener = Listener {
            name: "tcp-8080".to_string(),
            port: 8080,
            target_port: 18080,
            target_group: "pending".to_string(),
            protocols: vec![Protocol::Tcp],
            ..Listener::default()
        };

        validate_listener_config(&cfg, &listener, None)
            .expect("empty target groups must not block listener creation");
    }

    #[test]
    fn empty_external_ip_list_preserves_automatic_vip_expansion() {
        let resource = ListenerConfigResource {
            name: String::new(),
            vip_ips: Vec::new(),
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert!(listener.vip_ips.is_empty());
        assert_eq!(listener.name, "tcp-8080");
    }

    #[test]
    fn listener_name_is_always_generated_from_protocol_and_port() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.name, "tcp-8080");
    }

    #[test]
    fn auto_listener_name_is_preserved_for_generated_listeners() {
        let resource = ListenerConfigResource {
            name: "auto-stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.name, "auto-tcp-8080");
    }

    #[test]
    fn listener_protocols_are_normalized_and_deduplicated() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Udp, Protocol::Tcp, Protocol::Udp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.protocols, vec![Protocol::Udp, Protocol::Tcp]);
        assert_eq!(listener.name, "udp-tcp-8080");
    }

    #[test]
    fn combined_protocol_listener_keeps_one_generated_name() {
        let resource = ListenerConfigResource {
            name: "stale-name".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port: 8080,
            target_port: 18080,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let listener: Listener = resource.into();

        assert_eq!(listener.protocols, vec![Protocol::Tcp, Protocol::Udp]);
        assert_eq!(listener.name, "tcp-udp-8080");
    }

    #[test]
    fn listener_conflict_uses_socket_identity_not_name_only() {
        let cfg = test_cfg();
        let resource = |port: u16| ListenerConfigResource {
            name: "tcp-80".to_string(),
            vip_ips: vec!["192.168.0.12".parse().unwrap()],
            port,
            target_port: 8080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };
        let existing = resource(80);
        let same_name_other_port = resource(81);
        let same_socket_other_name = ListenerConfigResource {
            name: "old".to_string(),
            ..resource(80)
        };

        assert!(!listener_resource_conflicts(&cfg, &existing, &same_name_other_port).unwrap());
        assert!(listener_resource_conflicts(&cfg, &existing, &same_socket_other_name).unwrap());
    }

    #[test]
    fn listener_resource_round_trip_preserves_protocols_and_empty_vips() {
        let resource = ListenerConfigResource {
            name: "tcp-udp-443".to_string(),
            vip_ips: Vec::new(),
            port: 443,
            target_port: 8443,
            protocols: vec![Protocol::Tcp, Protocol::Udp],
            target_group: "tls-targets".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };

        let listener: Listener = resource.into();
        let restored = ListenerConfigResource::from(&listener);

        assert_eq!(restored.name, "tcp-udp-443");
        assert_eq!(restored.protocols, vec![Protocol::Tcp, Protocol::Udp]);
        assert!(restored.vip_ips.is_empty());
        assert_eq!(restored.target_port, 8443);
    }

    #[test]
    fn listener_resources_merge_vips_without_merging_different_listeners() {
        let resource = |vip: &str, port: u16| ListenerConfigResource {
            name: "tcp-80".to_string(),
            vip_ips: vec![vip.parse().unwrap()],
            port,
            target_port: 8080,
            protocols: vec![Protocol::Tcp],
            target_group: "web".to_string(),
            select: LbSelect::Hash,
            inactive_timeout: Some(60),
        };

        let result = coalesce_listener_resources(vec![
            resource("192.0.2.10", 80),
            resource("192.0.2.11", 80),
            resource("192.0.2.12", 81),
        ]);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].vip_ips.len(), 2);
        assert_eq!(result[1].port, 81);
    }
}
