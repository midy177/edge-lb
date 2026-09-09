use serde_json::json;

use crate::{
    api::response::Reply,
    config::{Config, TargetGroup},
};

use super::{
    common::require_gateway_role,
    proxy_config::{self, ProxyConfigOperation},
};

pub(in crate::api) fn target_groups(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match target_group_views(cfg) {
        Ok(groups) => Reply::json(200, groups),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

fn target_group_views(cfg: &Config) -> anyhow::Result<serde_json::Value> {
    let groups = crate::provider::native::target_groups_native(cfg)?;
    let health = crate::provider::native::target_health(cfg)?;
    let views = groups
        .into_iter()
        .map(|group| {
            let referenced = cfg
                .listeners
                .iter()
                .any(|listener| listener.target_group == group.name);
            let targets = group
                .targets
                .iter()
                .map(|target| {
                    let address = cfg.resolve_backend_target_address(target).to_string();
                    let health_state = if !referenced {
                        Some("unassociated".to_string())
                    } else {
                        health
                            .iter()
                            .filter(|entry| entry.host_name == address)
                            .find(|entry| health_matches_group(cfg, &group, entry))
                            .and_then(|entry| entry.current_state.as_deref())
                            .map(normalize_health_state)
                            .or_else(|| Some("nok".to_string()))
                    };
                    let mut value = serde_json::to_value(target).unwrap_or_default();
                    if let Some(object) = value.as_object_mut() {
                        object.insert("health".to_string(), serde_json::json!(health_state));
                    }
                    value
                })
                .collect::<Vec<_>>();
            let mut value = serde_json::to_value(group).unwrap_or_default();
            if let Some(object) = value.as_object_mut() {
                object.insert("targets".to_string(), serde_json::Value::Array(targets));
                let group_health = if !referenced {
                    "unassociated"
                } else if object
                    .get("targets")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|items| {
                        !items.is_empty()
                            && items.iter().all(|item| {
                                item.get("health").and_then(serde_json::Value::as_str) == Some("ok")
                            })
                    })
                {
                    "ok"
                } else {
                    "nok"
                };
                object.insert("health".to_string(), json!(group_health));
            }
            value
        })
        .collect::<Vec<_>>();
    Ok(serde_json::Value::Array(views))
}

fn normalize_health_state(state: &str) -> String {
    if matches!(
        state.trim().to_ascii_lowercase().as_str(),
        "ok" | "active" | "up" | "alive"
    ) {
        "ok".to_string()
    } else {
        "nok".to_string()
    }
}

fn health_matches_group(
    cfg: &Config,
    group: &TargetGroup,
    entry: &crate::provider::native::TargetHealthEntry,
) -> bool {
    if entry.target_group != group.name {
        return false;
    }
    let expected_type = group
        .probe_type
        .as_deref()
        .unwrap_or("none")
        .trim()
        .to_ascii_lowercase();
    let actual_type = entry
        .probe_type
        .as_deref()
        .unwrap_or("none")
        .trim()
        .to_ascii_lowercase();
    if expected_type != actual_type {
        return false;
    }

    match group.probe_port {
        Some(port) => entry.probe_port == Some(port),
        None => cfg.listeners.iter().any(|listener| {
            listener.target_group == group.name && entry.probe_port == Some(listener.target_port)
        }),
    }
}

pub(in crate::api) fn export_target_groups(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    match crate::provider::native::target_groups_native(cfg) {
        Ok(groups) => Reply::json(200, json!({ "version": 1, "targetGroups": groups })),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn import_target_groups(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        ProxyConfigOperation::TargetGroupImport {
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn import_target_groups_local(cfg: &Config, body: &str) -> Reply {
    use crate::storage::proxy_config::{Rejection, mutate};
    let value: serde_json::Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad target group import JSON: {e}")),
    };
    let groups = value.get("targetGroups").cloned().unwrap_or(value);
    let groups: Vec<TargetGroup> = match serde_json::from_value(groups) {
        Ok(groups) => groups,
        Err(e) => return Reply::error(400, format!("bad target group import payload: {e}")),
    };
    match mutate(cfg, |state| {
        let mut names = std::collections::HashSet::new();
        for group in &groups {
            if group.name.trim().is_empty() || !names.insert(&group.name) {
                return Err(Rejection::new(
                    400,
                    "empty or duplicate target group name in import",
                ));
            }
            if let Some(existing) = state
                .target_groups
                .iter_mut()
                .find(|item| item.name == group.name)
            {
                *existing = group.clone();
            } else {
                state.target_groups.push(group.clone());
            }
        }
        let mut file = cfg.file.clone();
        file.listeners = state.listeners.clone();
        file.target_groups = state.target_groups.clone();
        file.validate().map_err(|error| {
            Rejection::new(400, format!("invalid target group import: {error:#}"))
        })?;
        Ok(())
    }) {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(200, json!({ "status": "imported", "count": groups.len() }))
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

pub(in crate::api) fn create_target_group(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        proxy_config::ProxyConfigOperation::TargetGroupCreate {
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn update_target_group(cfg: &Config, name: &str, body: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        proxy_config::ProxyConfigOperation::TargetGroupUpdate {
            name: name.to_string(),
            body: body.to_string(),
        },
    )
}

pub(in crate::api) fn delete_target_group(cfg: &Config, name: &str) -> Reply {
    if let Some(reply) = require_gateway_role(cfg) {
        return reply;
    }
    proxy_config::apply_authoritative(
        cfg,
        proxy_config::ProxyConfigOperation::TargetGroupDelete {
            name: name.to_string(),
        },
    )
}

pub(in crate::api) fn upsert_target_group_local(cfg: &Config, body: &str) -> Reply {
    use crate::storage::proxy_config::{Rejection, mutate};
    let group: TargetGroup = match serde_json::from_str(body) {
        Ok(group) => group,
        Err(error) => return Reply::error(400, format!("bad target group JSON: {error}")),
    };
    match mutate(cfg, |state| {
        if group.name.trim().is_empty() {
            return Err(Rejection::new(400, "target group name is required"));
        }
        if let Some(existing) = state
            .target_groups
            .iter_mut()
            .find(|item| item.name == group.name)
        {
            *existing = group.clone();
        } else {
            state.target_groups.push(group.clone());
        }
        let mut file = cfg.file.clone();
        file.listeners = state.listeners.clone();
        file.target_groups = state.target_groups.clone();
        file.validate()
            .map_err(|error| Rejection::new(400, format!("invalid target group: {error:#}")))?;
        Ok(())
    }) {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(200, serde_json::to_value(group).unwrap())
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

pub(in crate::api) fn delete_target_group_local(cfg: &Config, name: &str) -> Reply {
    use crate::storage::proxy_config::{Rejection, mutate};
    match mutate(cfg, |state| {
        if state
            .listeners
            .iter()
            .any(|listener| listener.target_group == name)
        {
            return Err(Rejection::new(
                409,
                format!("target group {name} is still referenced by a listener"),
            ));
        }
        let before = state.target_groups.len();
        state.target_groups.retain(|group| group.name != name);
        if state.target_groups.len() == before {
            return Err(Rejection::new(404, format!("no target group {name}")));
        }
        Ok(())
    }) {
        Ok(((), changed)) => {
            if changed {
                crate::provider::native::mark_state_dirty();
            }
            Reply::json(200, json!({ "status": "deleted", "name": name }))
        }
        Err(error) => proxy_config::mutation_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FileConfig, Listener, Protocol};
    use std::path::PathBuf;

    fn config_with_listener(target_port: u16) -> Config {
        let mut file = FileConfig::default();
        file.listeners.push(Listener {
            name: "tcp-80".to_string(),
            port: 80,
            target_port,
            target_group: "web".to_string(),
            protocols: vec![Protocol::Tcp],
            ..Listener::default()
        });
        Config {
            path: PathBuf::from("/tmp/edge-lb-target-group-test.toml"),
            file,
        }
    }

    #[test]
    fn health_matching_falls_back_to_listener_target_port() {
        let cfg = config_with_listener(8080);
        let group = TargetGroup {
            name: "web".to_string(),
            probe_type: None,
            probe_port: None,
            ..TargetGroup::default()
        };
        let entry = crate::provider::native::TargetHealthEntry {
            target_group: "web".to_string(),
            host_name: "192.0.2.10".to_string(),
            probe_type: Some("none".to_string()),
            probe_port: Some(8080),
            ..Default::default()
        };
        assert!(health_matches_group(&cfg, &group, &entry));
    }

    #[test]
    fn health_matching_keeps_explicit_probe_port() {
        let cfg = config_with_listener(8080);
        let group = TargetGroup {
            name: "web".to_string(),
            probe_type: Some("http".to_string()),
            probe_port: Some(9090),
            ..TargetGroup::default()
        };
        let entry = crate::provider::native::TargetHealthEntry {
            target_group: "web".to_string(),
            host_name: "192.0.2.10".to_string(),
            probe_type: Some("http".to_string()),
            probe_port: Some(9090),
            ..Default::default()
        };
        assert!(health_matches_group(&cfg, &group, &entry));
    }

    #[test]
    fn health_states_are_reduced_to_the_three_api_states() {
        assert_eq!(normalize_health_state("ok"), "ok");
        assert_eq!(normalize_health_state("active"), "ok");
        assert_eq!(normalize_health_state("nok"), "nok");
        assert_eq!(normalize_health_state("unknown"), "nok");
    }
}
