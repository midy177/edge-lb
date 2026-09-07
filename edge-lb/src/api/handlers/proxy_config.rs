//! HA-aware native proxy configuration writes.

use serde::{Deserialize, Serialize};

use crate::{
    api::response::Reply,
    config::Config,
    runtime::{
        ha,
        ha_write::{self, WriteRole},
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::api) enum ProxyConfigOperation {
    ListenerCreate { body: String },
    ListenerUpdate { name: String, body: String },
    ListenerDelete { name: String },
    TargetGroupCreate { body: String },
    TargetGroupUpdate { name: String, body: String },
    TargetGroupDelete { name: String },
}

pub(in crate::api) fn apply_authoritative(cfg: &Config, op: ProxyConfigOperation) -> Reply {
    match ha_write::write_role(cfg) {
        Ok(WriteRole::LocalMaster(peer)) => apply_as_master(cfg, op, peer),
        Ok(WriteRole::Backup(peer)) => forward_to_master(cfg, &peer, &op),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_apply_active(cfg: &Config, body: &str) -> Reply {
    let op: ProxyConfigOperation = match serde_json::from_str(body) {
        Ok(op) => op,
        Err(e) => return Reply::error(400, format!("bad proxy config operation JSON: {e}")),
    };
    match ha_write::write_role(cfg) {
        Ok(WriteRole::LocalMaster(peer)) => apply_as_master(cfg, op, peer),
        Ok(WriteRole::Backup(_)) => Reply::error(409, "local gateway is not MASTER"),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_apply_replica(cfg: &Config, body: &str) -> Reply {
    let op: ProxyConfigOperation = match serde_json::from_str(body) {
        Ok(op) => op,
        Err(e) => return Reply::error(400, format!("bad proxy config operation JSON: {e}")),
    };
    invoke_replica(cfg, &op)
}

fn apply_as_master(
    cfg: &Config,
    op: ProxyConfigOperation,
    peer: Option<ha::GatewayHaPeer>,
) -> Reply {
    let reply = invoke_local(cfg, &op);
    if !(200..300).contains(&reply.status) {
        return reply;
    }
    let Some(peer) = peer else {
        return reply;
    };
    let replica_op = sanitize_replica_operation(cfg, &op);
    match ha_write::post_peer_json(
        cfg,
        &peer,
        "/api/v1/ha/peer/proxy-config/replica",
        &replica_op,
    ) {
        Ok(response) if (200..300).contains(&response.status) => reply,
        Ok(response) => Reply::error(
            502,
            format!(
                "local native proxy write applied but HA replica sync to {} failed with HTTP {}: {}",
                peer.name, response.status, response.body
            ),
        ),
        Err(e) => Reply::error(
            502,
            format!(
                "local native proxy write applied but HA replica sync to {} failed: {e:#}",
                peer.name
            ),
        ),
    }
}

fn forward_to_master(cfg: &Config, peer: &ha::GatewayHaPeer, op: &ProxyConfigOperation) -> Reply {
    match ha_write::post_peer_json(cfg, peer, "/api/v1/ha/peer/proxy-config/active", op) {
        Ok(response) => Reply::json_bytes(response.status, response.body.into_bytes()),
        Err(e) => Reply::error(
            502,
            format!(
                "forwarding native proxy write to MASTER {} failed: {e:#}",
                peer.name
            ),
        ),
    }
}

fn invoke_local(cfg: &Config, op: &ProxyConfigOperation) -> Reply {
    match op {
        ProxyConfigOperation::ListenerCreate { body } => {
            super::listeners::create_config_local(cfg, body)
        }
        ProxyConfigOperation::ListenerUpdate { name, body } => {
            super::listeners::update_config_local(cfg, name, body)
        }
        ProxyConfigOperation::ListenerDelete { name } => {
            super::listeners::delete_config_local(cfg, name)
        }
        ProxyConfigOperation::TargetGroupCreate { body } => {
            super::target_groups::upsert_target_group_local(cfg, body)
        }
        ProxyConfigOperation::TargetGroupUpdate { name, body } => {
            super::target_groups::upsert_target_group_local(cfg, &target_group_body(name, body))
        }
        ProxyConfigOperation::TargetGroupDelete { name } => {
            super::target_groups::delete_target_group_local(cfg, name)
        }
    }
}

fn invoke_replica(cfg: &Config, op: &ProxyConfigOperation) -> Reply {
    match op {
        ProxyConfigOperation::ListenerCreate { body } => {
            let body = sanitize_replica_listener_body(cfg, body);
            super::listeners::create_or_replace_config_local(cfg, &body)
        }
        ProxyConfigOperation::ListenerUpdate { name, body } => {
            let body = sanitize_replica_listener_body(cfg, body);
            super::listeners::update_config_local(cfg, name, &body)
        }
        ProxyConfigOperation::ListenerDelete { name } => ok_if_missing(
            super::listeners::delete_config_local(cfg, name),
            "listener",
            name,
        ),
        ProxyConfigOperation::TargetGroupCreate { body } => {
            super::target_groups::upsert_target_group_local(cfg, body)
        }
        ProxyConfigOperation::TargetGroupUpdate { name, body } => {
            super::target_groups::upsert_target_group_local(cfg, &target_group_body(name, body))
        }
        ProxyConfigOperation::TargetGroupDelete { name } => ok_if_missing(
            super::target_groups::delete_target_group_local(cfg, name),
            "target group",
            name,
        ),
    }
}

fn sanitize_replica_operation(cfg: &Config, op: &ProxyConfigOperation) -> ProxyConfigOperation {
    match op {
        ProxyConfigOperation::ListenerCreate { body } => ProxyConfigOperation::ListenerCreate {
            body: sanitize_replica_listener_body(cfg, body),
        },
        ProxyConfigOperation::ListenerUpdate { name, body } => {
            ProxyConfigOperation::ListenerUpdate {
                name: name.clone(),
                body: sanitize_replica_listener_body(cfg, body),
            }
        }
        _ => op.clone(),
    }
}

fn target_group_body(name: &str, body: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
    }
    serde_json::to_string(&value).unwrap_or_else(|_| body.to_string())
}

fn ok_if_missing(reply: Reply, object: &str, name: &str) -> Reply {
    if reply.status == 404 {
        Reply::json(
            200,
            serde_json::json!({
                "status": "already_absent",
                "object": object,
                "name": name,
            }),
        )
    } else {
        reply
    }
}

fn sanitize_replica_listener_body(cfg: &Config, body: &str) -> String {
    match sanitize_replica_listener_body_inner(cfg, body) {
        Ok(Some(next)) => next,
        Ok(None) => body.to_string(),
        Err(e) => {
            tracing::warn!("HA replica listener body sanitize skipped: {e:#}");
            body.to_string()
        }
    }
}

fn sanitize_replica_listener_body_inner(
    cfg: &Config,
    body: &str,
) -> anyhow::Result<Option<String>> {
    let ha_cfg = ha::load_for_state_dir(std::path::Path::new(&*cfg.state_dir))?;
    if ha_cfg.peers.is_empty() {
        return Ok(None);
    }

    let mut value: serde_json::Value = serde_json::from_str(body)?;
    // VIP ownership is local HA state. Do not replicate either gateway
    // underlay addresses or the shared L2 VIP through listener writes.
    if clear_replica_listener_vips(&mut value) {
        return Ok(Some(serde_json::to_string(&value)?));
    }

    Ok(None)
}

fn clear_replica_listener_vips(value: &mut serde_json::Value) -> bool {
    let Some(object) = value.as_object_mut() else {
        return false;
    };
    let has_vips = object
        .get("vip_ips")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| !values.is_empty());
    if has_vips {
        object.insert("vip_ips".to_string(), serde_json::Value::Array(Vec::new()));
    }
    has_vips
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replica_listener_vips_are_not_replicated() {
        let mut listener = serde_json::json!({
            "name": "tcp-80",
            "vip_ips": ["192.168.0.12", "192.168.0.6"],
            "port": 80,
            "target_port": 8080,
            "target_group": "web",
            "protocols": ["tcp"]
        });

        assert!(clear_replica_listener_vips(&mut listener));
        assert_eq!(listener.get("vip_ips"), Some(&serde_json::json!([])));
    }

    #[test]
    fn empty_replica_listener_vips_are_left_unchanged() {
        let mut listener = serde_json::json!({
            "name": "tcp-80",
            "vip_ips": [],
            "port": 80,
            "target_port": 8080,
            "target_group": "web",
            "protocols": ["tcp"]
        });

        assert!(!clear_replica_listener_vips(&mut listener));
        assert_eq!(listener.get("vip_ips"), Some(&serde_json::json!([])));
    }
}
