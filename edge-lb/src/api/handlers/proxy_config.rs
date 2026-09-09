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

pub(super) fn mutation_error(error: crate::storage::proxy_config::MutationError) -> Reply {
    use crate::storage::proxy_config::MutationError;
    match error {
        MutationError::Rejected(error) => Reply::error(error.status, error.message),
        MutationError::Storage(error) => {
            Reply::error(500, format!("committing proxy configuration: {error:#}"))
        }
        MutationError::Contended => Reply::error(
            409,
            "proxy configuration changed concurrently; retry the operation",
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(in crate::api) enum ProxyConfigOperation {
    ListenerImport { body: String },
    TargetGroupImport { body: String },
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
    let snapshot = match serde_json::from_str::<crate::storage::proxy_replication::Snapshot>(body) {
        Ok(value) => value,
        Err(error) => return Reply::error(400, format!("bad proxy snapshot JSON: {error}")),
    };
    match crate::storage::proxy_replication::receive(cfg, &snapshot) {
        Ok(receipt) => Reply::json(200, serde_json::to_value(receipt).unwrap()),
        Err(error) => mutation_error(error),
    }
}

pub(in crate::api) fn sync_status(cfg: &Config) -> Reply {
    match crate::storage::proxy_replication::status(cfg) {
        Ok(status) => Reply::json(200, serde_json::to_value(status).unwrap()),
        Err(error) => Reply::error(500, format!("reading proxy replication status: {error:#}")),
    }
}

fn apply_as_master(
    cfg: &Config,
    op: ProxyConfigOperation,
    peer: Option<ha::GatewayHaPeer>,
) -> Reply {
    let reply = invoke_local(cfg, &op);
    if (200..300).contains(&reply.status) && peer.is_some() {
        // The mutation has already committed the canonical pair and durable
        // replication cursor. No peer network operation is needed to accept it.
        return accepted_reply(
            reply,
            &cfg.node_name,
            crate::storage::proxy_replication::status(cfg).ok(),
        );
    }
    reply
}

fn accepted_reply(
    reply: Reply,
    authority: &str,
    cursor: Option<crate::storage::proxy_replication::SyncState>,
) -> Reply {
    let mut body: serde_json::Value =
        serde_json::from_slice(&reply.body).expect("local JSON reply");
    body["sync"] = serde_json::json!({
        "state": "accepted",
        "authority": authority,
        "authority_committed": true,
        "replica_confirmed": false,
    });
    // A post-commit visibility barrier may include a later concurrent write.
    // Failure to read it must not turn an already committed write into an error.
    if let Some(cursor) = cursor
        && cursor.source == authority
        && cursor.sequence > 0
        && !cursor.pairing_id.is_empty()
    {
        body["sync"]["barrier"] = serde_json::json!({
            "sequence": cursor.sequence,
            "source": cursor.source,
            "pairing_id": cursor.pairing_id,
            "content_hash": cursor.content_hash,
        });
    }
    Reply::json(202, body)
}

fn forward_to_master(cfg: &Config, peer: &ha::GatewayHaPeer, op: &ProxyConfigOperation) -> Reply {
    match ha_write::post_peer_json(cfg, peer, "/api/v1/ha/peer/proxy-config/active", op) {
        Ok(response) => Reply::json_bytes(response.status, response.body.into_bytes()),
        Err(e) => Reply::error(
            502,
            format!(
                "forwarding proxy write to MASTER {} failed; commit outcome is unknown: {e:#}",
                peer.name
            ),
        ),
    }
}

fn invoke_local(cfg: &Config, op: &ProxyConfigOperation) -> Reply {
    match op {
        ProxyConfigOperation::ListenerImport { body } => {
            super::listeners::import_configs_local(cfg, body)
        }
        ProxyConfigOperation::TargetGroupImport { body } => {
            super::target_groups::import_target_groups_local(cfg, body)
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::proxy_replication::SyncState;
    use serde_json::json;

    #[test]
    fn accepted_write_exposes_visibility_barrier_without_claiming_replica_ack() {
        let reply = accepted_reply(
            Reply::json(201, json!({"name": "tcp-80", "port": 80})),
            "gateway-a",
            Some(SyncState {
                sequence: 7,
                source: "gateway-a".into(),
                pairing_id: "pair-1".into(),
                content_hash: "hash-7".into(),
                pending: false,
                last_error: None,
            }),
        );
        assert_eq!(reply.status, 202);
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["name"], "tcp-80");
        assert_eq!(body["sync"]["authority_committed"], true);
        assert_eq!(body["sync"]["replica_confirmed"], false);
        assert_eq!(
            body["sync"]["barrier"],
            json!({
                "sequence": 7, "source": "gateway-a", "pairing_id": "pair-1", "content_hash": "hash-7"
            })
        );
    }

    #[test]
    fn missing_or_foreign_cursor_does_not_turn_committed_write_into_failure() {
        for cursor in [
            None,
            Some(SyncState::default()),
            Some(SyncState {
                sequence: 8,
                source: "gateway-b".into(),
                pairing_id: "pair-1".into(),
                content_hash: "hash-8".into(),
                pending: false,
                last_error: None,
            }),
        ] {
            let reply = accepted_reply(
                Reply::json(200, json!({"status": "ok"})),
                "gateway-a",
                cursor,
            );
            assert_eq!(reply.status, 202);
            let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["sync"]["authority_committed"], true);
            assert!(body["sync"].get("barrier").is_none());
        }
    }
}
