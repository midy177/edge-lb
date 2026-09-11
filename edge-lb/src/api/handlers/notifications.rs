use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    api::response::Reply,
    config::{Config, NodeRole},
    notify::{
        self,
        model::{NotificationChannel, NotificationConfig},
        store, sync,
    },
};

#[derive(Debug, Deserialize)]
struct ChannelPatch {
    #[serde(default)]
    channel: Option<NotificationChannel>,
}

pub(in crate::api) fn list(cfg: &Config) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    match store::summaries(cfg) {
        Ok(channels) => Reply::json(
            200,
            json!({
                "channels": channels,
                "events": crate::events::all_kinds(),
            }),
        ),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn get(cfg: &Config, id: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    match store::channel(cfg, id) {
        Ok(Some(channel)) => Reply::json(200, serde_json::to_value(channel).unwrap()),
        Ok(None) => Reply::error(404, format!("notification channel {id:?} not found")),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn save(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let channel = match parse_channel(body) {
        Ok(channel) => channel,
        Err(e) => return Reply::error(400, e),
    };
    let config = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    let (config, channel) = match store::upsert_channel_in_config(config, channel) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("{e:#}")),
    };
    match sync::save_authoritative(cfg, &config) {
        Ok(sync) => channel_reply(channel, sync),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn delete(cfg: &Config, id: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let config = match store::load(cfg) {
        Ok(config) => config,
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    let (config, changed) = store::delete_channel_in_config(config, id);
    if !changed {
        return Reply::error(404, format!("notification channel {id:?} not found"));
    }
    match sync::save_authoritative(cfg, &config) {
        Ok(sync) => Reply::json(200, json!({ "status": "deleted", "id": id, "sync": sync })),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

pub(in crate::api) fn test(cfg: &Config, id: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let channel = match store::channel(cfg, id) {
        Ok(Some(channel)) => channel,
        Ok(None) => return Reply::error(404, format!("notification channel {id:?} not found")),
        Err(e) => return Reply::error(500, format!("{e:#}")),
    };
    match notify::send_test(cfg, &channel) {
        Ok(delivery) => {
            let status = if delivery.ok { 200 } else { 502 };
            Reply::json(status, serde_json::to_value(delivery).unwrap())
        }
        Err(e) => Reply::error(502, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_replace_active(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let value: NotificationConfig = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad notification config JSON: {e}")),
    };
    let value = match store::normalize_config(value) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("{e:#}")),
    };
    match sync::save_from_peer_active(cfg, &value) {
        Ok(sync) => Reply::json(200, json!({ "status": "saved", "sync": sync })),
        Err(e) => Reply::error(409, format!("{e:#}")),
    }
}

pub(in crate::api) fn peer_replace_replica(cfg: &Config, body: &str) -> Reply {
    if let Some(reply) = require_gateway(cfg) {
        return reply;
    }
    let value: NotificationConfig = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(e) => return Reply::error(400, format!("bad notification config JSON: {e}")),
    };
    match sync::save_from_peer_replica(cfg, &value) {
        Ok(sync) => Reply::json(200, json!({ "status": "saved", "sync": sync })),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}

fn parse_channel(body: &str) -> Result<NotificationChannel, String> {
    if let Ok(channel) = serde_json::from_str::<NotificationChannel>(body) {
        return Ok(channel);
    }
    let patch: ChannelPatch =
        serde_json::from_str(body).map_err(|e| format!("bad notification channel JSON: {e}"))?;
    patch
        .channel
        .ok_or_else(|| "body must be a notification channel object".to_string())
}

fn channel_reply(channel: NotificationChannel, sync: sync::SyncResult) -> Reply {
    let mut value = serde_json::to_value(channel).unwrap();
    if let Value::Object(map) = &mut value {
        map.insert("sync".to_string(), serde_json::to_value(sync).unwrap());
    }
    Reply::json(200, value)
}

fn require_gateway(cfg: &Config) -> Option<Reply> {
    if matches!(cfg.node_role, NodeRole::Gateway) {
        None
    } else {
        Some(Reply::error(
            403,
            "notification API is only available on gateway nodes",
        ))
    }
}
