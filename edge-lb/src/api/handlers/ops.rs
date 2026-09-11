use serde_json::json;

use crate::{
    api::response::Reply,
    config::Config,
    role::{
        backend,
        gateway::{self, ApplyOptions, CleanupOptions},
    },
};

pub(in crate::api) fn apply(cfg: &Config) -> Reply {
    match cfg.node_role {
        crate::config::NodeRole::Backend => match backend::apply(cfg) {
            Ok(()) => Reply::json(200, json!({ "status": "applied" })),
            Err(e) => Reply::error(500, format!("{e:#}")),
        },
        crate::config::NodeRole::Gateway => match gateway::apply(cfg, &ApplyOptions::default()) {
            Ok(()) => Reply::json(200, json!({ "status": "applied" })),
            Err(e) => Reply::error(500, format!("{e:#}")),
        },
    }
}

pub(in crate::api) fn cleanup(cfg: &Config) -> Reply {
    match cfg.node_role {
        crate::config::NodeRole::Backend => match backend::cleanup(cfg) {
            Ok(()) => Reply::json(200, json!({ "status": "cleaned" })),
            Err(e) => Reply::error(500, format!("{e:#}")),
        },
        crate::config::NodeRole::Gateway => match gateway::cleanup(
            cfg,
            &CleanupOptions {
                rules: true,
                datapath: false,
            },
        ) {
            Ok(()) => Reply::json(200, json!({ "status": "cleaned" })),
            Err(e) => Reply::error(500, format!("{e:#}")),
        },
    }
}
