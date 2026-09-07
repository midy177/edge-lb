use serde_json::json;

use crate::{
    api::response::Reply,
    config::{Config, FileConfig},
    role::{
        backend,
        gateway::{self, ApplyOptions},
    },
};

pub(in crate::api) fn put_config(cfg: &Config, path: &std::path::Path, body: &str) -> Reply {
    let mut new_file: FileConfig = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return Reply::error(400, format!("bad config JSON: {e}")),
    };
    if let Err(e) = crate::runtime::discovery::resolve_auto_ips(&mut new_file) {
        return Reply::error(400, format!("IP auto discovery failed: {e:#}"));
    }
    if let Err(e) = new_file.validate() {
        return Reply::error(400, format!("invalid config: {e:#}"));
    }
    if new_file.api.auth_token.is_none() {
        new_file.api.auth_token = cfg.api.auth_token.clone();
    }
    if let Err(e) = new_file.save_user_atomic(path) {
        return Reply::error(500, format!("{e:#}"));
    }
    spawn_reconcile(path, &new_file);
    Reply::json(200, json!({ "status": "saved and reconciling" }))
}

fn spawn_reconcile(path: &std::path::Path, file: &FileConfig) {
    let path = path.to_path_buf();
    let file = file.clone();
    std::thread::Builder::new()
        .name("edge-lb-reconcile".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            let cfg = Config { path, file };
            let result = match cfg.node_role {
                crate::config::NodeRole::Backend => backend::apply(&cfg),
                crate::config::NodeRole::Gateway => gateway::apply(&cfg, &ApplyOptions::default()),
            };
            match result {
                Ok(()) => tracing::info!("[api] reconcile done"),
                Err(e) => tracing::error!("[api] reconcile failed: {e:#}"),
            }
        })
        .expect("spawn reconcile thread");
}
