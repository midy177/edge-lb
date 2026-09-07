use serde_json::{Value, json};

use crate::{
    api::response::Reply,
    cli::VerifyArgs,
    config::Config,
    role::{
        backend,
        gateway::{self, ApplyOptions, CleanupOptions},
    },
    verify,
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

pub(in crate::api) fn failover(cfg: &Config, body: &str) -> Reply {
    let target: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(e) => return Reply::error(400, format!("bad JSON: {e}")),
    };
    let Some(key) = target.get("gateway").and_then(|v| v.as_str()) else {
        return Reply::error(400, "body must be {\"gateway\": \"<name or underlay ip>\"}");
    };
    match cfg.gateway_by_key(key) {
        Some(gw) => {
            if let Err(e) = cfg.write_active_gateway(&gw.name) {
                return Reply::error(500, format!("{e:#}"));
            }
            if matches!(cfg.node_role, crate::config::NodeRole::Backend)
                && let Err(e) = backend::reconcile_once(cfg)
            {
                return Reply::error(500, format!("switched but reconcile failed: {e:#}"));
            }
            Reply::json(200, json!({ "status": "failed-over", "gateway": gw.name }))
        }
        None => Reply::error(404, format!("unknown gateway {key:?}")),
    }
}

pub(in crate::api) fn verify(cfg: &Config) -> Reply {
    match verify::run_checks(
        cfg,
        &VerifyArgs {
            skip_vip: false,
            skip_backend: false,
            timeout: 5,
            overrides: Default::default(),
        },
    ) {
        Ok(out) => Reply::json(
            200,
            json!({ "vip_ok": out.vip_ok, "backend_ok": out.backend_ok, "detail": out.detail }),
        ),
        Err(e) => Reply::error(500, format!("{e:#}")),
    }
}
