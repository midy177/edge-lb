use anyhow::{Context, Result};
use tiny_http::Method;

use crate::{
    api::{handlers, response::Reply},
    config::{Config, FileConfig},
};

#[derive(Clone, Copy, Default)]
pub(in crate::api) struct LoadOptions {
    pub hydrate_proxy: bool,
    pub merge_backend_subscriptions: bool,
}

pub(in crate::api) fn route(
    method: &Method,
    path: &str,
    body: &str,
    cfg: &Config,
    config_path: &std::path::Path,
) -> Reply {
    if !path.starts_with("/api/v1/") {
        return Reply::error(404, "API path must use /api/v1");
    }
    let Some(canonical) = canonical_path(path) else {
        return Reply::error(404, format!("unknown API path: {path}"));
    };
    let path = canonical.as_str();
    match (method, path) {
        (Method::Get, "/api/status") => handlers::status::status(cfg),
        (Method::Get, "/api/config") => Reply::json(200, serde_json::to_value(&cfg.file).unwrap()),
        (Method::Put, "/api/config") => handlers::config::put_config(cfg, config_path, body),
        (Method::Get, "/api/target-groups") => handlers::target_groups::target_groups(cfg),
        (Method::Get, "/api/target-groups/export") => {
            handlers::target_groups::export_target_groups(cfg)
        }
        (Method::Post, "/api/target-groups/import") => {
            handlers::target_groups::import_target_groups(cfg, body)
        }
        (Method::Post, "/api/target-groups") => {
            handlers::target_groups::create_target_group(cfg, body)
        }
        (Method::Put, path) if path.starts_with("/api/target-groups/") => {
            handlers::target_groups::update_target_group(
                cfg,
                path.trim_start_matches("/api/target-groups/"),
                body,
            )
        }
        (Method::Delete, path) if path.starts_with("/api/target-groups/") => {
            handlers::target_groups::delete_target_group(
                cfg,
                path.trim_start_matches("/api/target-groups/"),
            )
        }
        (Method::Get, "/api/listener-configs") => handlers::listeners::list_configs(cfg),
        (Method::Get, "/api/listener-configs/export") => handlers::listeners::export_configs(cfg),
        (Method::Post, "/api/listener-configs/import") => {
            handlers::listeners::import_configs(cfg, body)
        }
        (Method::Post, "/api/listener-configs") => handlers::listeners::create_config(cfg, body),
        (Method::Get, "/api/gateway-nodes") => handlers::nodes::gateway_nodes(cfg),
        (Method::Get, "/api/backend-nodes") => handlers::nodes::backend_nodes(cfg),
        (Method::Get, "/api/control-backend-subscriptions") => {
            handlers::nodes::control_backend_subscriptions()
        }
        (Method::Post, "/api/apply") => handlers::ops::apply(cfg),
        (Method::Post, "/api/cleanup") => handlers::ops::cleanup(cfg),
        (Method::Post, "/api/failover") => handlers::ops::failover(cfg, body),
        (Method::Post, "/api/verify") => handlers::ops::verify(cfg),
        (Method::Get, "/api/ha/config") => handlers::ha::get_config(cfg),
        (Method::Put, "/api/ha/config") => handlers::ha::put_config(cfg, body),
        (Method::Get, "/api/ha/status") => handlers::ha::status(cfg),
        (Method::Get, "/api/ha/peer/status") => handlers::ha::peer_status(cfg),
        (Method::Post, "/api/ha/peer/activate") => handlers::ha::peer_activate(cfg, body),
        (Method::Put, "/api/ha/peer/notifications/active") => {
            handlers::notifications::peer_replace_active(cfg, body)
        }
        (Method::Put, "/api/ha/peer/notifications/replica") => {
            handlers::notifications::peer_replace_replica(cfg, body)
        }
        (Method::Post, "/api/ha/peer/proxy-config/active") => {
            handlers::proxy_config::peer_apply_active(cfg, body)
        }
        (Method::Post, "/api/ha/peer/proxy-config/replica") => {
            handlers::proxy_config::peer_apply_replica(cfg, body)
        }
        (Method::Post, "/api/ha/pair") => handlers::ha::pair(cfg, body),
        (Method::Delete, "/api/ha/pair") => handlers::ha::unpair(cfg),
        (Method::Post, "/api/ha/failover") => handlers::ha::failover(cfg, body),
        (Method::Post, "/api/ha/refresh-datapath") => handlers::ha::refresh_native_datapath(cfg),
        (Method::Get, "/api/notifications") => handlers::notifications::list(cfg),
        (Method::Put, "/api/notifications") => handlers::notifications::replace_config(cfg, body),
        (Method::Post, "/api/notifications") => handlers::notifications::save(cfg, body),
        (Method::Get, "/api/automation-templates") => handlers::automations::list(cfg),
        (Method::Post, "/api/automation-templates") => handlers::automations::create(cfg, body),
        (Method::Get, "/api/automation-templates/export") => handlers::automations::export(cfg),
        (Method::Post, "/api/automation-templates/import") => {
            handlers::automations::import(cfg, body)
        }
        (Method::Put, "/api/ha/peer/automation-templates/active") => {
            handlers::automations::peer_replace_active(cfg, body)
        }
        (Method::Put, "/api/ha/peer/automation-templates/replica") => {
            handlers::automations::peer_replace_replica(cfg, body)
        }
        (Method::Get, "/api/metrics") => handlers::status::metrics(cfg),
        _ => route_named(method, path, body, cfg),
    }
}

pub(in crate::api) fn load_options(method: &Method, path: &str) -> LoadOptions {
    let Some(canonical) = canonical_path(path) else {
        return LoadOptions::default();
    };
    let path = canonical.as_str();
    let proxy_read = matches!(
        (method, path),
        (Method::Get, "/api/target-groups")
            | (Method::Get, "/api/listener-configs")
            | (Method::Get, "/api/ha/status")
    );
    let peer_write = path.starts_with("/api/ha/peer/proxy-config")
        || path.starts_with("/api/ha/peer/automation-templates")
        || path.starts_with("/api/ha/peer/notifications");
    let proxy_write = matches!(method, Method::Post | Method::Put | Method::Delete)
        && (path.starts_with("/api/listener-configs")
            || path.starts_with("/api/target-groups")
            || path.starts_with("/api/automation-templates"))
        && !peer_write;
    let needs_backend_subscriptions = matches!(
        (method, path),
        (Method::Get, "/api/backend-nodes")
            | (Method::Post, "/api/apply")
            | (Method::Post, "/api/ha/refresh-datapath")
            | (Method::Post, "/api/verify")
    );

    LoadOptions {
        hydrate_proxy: proxy_read || proxy_write,
        merge_backend_subscriptions: needs_backend_subscriptions || proxy_read || proxy_write,
    }
}

/// The public entry point accepts only the current `/api/v1` resource surface.
/// Handler names are internal implementation details and are not public aliases.
fn canonical_path(path: &str) -> Option<String> {
    let rest = path.strip_prefix("/api/v1")?;
    if rest.is_empty() {
        return None;
    }
    if rest == "/automations" {
        return Some("/api/automation-templates".to_string());
    }
    if let Some(tail) = rest.strip_prefix("/automations/") {
        return Some(format!("/api/automation-templates/{tail}"));
    }
    let mapped = match rest {
        "/status" => "/api/status",
        "/config" => "/api/config",
        "/target-groups" => "/api/target-groups",
        "/target-groups/export" => "/api/target-groups/export",
        "/target-groups/import" => "/api/target-groups/import",
        "/listener-configs" => "/api/listener-configs",
        "/listener-configs/export" => "/api/listener-configs/export",
        "/listener-configs/import" => "/api/listener-configs/import",
        "/nodes/gateways" => "/api/gateway-nodes",
        "/nodes/backends" => "/api/backend-nodes",
        "/nodes/backend-subscriptions" => "/api/control-backend-subscriptions",
        "/operations/apply" => "/api/apply",
        "/operations/cleanup" => "/api/cleanup",
        "/operations/failover" => "/api/failover",
        "/operations/verify" => "/api/verify",
        "/ha/config" => "/api/ha/config",
        "/ha/status" => "/api/ha/status",
        "/ha/peer/status" => "/api/ha/peer/status",
        "/ha/peer/activate" => "/api/ha/peer/activate",
        "/ha/peer/notifications/active" => "/api/ha/peer/notifications/active",
        "/ha/peer/notifications/replica" => "/api/ha/peer/notifications/replica",
        "/ha/peer/proxy-config/active" => "/api/ha/peer/proxy-config/active",
        "/ha/peer/proxy-config/replica" => "/api/ha/peer/proxy-config/replica",
        "/ha/peer/automation-templates/active" => "/api/ha/peer/automation-templates/active",
        "/ha/peer/automation-templates/replica" => "/api/ha/peer/automation-templates/replica",
        "/ha/pair" => "/api/ha/pair",
        "/ha/failover" => "/api/ha/failover",
        "/ha/refresh-datapath" => "/api/ha/refresh-datapath",
        "/notifications" => "/api/notifications",
        "/metrics" => "/api/metrics",
        _ => {
            if rest.starts_with("/target-groups/")
                || rest.starts_with("/listener-configs/")
                || rest.starts_with("/notifications/")
            {
                return Some(format!("/api{rest}"));
            }
            return None;
        }
    };
    Some(mapped.to_string())
}

pub(in crate::api) fn load_config(
    config_path: &std::path::Path,
    opts: LoadOptions,
) -> Result<Config> {
    let mut file = FileConfig::load_file(config_path)?.unwrap_or_default();
    crate::runtime::discovery::resolve_auto_ips(&mut file)?;
    crate::runtime::ha::merge_gateway_peers_best_effort(&mut file);
    let mut cfg = Config {
        path: config_path.to_path_buf(),
        file,
    };
    if matches!(cfg.node_role, crate::config::NodeRole::Gateway) {
        if opts.merge_backend_subscriptions {
            crate::control::merge_active_backend_subscriptions(&mut cfg)?;
        }
        if opts.hydrate_proxy {
            crate::provider::native::hydrate_proxy_config_from_api(&mut cfg)
                .context("loading native proxy state")?;
        }
    }
    Ok(cfg)
}

fn route_named(method: &Method, path: &str, body: &str, cfg: &Config) -> Reply {
    if let Some(name) = path.strip_prefix("/api/listener-configs/") {
        if name == "export" {
            return Reply::error(405, "method not allowed");
        }
        return match method {
            Method::Put => handlers::listeners::update_config(cfg, name, body),
            Method::Delete => handlers::listeners::delete_config(cfg, name),
            _ => Reply::error(405, "method not allowed"),
        };
    }
    if let Some(rest) = path.strip_prefix("/api/notifications/") {
        if let Some(id) = rest.strip_suffix("/test") {
            return match method {
                Method::Post => handlers::notifications::test(cfg, id),
                _ => Reply::error(405, "method not allowed"),
            };
        }
        return match method {
            Method::Get => handlers::notifications::get(cfg, rest),
            Method::Put => handlers::notifications::save(cfg, body),
            Method::Delete => handlers::notifications::delete(cfg, rest),
            _ => Reply::error(405, "method not allowed"),
        };
    }
    if let Some(rest) = path.strip_prefix("/api/automation-templates/") {
        if rest == "export" || rest == "import" {
            return Reply::error(405, "method not allowed");
        }
        if let Some(name) = rest.strip_suffix("/test") {
            return match method {
                Method::Post => handlers::automations::test(cfg, name, body),
                _ => Reply::error(405, "method not allowed"),
            };
        }
        return match method {
            Method::Put => handlers::automations::update(cfg, rest, body),
            Method::Delete => handlers::automations::delete(cfg, rest),
            _ => Reply::error(405, "method not allowed"),
        };
    }
    Reply::error(404, format!("no such API path: {path}"))
}

#[cfg(test)]
mod tests {
    use super::canonical_path;

    #[test]
    fn v1_listener_config_paths_dispatch_to_listener_config_handlers() {
        assert_eq!(
            canonical_path("/api/v1/listener-configs"),
            Some("/api/listener-configs".to_string())
        );
        assert_eq!(
            canonical_path("/api/v1/listener-configs/tcp-80"),
            Some("/api/listener-configs/tcp-80".to_string())
        );
        assert_eq!(
            canonical_path("/api/v1/listener-configs/export"),
            Some("/api/listener-configs/export".to_string())
        );
    }

    #[test]
    fn v1_public_resources_are_normalized() {
        assert_eq!(
            canonical_path("/api/v1/automations"),
            Some("/api/automation-templates".to_string())
        );
        assert_eq!(
            canonical_path("/api/v1/nodes/backends"),
            Some("/api/backend-nodes".to_string())
        );
        assert_eq!(
            canonical_path("/api/v1/operations/failover"),
            Some("/api/failover".to_string())
        );
        assert_eq!(canonical_path("/api/v1/automation-templates"), None);
        assert_eq!(
            canonical_path("/api/v1/ha/peer/automation-templates/active"),
            Some("/api/ha/peer/automation-templates/active".to_string())
        );
        assert_eq!(canonical_path("/api/v1/ha/peer/automations/active"), None);
        assert_eq!(canonical_path("/api/v1/backend-nodes"), None);
        assert_eq!(canonical_path("/api/v1/apply"), None);
    }

    #[test]
    fn frontend_v1_resource_surface_has_canonical_paths() {
        let paths = [
            "/api/v1/status",
            "/api/v1/target-groups",
            "/api/v1/target-groups/export",
            "/api/v1/target-groups/import",
            "/api/v1/listener-configs",
            "/api/v1/listener-configs/export",
            "/api/v1/listener-configs/tcp-udp-443",
            "/api/v1/nodes/gateways",
            "/api/v1/nodes/backends",
            "/api/v1/nodes/backend-subscriptions",
            "/api/v1/ha/config",
            "/api/v1/ha/status",
            "/api/v1/notifications",
            "/api/v1/automations",
            "/api/v1/operations/apply",
        ];

        for path in paths {
            assert!(
                canonical_path(path).is_some_and(|path| path.starts_with("/api/")),
                "v1 path was not normalized: {path}"
            );
        }
    }
}
