use serde_json::json;

use crate::{api::response::Reply, config::Config};

pub(in crate::api) fn status(cfg: &Config) -> Reply {
    let active = cfg.active_gateway().map(|g| g.name.clone()).ok();
    let overlay_ip = match cfg.node_role {
        crate::config::NodeRole::Gateway => cfg.gateway_cfg().overlay_ip.clone(),
        crate::config::NodeRole::Backend => cfg.backend_cfg().overlay_ip.clone(),
    };
    let mut value = json!({
        "node_role": cfg.node_role,
        "node_name": cfg.node_name,
        "public_ip": cfg.public_ip,
        "underlay_ip": cfg.underlay_ip,
        "overlay_ip": overlay_ip,
        "active_gateway": active,
        "listen": cfg.api.listen,
        "discovery": cfg.file.runtime_discovery,
    });
    let obj = value.as_object_mut().unwrap();
    let n = cfg.network();
    obj.insert(
        "vxlan".into(),
        json!({
        "dev": n.vxlan_dev,
        "underlay_dev": n.underlay_dev,
        "vni": n.vni,
        "vxlan_port": n.vxlan_port,
        "mtu": n.vxlan_mtu,
        "dscp": n.dscp,
        "present": crate::linux::net::link_exists(&n.vxlan_dev),
        "up": crate::linux::net::is_up(&n.vxlan_dev),
        "remote": crate::linux::net::vxlan_remote(&n.vxlan_dev).map(|r| r.to_string()),
        }),
    );
    match cfg.node_role {
        crate::config::NodeRole::Backend => {
            obj.insert(
                "nft_table_present".into(),
                json!(crate::linux::nftables::table_exists(cfg)),
            );
            obj.insert(
                "policy_rule_present".into(),
                json!(crate::linux::route::policy_rule_present(cfg)),
            );
        }
        crate::config::NodeRole::Gateway => {
            obj.insert(
                "native_datapath_attached".into(),
                json!(crate::linux::native_dnat::attached(cfg)),
            );
            obj.insert(
                "dscp_attached".into(),
                json!(crate::linux::dscp::attached(cfg, &n.underlay_dev)),
            );
            if let Ok(stats) = crate::linux::dscp::stats(cfg) {
                obj.insert("dscp_stats".into(), serde_json::to_value(stats).unwrap());
            }
            if let Ok(stats) = crate::linux::native_dnat::stats(cfg) {
                obj.insert(
                    "native_datapath_stats".into(),
                    serde_json::to_value(stats).unwrap(),
                );
            }
        }
    }
    Reply::json(200, value)
}

pub(in crate::api) fn metrics(cfg: &Config) -> Reply {
    let mut text =
        std::fs::read_to_string(std::path::Path::new(&*cfg.state_dir).join("edge-lb-backend.prom"))
            .unwrap_or_default();
    if let Ok(stats) = crate::linux::dscp::stats(cfg) {
        text.push_str(&format!(
            "# TYPE edge_lb_dscp_packets_total counter\n\
             edge_lb_dscp_packets_total{{kind=\"matched\"}} {}\n\
             edge_lb_dscp_packets_total{{kind=\"changed\"}} {}\n",
            stats.matched, stats.changed
        ));
    }
    Reply {
        status: 200,
        content_type: "text/plain; version=0.0.4".into(),
        body: text.into_bytes(),
    }
}
