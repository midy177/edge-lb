use crate::{api::response::Reply, config::Config};

pub(in crate::api) fn require_gateway_role(cfg: &Config) -> Option<Reply> {
    if !matches!(cfg.node_role, crate::config::NodeRole::Gateway) {
        return Some(Reply::error(
            400,
            "target groups and listeners are managed by gateway nodes only",
        ));
    }
    None
}
