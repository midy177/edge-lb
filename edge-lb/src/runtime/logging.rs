//! Process-wide tracing initialization.

use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init(config_level: &str) {
    let filter = std::env::var("EDGE_LB_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| config_level.to_string());
    let filter = normalize_filter(&filter);
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::registry().with(filter).with(
        fmt::layer()
            .compact()
            .with_target(false)
            .with_thread_ids(false)
            .with_thread_names(false),
    );
    let _ = subscriber.try_init();
}

fn normalize_filter(filter: &str) -> String {
    let filter = filter.trim();
    if filter.is_empty() {
        return default_filter("info");
    }
    if filter.contains('=') || filter.contains(',') {
        return filter.to_string();
    }
    default_filter(filter)
}

fn default_filter(level: &str) -> String {
    format!("{level},netlink_packet_route=error")
}

#[cfg(test)]
mod tests {
    #[test]
    fn simple_log_level_suppresses_noisy_netlink_route_dependency() {
        assert_eq!(
            super::normalize_filter("info"),
            "info,netlink_packet_route=error"
        );
    }

    #[test]
    fn explicit_filter_is_preserved() {
        assert_eq!(
            super::normalize_filter("edge_lb=debug,info"),
            "edge_lb=debug,info"
        );
    }
}
