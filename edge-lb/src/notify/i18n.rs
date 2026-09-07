//! Reader-facing notification text.

use crate::events::{EdgeEvent, Severity};

pub fn render(event: &EdgeEvent, lang: &str) -> (String, String) {
    if lang.eq_ignore_ascii_case("en") {
        return (event.title.clone(), event.text.clone());
    }
    let prefix = match event.severity {
        Severity::Info => "通知",
        Severity::Warning => "告警",
        Severity::Critical => "严重告警",
    };
    (
        format!("Edge LB {prefix}: {}", event.title),
        format!(
            "{}\n\n节点: {}\n角色: {}\n事件: {}",
            event.text, event.node, event.role, event.kind
        ),
    )
}

pub fn marker(event: &EdgeEvent) -> &'static str {
    match event.severity {
        Severity::Info => "[INFO]",
        Severity::Warning => "[WARN]",
        Severity::Critical => "[CRIT]",
    }
}

pub fn feishu_template(event: &EdgeEvent) -> &'static str {
    match event.severity {
        Severity::Info => "blue",
        Severity::Warning => "orange",
        Severity::Critical => "red",
    }
}

pub fn wecom_color(event: &EdgeEvent) -> &'static str {
    match event.severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "warning",
    }
}
