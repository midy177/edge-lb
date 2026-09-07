//! Notification channel configuration and delivery records.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Webhook,
    Dingtalk,
    Feishu,
    Wecom,
    Telegram,
    Slack,
    Pushplus,
    Lanxin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub kind: ChannelKind,
    pub enabled: bool,
    pub events: Vec<String>,
    pub lang: String,
    pub config: Value,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

impl Default for NotificationChannel {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            kind: ChannelKind::Webhook,
            enabled: true,
            events: vec!["*".to_string()],
            lang: "zh".to_string(),
            config: Value::Object(Default::default()),
            created_at_unix: 0,
            updated_at_unix: 0,
        }
    }
}

impl NotificationChannel {
    pub fn matches_event(&self, kind: &str) -> bool {
        self.enabled
            && (self.events.is_empty() || self.events.iter().any(|ev| ev == "*" || ev == kind))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    pub channels: Vec<NotificationChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannelSummary {
    pub id: String,
    pub name: String,
    pub kind: ChannelKind,
    pub enabled: bool,
    pub events: Vec<String>,
    pub lang: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
}

impl From<&NotificationChannel> for NotificationChannelSummary {
    fn from(value: &NotificationChannel) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            kind: value.kind,
            enabled: value.enabled,
            events: value.events.clone(),
            lang: value.lang.clone(),
            created_at_unix: value.created_at_unix,
            updated_at_unix: value.updated_at_unix,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryRecord {
    pub channel_id: String,
    pub channel_name: String,
    pub event_kind: String,
    pub ok: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub response: String,
    pub attempted_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delivery {
    pub ok: bool,
    pub status_code: Option<u16>,
    pub response: String,
}
