//! SQLite-backed notification configuration store.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};

use super::model::{
    DeliveryRecord, NotificationChannel, NotificationChannelSummary, NotificationConfig,
};
use crate::{config::Config, events};

const DELIVERY_RESOURCE: &str = "notification_deliveries";
const DELIVERY_HISTORY_LIMIT: usize = 512;

pub fn load(_cfg: &Config) -> Result<NotificationConfig> {
    let repository = crate::storage::repository()?;
    if let Some(payload) = repository.get("notifications", "config")? {
        return serde_json::from_str(&payload).context("parsing stored notification config");
    }
    Ok(NotificationConfig::default())
}

pub fn save(_cfg: &Config, value: &NotificationConfig) -> Result<()> {
    validate_config(value)?;
    let payload = serde_json::to_string(value).context("encoding notification config")?;
    crate::storage::repository()?.put_if_changed(
        "notifications",
        "config",
        crate::storage::next_revision(),
        payload,
    )?;
    Ok(())
}

pub fn summaries(cfg: &Config) -> Result<Vec<NotificationChannelSummary>> {
    Ok(load(cfg)?.channels.iter().map(Into::into).collect())
}

pub fn append_delivery(cfg: &Config, record: &DeliveryRecord) {
    if let Err(e) = append_delivery_inner(cfg, record) {
        tracing::warn!("[notify] recording delivery failed: {e:#}");
    }
}

fn append_delivery_inner(_cfg: &Config, record: &DeliveryRecord) -> Result<()> {
    let revision = crate::storage::next_revision();
    let channel = record.channel_id.trim().replace('/', "-");
    let resource_name = format!("{revision}-{channel}");
    let payload = serde_json::to_string(record).context("encoding delivery record")?;
    let repository = crate::storage::repository()?;
    repository.put(DELIVERY_RESOURCE, &resource_name, revision, payload)?;
    repository.prune_resource(DELIVERY_RESOURCE, DELIVERY_HISTORY_LIMIT)?;
    Ok(())
}

pub fn normalize_config(mut config: NotificationConfig) -> Result<NotificationConfig> {
    let now = events::now_unix();
    for channel in &mut config.channels {
        normalize_channel(channel, now);
    }
    validate_config(&config)?;
    Ok(config)
}

pub fn upsert_channel_in_config(
    mut config: NotificationConfig,
    mut channel: NotificationChannel,
) -> Result<(NotificationConfig, NotificationChannel)> {
    let now = events::now_unix();
    normalize_channel(&mut channel, now);
    match config
        .channels
        .iter_mut()
        .find(|item| item.id == channel.id)
    {
        Some(existing) => {
            channel.created_at_unix = existing.created_at_unix;
            *existing = channel.clone();
        }
        None => config.channels.push(channel.clone()),
    }
    validate_config(&config)?;
    Ok((config, channel))
}

pub fn delete_channel_in_config(
    mut config: NotificationConfig,
    id: &str,
) -> (NotificationConfig, bool) {
    let before = config.channels.len();
    config.channels.retain(|item| item.id != id);
    let changed = before != config.channels.len();
    (config, changed)
}

pub fn channel(cfg: &Config, id: &str) -> Result<Option<NotificationChannel>> {
    Ok(load(cfg)?.channels.into_iter().find(|item| item.id == id))
}

fn new_channel_id(name: &str, now: u64) -> String {
    let mut stem = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    while stem.contains("--") {
        stem = stem.replace("--", "-");
    }
    if stem.is_empty() {
        stem = "channel".to_string();
    }
    format!("{stem}-{now}")
}

fn normalize_channel(channel: &mut NotificationChannel, now: u64) {
    channel.name = channel.name.trim().to_string();
    channel.id = channel.id.trim().to_string();
    if channel.id.is_empty() {
        channel.id = new_channel_id(&channel.name, now);
    }
    channel.events = channel
        .events
        .iter()
        .map(|event| event.trim().to_string())
        .filter(|event| !event.is_empty())
        .collect();
    if channel.created_at_unix == 0 {
        channel.created_at_unix = now;
    }
    channel.updated_at_unix = now;
}

pub fn validate_config(config: &NotificationConfig) -> Result<()> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    for (idx, channel) in config.channels.iter().enumerate() {
        if channel.id.trim().is_empty() {
            bail!("notification channels[{idx}].id is required");
        }
        if !ids.insert(channel.id.trim()) {
            bail!("duplicate notification channel id {:?}", channel.id);
        }
        if channel.name.trim().is_empty() {
            bail!("notification channels[{idx}].name is required");
        }
        if !names.insert(channel.name.trim()) {
            bail!("duplicate notification channel name {:?}", channel.name);
        }
        validate_events(idx, &channel.events)?;
        validate_channel_config(channel).with_context(|| {
            format!(
                "invalid notification channels[{idx}] {:?} config",
                channel.kind
            )
        })?;
    }
    Ok(())
}

fn validate_events(idx: usize, events: &[String]) -> Result<()> {
    for event in events {
        let event = event.trim();
        if event == "*" {
            continue;
        }
        if !crate::events::all_kinds().contains(&event) {
            bail!("notification channels[{idx}].events contains unknown event {event:?}");
        }
    }
    Ok(())
}

fn validate_channel_config(channel: &NotificationChannel) -> Result<()> {
    if !channel.config.is_object() {
        bail!("config must be a JSON object");
    }
    match channel.kind {
        super::model::ChannelKind::Webhook
        | super::model::ChannelKind::Feishu
        | super::model::ChannelKind::Wecom
        | super::model::ChannelKind::Slack
        | super::model::ChannelKind::Lanxin => {
            let url = required_str(&channel.config, "url")?;
            validate_http_url(url)?;
        }
        super::model::ChannelKind::Dingtalk => {
            required_str(&channel.config, "access_token")?;
        }
        super::model::ChannelKind::Telegram => {
            required_str(&channel.config, "bot_token")?;
            required_str(&channel.config, "chat_id")?;
        }
        super::model::ChannelKind::Pushplus => {
            required_str(&channel.config, "token")?;
        }
    }
    Ok(())
}

fn required_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{field} is required"))
}

fn validate_http_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("url is invalid")?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => bail!("url scheme {scheme:?} is not supported"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::notify::model::{ChannelKind, NotificationChannel, NotificationConfig};

    fn channel() -> NotificationChannel {
        NotificationChannel {
            id: "webhook-1".to_string(),
            name: "webhook".to_string(),
            kind: ChannelKind::Webhook,
            enabled: true,
            events: vec!["ha_switchover_succeeded".to_string()],
            lang: "zh".to_string(),
            config: json!({ "url": "https://example.com/hook" }),
            created_at_unix: 1,
            updated_at_unix: 1,
        }
    }

    #[test]
    fn normalize_config_fills_identity_and_timestamps() {
        let cfg = NotificationConfig {
            channels: vec![NotificationChannel {
                id: " ".to_string(),
                name: " Ops Webhook ".to_string(),
                config: json!({ "url": "https://example.com/hook" }),
                ..NotificationChannel::default()
            }],
        };

        let normalized = normalize_config(cfg).expect("normalize config");

        assert!(normalized.channels[0].id.starts_with("ops-webhook-"));
        assert_eq!(normalized.channels[0].name, "Ops Webhook");
        assert!(normalized.channels[0].created_at_unix > 0);
        assert!(normalized.channels[0].updated_at_unix > 0);
    }

    #[test]
    fn validate_config_rejects_unknown_events_and_empty_url() {
        let mut cfg = NotificationConfig {
            channels: vec![channel()],
        };
        cfg.channels[0].events = vec!["not_an_event".to_string()];
        assert!(validate_config(&cfg).is_err());

        cfg.channels[0].events = vec!["*".to_string()];
        cfg.channels[0].config = json!({ "url": "" });
        assert!(validate_config(&cfg).is_err());
    }

    #[test]
    fn validate_config_rejects_duplicate_names() {
        let mut second = channel();
        second.id = "webhook-2".to_string();
        let cfg = NotificationConfig {
            channels: vec![channel(), second],
        };

        assert!(validate_config(&cfg).is_err());
    }
}
