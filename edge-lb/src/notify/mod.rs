//! HA and datapath notification dispatcher.

use std::{sync::mpsc, thread, time::Duration};

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{config::Config, events::EdgeEvent};

pub mod i18n;
pub mod model;
pub mod signer;
pub mod store;
pub mod sync;

use model::{ChannelKind, Delivery, DeliveryRecord, NotificationChannel};

const QUEUE_CAPACITY: usize = 1024;
const MAX_RETRIES: usize = 5;
const RESPONSE_LIMIT: usize = 2048;

pub fn spawn_dispatcher(cfg: &Config) {
    let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
    crate::events::install_sender(tx);
    let cfg = cfg.clone();
    thread::Builder::new()
        .name("edge-lb-notify".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            let http = match http_client() {
                Ok(client) => client,
                Err(e) => {
                    tracing::warn!("[notify] disabled: {e:#}");
                    return;
                }
            };
            while let Ok(event) = rx.recv() {
                dispatch_event(&cfg, &http, &event);
            }
        })
        .expect("spawn notification dispatcher");
}

pub fn send_test(cfg: &Config, channel: &NotificationChannel) -> Result<Delivery> {
    let http = http_client()?;
    let event = EdgeEvent::new(
        "notification_test",
        crate::events::Severity::Info,
        &cfg.node_name,
        format!("{:?}", cfg.node_role).to_ascii_lowercase(),
        "Notification test",
        "This is a test message from edge-lb.",
    );
    send_with_retry(&http, channel, &event)
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("edge-lb/0.1")
        .build()
        .context("building notification HTTP client")
}

fn dispatch_event(cfg: &Config, http: &Client, event: &EdgeEvent) {
    let config = match store::load(cfg) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!("[notify] loading channels failed: {e:#}");
            return;
        }
    };
    for channel in config
        .channels
        .iter()
        .filter(|channel| channel.matches_event(&event.kind))
    {
        let delivery = match send_with_retry(http, channel, event) {
            Ok(delivery) => delivery,
            Err(e) => Delivery {
                ok: false,
                status_code: None,
                response: format!("{e:#}"),
            },
        };
        let response = truncate_response(&delivery.response);
        if delivery.ok {
            tracing::info!(
                "[notify] delivered event={} channel={} kind={:?} status={:?}",
                event.kind,
                channel.name,
                channel.kind,
                delivery.status_code
            );
        } else {
            tracing::warn!(
                "[notify] delivery failed event={} channel={} kind={:?} status={:?} response={}",
                event.kind,
                channel.name,
                channel.kind,
                delivery.status_code,
                response
            );
        }
        store::append_delivery(
            cfg,
            &DeliveryRecord {
                channel_id: channel.id.clone(),
                channel_name: channel.name.clone(),
                event_kind: event.kind.clone(),
                ok: delivery.ok,
                status_code: delivery.status_code,
                error: (!delivery.ok).then(|| response.clone()),
                response,
                attempted_at_unix: crate::events::now_unix(),
            },
        );
    }
}

fn send_with_retry(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let mut last = None;
    for attempt in 0..MAX_RETRIES {
        match send_once(http, channel, event) {
            Ok(delivery) if delivery.ok => return Ok(delivery),
            Ok(delivery) => {
                last = Some(anyhow!(
                    "notification response was not successful: {}",
                    delivery.response
                ))
            }
            Err(e) => last = Some(e),
        }
        if attempt + 1 < MAX_RETRIES {
            let delay_ms = 200_u64.saturating_mul(1 << attempt);
            thread::sleep(Duration::from_millis(delay_ms));
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("notification delivery failed")))
}

fn send_once(http: &Client, channel: &NotificationChannel, event: &EdgeEvent) -> Result<Delivery> {
    match channel.kind {
        ChannelKind::Webhook => send_webhook(http, channel, event),
        ChannelKind::Dingtalk => send_dingtalk(http, channel, event),
        ChannelKind::Feishu => send_feishu(http, channel, event),
        ChannelKind::Wecom => send_wecom(http, channel, event),
        ChannelKind::Telegram => send_telegram(http, channel, event),
        ChannelKind::Slack => send_slack(http, channel, event),
        ChannelKind::Pushplus => send_pushplus(http, channel, event),
        ChannelKind::Lanxin => send_lanxin(http, channel, event),
    }
}

#[derive(Debug, Deserialize)]
struct UrlConfig {
    url: String,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DingTalkConfig {
    access_token: String,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TelegramConfig {
    bot_token: String,
    chat_id: String,
}

#[derive(Debug, Deserialize)]
struct PushplusConfig {
    token: String,
    #[serde(default)]
    topic: Option<String>,
}

fn send_webhook(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: UrlConfig =
        serde_json::from_value(channel.config.clone()).context("invalid webhook config")?;
    let payload = json!({
        "event": event.kind,
        "severity": event.severity,
        "title": event.title,
        "text": event.text,
        "node": event.node,
        "role": event.role,
        "occurred_at_unix": event.occurred_at_unix,
        "labels": event.labels,
        "details": event.details,
    });
    let body = serde_json::to_vec(&payload).context("encoding webhook payload")?;
    let mut req = http
        .post(&cfg.url)
        .header("content-type", "application/json")
        .body(body.clone());
    if let Some(secret) = cfg.secret.as_deref().filter(|value| !value.is_empty()) {
        req = req.header(
            "X-Edge-LB-Signature",
            signer::hmac_sha256_hex(secret, &body),
        );
    }
    response(req.send().context("webhook request")?)
}

fn send_dingtalk(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: DingTalkConfig =
        serde_json::from_value(channel.config.clone()).context("invalid dingtalk config")?;
    let mut url = format!(
        "https://oapi.dingtalk.com/robot/send?access_token={}",
        cfg.access_token
    );
    if let Some(secret) = cfg.secret.as_deref().filter(|value| !value.is_empty()) {
        let ts = signer::now_millis();
        url.push_str(&format!(
            "&timestamp={ts}&sign={}",
            signer::dingtalk_sign(ts, secret)
        ));
    }
    let (title, text) = i18n::render(event, &channel.lang);
    let body = json!({
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": format!("### {} {}\n\n{}", i18n::marker(event), title, text),
        }
    });
    let delivery = response(
        http.post(url)
            .json(&body)
            .send()
            .context("dingtalk request")?,
    )?;
    Ok(json_code_delivery(delivery, "errcode", 0))
}

fn send_feishu(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: UrlConfig =
        serde_json::from_value(channel.config.clone()).context("invalid feishu config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let mut body = json!({
        "msg_type": "interactive",
        "card": {
            "config": { "wide_screen_mode": true },
            "header": {
                "template": i18n::feishu_template(event),
                "title": { "tag": "plain_text", "content": format!("{} {}", i18n::marker(event), title) }
            },
            "elements": [
                { "tag": "div", "text": { "tag": "lark_md", "content": text } }
            ]
        }
    });
    if let Some(secret) = cfg.secret.as_deref().filter(|value| !value.is_empty()) {
        let ts = signer::now_millis() / 1000;
        body["timestamp"] = json!(ts.to_string());
        body["sign"] = json!(signer::feishu_sign(ts, secret));
    }
    let delivery = response(
        http.post(&cfg.url)
            .json(&body)
            .send()
            .context("feishu request")?,
    )?;
    Ok(json_code_delivery_any(
        delivery,
        &[("code", 0), ("StatusCode", 0)],
    ))
}

fn send_wecom(http: &Client, channel: &NotificationChannel, event: &EdgeEvent) -> Result<Delivery> {
    let cfg: UrlConfig =
        serde_json::from_value(channel.config.clone()).context("invalid wecom config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let body = json!({
        "msgtype": "markdown",
        "markdown": {
            "content": format!("## {} {}\n<font color=\"{}\">{}</font>", i18n::marker(event), title, i18n::wecom_color(event), text)
        }
    });
    let delivery = response(
        http.post(&cfg.url)
            .json(&body)
            .send()
            .context("wecom request")?,
    )?;
    Ok(json_code_delivery(delivery, "errcode", 0))
}

fn send_telegram(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: TelegramConfig =
        serde_json::from_value(channel.config.clone()).context("invalid telegram config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.bot_token);
    let body = json!({
        "chat_id": cfg.chat_id,
        "text": format!("{} *{}*\n\n{}", i18n::marker(event), title, text),
        "parse_mode": "Markdown",
    });
    let delivery = response(
        http.post(url)
            .json(&body)
            .send()
            .context("telegram request")?,
    )?;
    Ok(json_bool_delivery(delivery, "ok"))
}

fn send_slack(http: &Client, channel: &NotificationChannel, event: &EdgeEvent) -> Result<Delivery> {
    let cfg: UrlConfig =
        serde_json::from_value(channel.config.clone()).context("invalid slack config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let body = json!({ "text": format!("{} *{}*\n{}", i18n::marker(event), title, text) });
    response(
        http.post(&cfg.url)
            .json(&body)
            .send()
            .context("slack request")?,
    )
}

fn send_pushplus(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: PushplusConfig =
        serde_json::from_value(channel.config.clone()).context("invalid pushplus config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let mut body = json!({
        "token": cfg.token,
        "title": title,
        "content": text,
        "template": "markdown",
    });
    if let Some(topic) = cfg.topic.as_deref().filter(|value| !value.is_empty()) {
        body["topic"] = json!(topic);
    }
    let delivery = response(
        http.post("https://www.pushplus.plus/send")
            .json(&body)
            .send()
            .context("pushplus request")?,
    )?;
    Ok(json_code_delivery(delivery, "code", 200))
}

fn send_lanxin(
    http: &Client,
    channel: &NotificationChannel,
    event: &EdgeEvent,
) -> Result<Delivery> {
    let cfg: UrlConfig =
        serde_json::from_value(channel.config.clone()).context("invalid lanxin config")?;
    let (title, text) = i18n::render(event, &channel.lang);
    let body = json!({ "title": title, "text": text, "event": event.kind });
    response(
        http.post(&cfg.url)
            .json(&body)
            .send()
            .context("lanxin request")?,
    )
}

fn response(resp: reqwest::blocking::Response) -> Result<Delivery> {
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    Ok(Delivery {
        ok: status.is_success(),
        status_code: Some(status.as_u16()),
        response: text,
    })
}

fn json_code_delivery(mut delivery: Delivery, field: &str, expected: i64) -> Delivery {
    let ok = delivery.status_code == Some(200)
        && serde_json::from_str::<Value>(&delivery.response)
            .ok()
            .and_then(|value| value.get(field).and_then(|code| code.as_i64()))
            == Some(expected);
    delivery.ok = ok;
    delivery
}

fn json_code_delivery_any(mut delivery: Delivery, fields: &[(&str, i64)]) -> Delivery {
    let parsed = serde_json::from_str::<Value>(&delivery.response).ok();
    let ok = delivery.status_code == Some(200)
        && fields.iter().any(|(field, expected)| {
            parsed
                .as_ref()
                .and_then(|value| value.get(*field).and_then(|code| code.as_i64()))
                == Some(*expected)
        });
    delivery.ok = ok;
    delivery
}

fn json_bool_delivery(mut delivery: Delivery, field: &str) -> Delivery {
    let ok = delivery.status_code == Some(200)
        && serde_json::from_str::<Value>(&delivery.response)
            .ok()
            .and_then(|value| value.get(field).and_then(|flag| flag.as_bool()))
            == Some(true);
    delivery.ok = ok;
    delivery
}

fn truncate_response(value: &str) -> String {
    if value.len() <= RESPONSE_LIMIT {
        return value.to_string();
    }
    let mut end = RESPONSE_LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}
