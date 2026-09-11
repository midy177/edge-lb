use serde_json::{Value, json};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::api) struct PageQuery {
    pub enabled: bool,
    pub page: usize,
    pub per_page: usize,
    pub q: String,
}

pub(in crate::api) fn page_query(query: &str) -> PageQuery {
    let mut out = PageQuery {
        enabled: false,
        page: 1,
        per_page: 20,
        q: String::new(),
    };
    for pair in query.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "page" => {
                out.enabled = true;
                out.page = value.parse::<usize>().unwrap_or(1).max(1);
            }
            "per_page" | "perPage" | "page_size" | "pageSize" => {
                out.enabled = true;
                out.per_page = value.parse::<usize>().unwrap_or(20).clamp(1, 200);
            }
            "q" => {
                out.enabled = true;
                out.q = decode_query_value(value).trim().to_ascii_lowercase();
            }
            _ => {}
        }
    }
    out
}

pub(in crate::api) fn maybe_paginate_json(items: Vec<Value>, query: &str) -> Value {
    let page = page_query(query);
    if !page.enabled {
        return Value::Array(items);
    }
    let filtered = if page.q.is_empty() {
        items
    } else {
        items
            .into_iter()
            .filter(|item| value_contains(item, &page.q))
            .collect()
    };
    let total = filtered.len();
    let start = page.per_page.saturating_mul(page.page.saturating_sub(1));
    let page_items = filtered
        .into_iter()
        .skip(start)
        .take(page.per_page)
        .collect::<Vec<_>>();
    json!({
        "items": page_items,
        "total": total,
        "page": page.page,
        "per_page": page.per_page,
    })
}

fn value_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => value.to_string().contains(needle),
        Value::Number(value) => value.to_string().contains(needle),
        Value::String(value) => value.to_ascii_lowercase().contains(needle),
        Value::Array(items) => items.iter().any(|item| value_contains(item, needle)),
        Value::Object(object) => object.values().any(|item| value_contains(item, needle)),
    }
}

fn decode_query_value(value: &str) -> String {
    let mut out = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex(bytes[i + 1]);
                let lo = hex(bytes[i + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_query_parses_and_clamps() {
        assert_eq!(page_query("page=2&per_page=500&q=tcp%2D80").page, 2);
        let parsed = page_query("page=2&per_page=500&q=tcp%2D80");
        assert!(parsed.enabled);
        assert_eq!(parsed.per_page, 200);
        assert_eq!(parsed.q, "tcp-80");
    }

    #[test]
    fn maybe_paginate_filters_nested_values() {
        let items = vec![
            json!({"name":"tcp-80","target":{"address":"10.0.0.1"}}),
            json!({"name":"udp-53","target":{"address":"10.0.0.2"}}),
        ];
        let value = maybe_paginate_json(items, "page=1&per_page=10&q=10.0.0.2");
        assert_eq!(value["total"], 1);
        assert_eq!(value["items"][0]["name"], "udp-53");
    }
}
