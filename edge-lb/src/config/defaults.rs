use std::{fmt, fs, net::IpAddr};

use serde::{
    Deserialize, Deserializer, Serializer,
    de::{Error as _, Visitor},
};

pub(super) fn default_node_name() -> String {
    std::env::var("EDGE_LB_NODE_NAME")
        .ok()
        .and_then(non_empty_trimmed)
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .and_then(non_empty_trimmed)
        })
        .or_else(|| std::env::var("HOSTNAME").ok().and_then(non_empty_trimmed))
        .unwrap_or_else(|| "edge-lb-node".to_string())
}

fn non_empty_trimmed(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub(super) fn default_backend_weight() -> u32 {
    1
}

pub(super) fn default_gateway_overlay() -> String {
    "10.255.255.1/24".to_string()
}

pub(super) fn old_default_gateway_overlay() -> &'static str {
    "10.255.255.1/30"
}

pub(super) fn default_gateway_public_ip() -> IpAddr {
    "203.0.113.10".parse().unwrap()
}

pub(super) fn default_gateway_ip() -> IpAddr {
    "192.0.2.11".parse().unwrap()
}

pub(super) fn default_backend_overlay() -> String {
    "10.255.255.2/24".to_string()
}

pub(super) fn old_default_backend_overlay() -> &'static str {
    "10.255.255.2/30"
}

pub fn is_auto_ip(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

pub(super) fn default_auto_ip() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}

pub(super) fn deserialize_ip_auto<'de, D>(deserializer: D) -> std::result::Result<IpAddr, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    if text.eq_ignore_ascii_case("auto") {
        return Ok("0.0.0.0".parse().unwrap());
    }
    text.parse().map_err(D::Error::custom)
}

pub(super) fn deserialize_option_ip_auto<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(text) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if text.eq_ignore_ascii_case("auto") {
        return Ok(Some("0.0.0.0".parse().unwrap()));
    }
    text.parse().map(Some).map_err(D::Error::custom)
}

pub(super) fn serialize_ip_auto<S>(
    ip: &IpAddr,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if is_auto_ip(*ip) {
        serializer.serialize_str("auto")
    } else {
        serializer.serialize_str(&ip.to_string())
    }
}

pub(super) fn serialize_option_ip_auto<S>(
    ip: &Option<IpAddr>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match ip {
        Some(ip) => serialize_ip_auto(ip, serializer),
        None => serializer.serialize_none(),
    }
}

pub(super) fn deserialize_u32_auto<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    struct U32AutoVisitor;

    impl Visitor<'_> for U32AutoVisitor {
        type Value = u32;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a u32 value or \"auto\"")
        }

        fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u32::try_from(value).map_err(E::custom)
        }

        fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u32::try_from(value).map_err(E::custom)
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if value.trim().eq_ignore_ascii_case("auto") {
                return Ok(0);
            }
            value.trim().parse::<u32>().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U32AutoVisitor)
}

pub(super) fn serialize_u32_auto<S>(
    value: &u32,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *value == 0 {
        serializer.serialize_str("auto")
    } else {
        serializer.serialize_u32(*value)
    }
}
