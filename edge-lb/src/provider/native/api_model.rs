use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRuleStateList {
    pub rules: Vec<RuntimeRuleStateEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRuleStateEntry {
    pub spec: RuntimeRuleSpec,
    #[serde(default)]
    pub targets: Vec<RuntimeRuleTarget>,
    /// Logical listener protocols. The datapath expands this into one
    /// protocol-specific lookup key per selected transport protocol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRuleSpec {
    pub vip_ips: Vec<String>,
    pub port: u16,
    pub protocol: String,
    #[serde(default)]
    pub sel: u32,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub bgp: bool,
    #[serde(default)]
    pub monitor: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probetype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probeport: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probereq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proberesp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_timeout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_retries: Option<u32>,
    #[serde(default)]
    pub inactive_timeout: u32,
    #[serde(default)]
    pub block: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub proxyprotocolv2: bool,
    #[serde(default)]
    pub egress: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRuleTarget {
    /// Backend target address.
    pub address: String,
    /// Forwarding port owned by the listener configuration.
    pub target_port: u16,
    #[serde(default)]
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetHealthList {
    pub entries: Vec<TargetHealthEntry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetHealthEntry {
    pub host_name: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub inactive_retries: Option<u32>,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub probe_req: Option<String>,
    #[serde(default)]
    pub probe_resp: Option<String>,
    #[serde(default)]
    pub probe_duration: Option<u32>,
    #[serde(default)]
    pub probe_port: Option<u16>,
    #[serde(default)]
    pub min_delay: Option<String>,
    #[serde(default)]
    pub avg_delay: Option<String>,
    #[serde(default)]
    pub max_delay: Option<String>,
    #[serde(default)]
    pub current_state: Option<String>,
    #[serde(default)]
    pub sync: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbeConfig {
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub probe_port: Option<u16>,
    #[serde(default)]
    pub probe_req: Option<String>,
    #[serde(default)]
    pub probe_resp: Option<String>,
    #[serde(default)]
    pub expected_status: Option<u16>,
    #[serde(default)]
    pub skip_tls_verify: bool,
    #[serde(default)]
    pub probe_duration: Option<u32>,
    #[serde(default)]
    pub inactive_retries: Option<u32>,
}

impl HealthProbeConfig {
    pub fn enabled(&self) -> bool {
        self.probe_type
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some_and(|value| !value.eq_ignore_ascii_case("none"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_rule_state_uses_native_resource_field_names() {
        let value = RuntimeRuleStateList {
            rules: vec![RuntimeRuleStateEntry {
                spec: RuntimeRuleSpec {
                    vip_ips: vec!["192.0.2.10".to_string()],
                    port: 8080,
                    protocol: "tcp".to_string(),
                    ..RuntimeRuleSpec::default()
                },
                targets: vec![RuntimeRuleTarget {
                    address: "192.0.2.20".to_string(),
                    target_port: 10080,
                    weight: 1,
                    ..RuntimeRuleTarget::default()
                }],
                protocols: vec!["tcp".to_string()],
            }],
        };

        let json = serde_json::to_value(value).unwrap();
        assert!(json.get("rules").is_some());
        assert!(json["rules"][0].get("spec").is_some());
        assert!(json["rules"][0].get("targets").is_some());
        assert!(json.get("services").is_none());
        assert!(json["rules"][0].get("service_arguments").is_none());
        assert!(json["rules"][0].get("endpoints").is_none());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteTargetHealthResult {
    Deleted,
    NotFound,
    Referenced { listener: String },
}
