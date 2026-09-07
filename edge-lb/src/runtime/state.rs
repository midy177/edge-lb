//! Persistent agent state (`runtime_state` SQLite resource): pins and runtime
//! identifiers this agent created, so cleanup only touches its own objects and
//! `run` can detect interface/index changes. Business configuration is stored
//! in SQLite.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedTarget {
    pub backend_ip: String,
    pub backend_port: u16,
    #[serde(default = "default_backend_weight")]
    pub weight: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_req: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_resp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagedRuntimeRule {
    pub service: String,
    pub vip_ip: String,
    pub protocol: String,
    pub vip_port: u16,
    pub backend_port: u16,
    pub backend_ip: String,
    #[serde(default = "default_backend_weight")]
    pub backend_weight: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<ManagedTarget>,
    #[serde(default)]
    pub select: u32,
    #[serde(default)]
    pub mode: u32,
    #[serde(default)]
    pub bgp: bool,
    #[serde(default)]
    pub monitor: bool,
    #[serde(default)]
    pub inactive_timeout: Option<u32>,
    #[serde(default)]
    pub mark: Option<u32>,
    #[serde(default)]
    pub security: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub proxy_protocol_v2: bool,
    #[serde(default)]
    pub egress: bool,
}

fn default_backend_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentState {
    pub native_datapath_prog_id: Option<u32>,
    pub vxlan_ifindex: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dscp_ports: Vec<u32>,
    pub created_vxlan: bool,
}

impl AgentState {
    #[cfg(test)]
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join("state.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                if text.trim().is_empty() {
                    return Ok(Self::default());
                }
                serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    #[cfg(not(test))]
    pub fn load(_dir: &Path) -> Result<Self> {
        let payload = crate::storage::repository()?.get("runtime_state", "config")?;
        payload
            .map(|value| serde_json::from_str(&value).context("parsing stored runtime state"))
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    #[cfg(test)]
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
        let path = dir.join("state.json");
        let tmp = dir.join("state.json.tmp");
        let text = serde_json::to_string_pretty(self).context("serializing state")?;
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    #[cfg(not(test))]
    pub fn save(&self, _dir: &Path) -> Result<()> {
        let payload = serde_json::to_string(self).context("serializing runtime state")?;
        crate::storage::repository()?.put(
            "runtime_state",
            "config",
            crate::storage::next_revision(),
            payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_file_loads_default_state() {
        let dir = std::env::temp_dir().join(format!("edge-lb-state-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("state.json"), "\n").unwrap();

        let state = AgentState::load(&dir).unwrap();

        assert!(state.native_datapath_prog_id.is_none());
        assert!(state.dscp_ports.is_empty());
        std::fs::remove_file(dir.join("state.json")).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
