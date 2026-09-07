//! Process-wide structured events for HA and datapath operations.

use std::{
    collections::BTreeMap,
    sync::{OnceLock, mpsc::SyncSender},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

static EVENT_TX: OnceLock<SyncSender<EdgeEvent>> = OnceLock::new();

pub const HA_PAIR_SUCCEEDED: &str = "ha_pair_succeeded";
pub const HA_PAIR_FAILED: &str = "ha_pair_failed";
pub const HA_UNPAIRED: &str = "ha_unpaired";
pub const HA_SWITCHOVER_STARTED: &str = "ha_switchover_started";
pub const HA_SWITCHOVER_SUCCEEDED: &str = "ha_switchover_succeeded";
pub const HA_SWITCHOVER_FAILED: &str = "ha_switchover_failed";
pub const HA_STATE_CHANGED: &str = "ha_state_changed";
pub const HA_SPLIT_BRAIN_DETECTED: &str = "ha_split_brain_detected";
pub const HA_DUAL_BACKUP_DETECTED: &str = "ha_dual_backup_detected";
pub const BFD_STATE_CHANGED: &str = "bfd_state_changed";
pub const VIP_GARP_SENT: &str = "vip_garp_sent";
pub const VIP_GARP_FAILED: &str = "vip_garp_failed";
pub const DATAPATH_DEGRADED: &str = "datapath_degraded";
pub const DATAPATH_RECOVERED: &str = "datapath_recovered";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEvent {
    pub kind: String,
    pub severity: Severity,
    pub title: String,
    pub text: String,
    pub node: String,
    pub role: String,
    pub occurred_at_unix: u64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub details: Value,
}

impl EdgeEvent {
    pub fn new(
        kind: impl Into<String>,
        severity: Severity,
        node: impl Into<String>,
        role: impl Into<String>,
        title: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            severity,
            title: title.into(),
            text: text.into(),
            node: node.into(),
            role: role.into(),
            occurred_at_unix: now_unix(),
            labels: BTreeMap::new(),
            details: json!({}),
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
}

pub fn install_sender(tx: SyncSender<EdgeEvent>) {
    let _ = EVENT_TX.set(tx);
}

pub fn publish(event: EdgeEvent) {
    let Some(tx) = EVENT_TX.get() else {
        return;
    };
    if let Err(e) = tx.try_send(event) {
        tracing::warn!("[notify] dropping event: {e}");
    }
}

pub fn all_kinds() -> &'static [&'static str] {
    &[
        HA_PAIR_SUCCEEDED,
        HA_PAIR_FAILED,
        HA_UNPAIRED,
        HA_SWITCHOVER_STARTED,
        HA_SWITCHOVER_SUCCEEDED,
        HA_SWITCHOVER_FAILED,
        HA_STATE_CHANGED,
        HA_SPLIT_BRAIN_DETECTED,
        HA_DUAL_BACKUP_DETECTED,
        BFD_STATE_CHANGED,
        VIP_GARP_SENT,
        VIP_GARP_FAILED,
        DATAPATH_DEGRADED,
        DATAPATH_RECOVERED,
    ]
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
