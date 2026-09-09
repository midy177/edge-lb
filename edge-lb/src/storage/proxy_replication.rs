//! Durable latest-state replication. Canonical configuration and its cursor
//! commit together; health, local VIP expansion and credentials are not copied.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    proxy_config::{MutationError, ProxyConfig, Rejection},
    repository::{DocumentChange, DocumentGuard, Repository, StoredDocument},
};
use crate::{
    config::Config,
    runtime::ha::{GatewayHaPeer, GatewayHaPeerSecrets, GatewayHaRuntimeConfig},
};

const KEYS: [(&str, &str); 6] = [
    ("listeners", "config"),
    ("target_groups", "config"),
    ("proxy_replication", "config"),
    ("ha", "config"),
    ("ha_peer_secret", "config"),
    ("ha_active_gateway", "current"),
];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncState {
    pub sequence: u64,
    pub source: String,
    pub pairing_id: String,
    pub content_hash: String,
    pub pending: bool,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub sequence: u64,
    pub source: String,
    pub pairing_id: String,
    pub content_hash: String,
    pub config: ProxyConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub sequence: u64,
    pub source: String,
    pub pairing_id: String,
    pub content_hash: String,
}

enum Scope {
    Standalone,
    Master {
        pairing_id: String,
        peer: GatewayHaPeer,
    },
    Backup {
        pairing_id: String,
        peer: GatewayHaPeer,
    },
}

pub(super) struct Bundle {
    pub config: ProxyConfig,
    sync: SyncState,
    scope: Scope,
    documents: Vec<Option<StoredDocument>>,
}

fn decode<T: serde::de::DeserializeOwned>(document: &Option<StoredDocument>) -> Result<Option<T>> {
    document
        .as_ref()
        .map(|doc| serde_json::from_str(&doc.payload))
        .transpose()
        .context("decoding replication transaction snapshot")
}

pub(super) fn read(repo: &Repository, cfg: &Config) -> Result<Bundle> {
    let documents = repo.get_many(
        KEYS.iter()
            .map(|(kind, name)| (kind.to_string(), name.to_string()))
            .collect(),
    )?;
    let config = ProxyConfig {
        listeners: decode(&documents[0])?.unwrap_or_else(|| cfg.listeners.clone()),
        target_groups: decode(&documents[1])?.unwrap_or_else(|| cfg.target_groups.clone()),
    };
    let ha: GatewayHaRuntimeConfig = decode(&documents[3])?.unwrap_or_default();
    let scope = if ha.enabled {
        anyhow::ensure!(
            ha.peers.len() == 1,
            "HA replication requires exactly one peer"
        );
        let peer = ha.peers[0].clone();
        let secret: GatewayHaPeerSecrets =
            decode(&documents[4])?.context("HA pairing secret missing")?;
        anyhow::ensure!(
            !secret.session_token_id.is_empty()
                && !secret.session_token.is_empty()
                && secret.peer_name == peer.name
                && secret.peer_underlay_ip == peer.underlay_ip,
            "HA pairing identity is inconsistent"
        );
        let active = documents[5]
            .as_ref()
            .context("HA active selection missing")?
            .payload
            .trim();
        if active == cfg.node_name || active == cfg.underlay_ip.to_string() {
            Scope::Master {
                pairing_id: secret.session_token_id,
                peer,
            }
        } else if active == peer.name || active == peer.underlay_ip {
            Scope::Backup {
                pairing_id: secret.session_token_id,
                peer,
            }
        } else {
            bail!("HA active selection is not a member of the current pair");
        }
    } else {
        Scope::Standalone
    };
    Ok(Bundle {
        config,
        sync: decode(&documents[2])?.unwrap_or_default(),
        scope,
        documents,
    })
}

fn shared(config: &ProxyConfig) -> ProxyConfig {
    let mut config = config.clone();
    for listener in &mut config.listeners {
        listener.vip_ips.clear();
    }
    config
}

fn content_hash(config: &ProxyConfig) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(config)?)))
}

impl Bundle {
    pub(super) fn require_local_writer(&self) -> Result<(), MutationError> {
        if matches!(self.scope, Scope::Backup { .. }) {
            return Err(MutationError::Rejected(Rejection::new(
                409,
                "local gateway is not MASTER",
            )));
        }
        Ok(())
    }

    pub(super) fn local_version(&self, cfg: &Config, config: &ProxyConfig) -> Result<SyncState> {
        let (pairing_id, pending) = match &self.scope {
            Scope::Master { pairing_id, .. } => (pairing_id.clone(), true),
            Scope::Standalone => (String::new(), false),
            Scope::Backup { .. } => bail!("local gateway is not MASTER"),
        };
        Ok(SyncState {
            sequence: self
                .sync
                .sequence
                .checked_add(1)
                .context("replication sequence exhausted")?,
            source: cfg.node_name.clone(),
            pairing_id,
            content_hash: content_hash(&shared(config))?,
            pending,
            last_error: None,
        })
    }

    pub(super) fn commit(
        &self,
        repo: &Repository,
        config: &ProxyConfig,
        sync: &SyncState,
        business_changed: bool,
    ) -> Result<bool> {
        let mut changes = Vec::new();
        let mut guards = Vec::new();
        for (index, (kind, name)) in KEYS.iter().enumerate() {
            let expected_revision = self.documents[index].as_ref().map(|doc| doc.revision);
            let payload = match index {
                0 if business_changed => Some(serde_json::to_string(&config.listeners)?),
                1 if business_changed => Some(serde_json::to_string(&config.target_groups)?),
                2 => Some(serde_json::to_string(sync)?),
                _ => None,
            };
            if let Some(payload) = payload {
                changes.push(DocumentChange {
                    resource_type: kind.to_string(),
                    resource_name: name.to_string(),
                    expected_revision,
                    payload,
                });
            } else {
                guards.push(DocumentGuard {
                    resource_type: kind.to_string(),
                    resource_name: name.to_string(),
                    expected_revision,
                });
            }
        }
        repo.compare_and_put_guarded(changes, guards, super::next_revision())
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            sequence: self.sync.sequence,
            source: self.sync.source.clone(),
            pairing_id: self.sync.pairing_id.clone(),
            content_hash: self.sync.content_hash.clone(),
            config: shared(&self.config),
        }
    }
}

pub fn status(cfg: &Config) -> Result<SyncState> {
    Ok(read(super::repository()?.as_ref(), cfg)?.sync)
}

/// Re-advertise on promotion/pairing without touching business documents/maps.
pub fn outgoing(cfg: &Config) -> Result<Option<(GatewayHaPeer, Snapshot, bool)>> {
    outgoing_on(super::repository()?.as_ref(), cfg)
}

fn outgoing_on(repo: &Repository, cfg: &Config) -> Result<Option<(GatewayHaPeer, Snapshot, bool)>> {
    for _ in 0..16 {
        let bundle = read(repo, cfg)?;
        let Scope::Master { pairing_id, peer } = &bundle.scope else {
            return Ok(None);
        };
        if bundle.sync.source != cfg.node_name
            || &bundle.sync.pairing_id != pairing_id
            || bundle.sync.content_hash != content_hash(&shared(&bundle.config))?
        {
            let next = bundle.local_version(cfg, &bundle.config)?;
            if !bundle.commit(repo, &bundle.config, &next, false)? {
                continue;
            }
            continue;
        }
        return Ok(Some((peer.clone(), bundle.snapshot(), bundle.sync.pending)));
    }
    bail!("replication state changed concurrently; retry")
}

pub fn receive(cfg: &Config, snapshot: &Snapshot) -> Result<Receipt, MutationError> {
    let (receipt, changed) = receive_on(super::repository()?.as_ref(), cfg, snapshot)?;
    if changed {
        crate::provider::native::mark_state_dirty();
    }
    Ok(receipt)
}

fn receive_on(
    repo: &Repository,
    cfg: &Config,
    snapshot: &Snapshot,
) -> Result<(Receipt, bool), MutationError> {
    if snapshot.sequence == 0
        || snapshot
            .config
            .listeners
            .iter()
            .any(|l| !l.vip_ips.is_empty())
        || content_hash(&snapshot.config)? != snapshot.content_hash
    {
        return Err(MutationError::Rejected(Rejection::new(
            400,
            "invalid shared proxy snapshot",
        )));
    }
    let mut file = cfg.file.clone();
    file.listeners = snapshot.config.listeners.clone();
    file.target_groups = snapshot.config.target_groups.clone();
    // Replication validates explicit addresses, not this node's transient
    // subscription inventory. The optional backend name is only a reference.
    for group in &mut file.target_groups {
        for target in &mut group.targets {
            target.backend = None;
        }
    }
    file.validate().map_err(|e| {
        MutationError::Rejected(Rejection::new(
            400,
            format!("invalid proxy snapshot: {e:#}"),
        ))
    })?;
    for _ in 0..16 {
        let bundle = read(repo, cfg)?;
        let Scope::Backup { pairing_id, peer } = &bundle.scope else {
            return Err(MutationError::Rejected(Rejection::new(
                409,
                "replica write requires BACKUP role",
            )));
        };
        if &snapshot.pairing_id != pairing_id || snapshot.source != peer.name {
            return Err(MutationError::Rejected(Rejection::new(
                409,
                "replica source does not match current HA pairing",
            )));
        }
        let same_pair = snapshot.pairing_id == bundle.sync.pairing_id;
        if same_pair && snapshot.sequence < bundle.sync.sequence {
            return Err(MutationError::Rejected(Rejection::new(
                409,
                "stale proxy snapshot",
            )));
        }
        let mut changed = false;
        if same_pair && snapshot.sequence == bundle.sync.sequence {
            if snapshot.source != bundle.sync.source
                || snapshot.content_hash != bundle.sync.content_hash
                || content_hash(&shared(&bundle.config))? != snapshot.content_hash
            {
                return Err(MutationError::Rejected(Rejection::new(
                    409,
                    "conflicting proxy snapshot version",
                )));
            }
        } else {
            let next = SyncState {
                sequence: snapshot.sequence,
                source: snapshot.source.clone(),
                pairing_id: snapshot.pairing_id.clone(),
                content_hash: snapshot.content_hash.clone(),
                pending: false,
                last_error: None,
            };
            changed = content_hash(&shared(&bundle.config))? != snapshot.content_hash;
            let write_documents = changed || bundle.documents[..2].iter().any(Option::is_none);
            if !bundle.commit(repo, &snapshot.config, &next, write_documents)? {
                continue;
            }
        }
        return Ok((
            Receipt {
                sequence: snapshot.sequence,
                source: snapshot.source.clone(),
                pairing_id: snapshot.pairing_id.clone(),
                content_hash: snapshot.content_hash.clone(),
            },
            changed,
        ));
    }
    Err(MutationError::Contended)
}

pub fn record_result(cfg: &Config, snapshot: &Snapshot, error: Option<String>) -> Result<()> {
    record_result_on(super::repository()?.as_ref(), cfg, snapshot, error)
}

fn record_result_on(
    repo: &Repository,
    cfg: &Config,
    snapshot: &Snapshot,
    error: Option<String>,
) -> Result<()> {
    for _ in 0..16 {
        let bundle = read(repo, cfg)?;
        let Scope::Master { pairing_id, .. } = &bundle.scope else {
            return Ok(());
        };
        if pairing_id != &snapshot.pairing_id
            || bundle.sync.sequence != snapshot.sequence
            || bundle.sync.source != snapshot.source
            || bundle.sync.content_hash != snapshot.content_hash
        {
            return Ok(());
        }
        let mut next = bundle.sync.clone();
        next.pending = error.is_some();
        next.last_error = error
            .as_ref()
            .map(|value| value.chars().take(512).collect());
        if next == bundle.sync || bundle.commit(repo, &bundle.config, &next, false)? {
            return Ok(());
        }
    }
    bail!("replication acknowledgement changed concurrently; retry")
}

impl Receipt {
    pub fn matches(&self, snapshot: &Snapshot) -> bool {
        self.sequence == snapshot.sequence
            && self.source == snapshot.source
            && self.pairing_id == snapshot.pairing_id
            && self.content_hash == snapshot.content_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, Listener, NodeRole, TargetGroup};
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    fn database(name: &str, address: &str) -> (Repository, Config, String) {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "proxy-sync-{name}-{}-{id}.sqlite3",
            std::process::id()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(crate::storage::initialize_async(&url))
            .unwrap();
        let cfg = Config {
            path,
            file: FileConfig {
                node_name: name.into(),
                node_role: NodeRole::Gateway,
                underlay_ip: address.parse().unwrap(),
                network: crate::config::NetworkConfig {
                    underlay_dev: "eth0".into(),
                    vxlan_dev: "edge-hub".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        (Repository::start(url.clone()).unwrap(), cfg, url)
    }

    fn put(repo: &Repository, kind: &str, name: &str, payload: String) {
        repo.put(kind, name, crate::storage::next_revision(), payload)
            .unwrap();
    }

    fn pair(repo: &Repository, other: &Config, active: &str, token_id: &str) {
        let peer = GatewayHaPeer {
            name: other.node_name.clone(),
            underlay_ip: other.underlay_ip.to_string(),
            ..Default::default()
        };
        let ha = GatewayHaRuntimeConfig {
            enabled: true,
            peers: vec![peer.clone()],
            ..Default::default()
        };
        let secret = GatewayHaPeerSecrets {
            peer_name: peer.name,
            peer_underlay_ip: peer.underlay_ip,
            session_token: "test-session-secret".into(),
            session_token_id: token_id.into(),
            ..Default::default()
        };
        put(repo, "ha", "config", serde_json::to_string(&ha).unwrap());
        put(
            repo,
            "ha_peer_secret",
            "config",
            serde_json::to_string(&secret).unwrap(),
        );
        put(repo, "ha_active_gateway", "current", active.into());
    }

    fn write(repo: &Repository, cfg: &Config, port: u16) -> Snapshot {
        let bundle = read(repo, cfg).unwrap();
        bundle.require_local_writer().unwrap();
        let config = ProxyConfig {
            listeners: vec![Listener {
                name: format!("tcp-{port}"),
                port,
                target_port: 18080,
                target_group: "web".into(),
                vip_ips: vec![cfg.underlay_ip],
                ..Default::default()
            }],
            target_groups: vec![TargetGroup {
                name: "web".into(),
                ..Default::default()
            }],
        };
        let sync = bundle.local_version(cfg, &config).unwrap();
        assert!(bundle.commit(repo, &config, &sync, true).unwrap());
        read(repo, cfg).unwrap().snapshot()
    }

    #[test]
    fn replicas_reject_reordering_and_conflicts_and_replay_without_writes() {
        let (a, ac, _) = database("gateway-a", "192.0.2.10");
        let (b, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "pair-one");
        pair(&b, &ac, &ac.node_name, "pair-one");
        let old = write(&a, &ac, 8080);
        let new = write(&a, &ac, 8081);
        assert!(new.config.listeners[0].vip_ips.is_empty());
        let (receipt, changed) = receive_on(&b, &bc, &new).unwrap();
        assert!(changed && receipt.matches(&new));
        let before = read(&b, &bc).unwrap().documents;
        assert!(!receive_on(&b, &bc, &new).unwrap().1);
        assert_eq!(before, read(&b, &bc).unwrap().documents);
        assert!(matches!(
            receive_on(&b, &bc, &old),
            Err(MutationError::Rejected(Rejection { status: 409, .. }))
        ));
        let mut conflict = new.clone();
        conflict.config.listeners[0].target_port += 1;
        conflict.content_hash = content_hash(&conflict.config).unwrap();
        assert!(receive_on(&b, &bc, &conflict).is_err());
        let mut invalid = new.clone();
        invalid.config.listeners[0].vip_ips.push(ac.underlay_ip);
        invalid.content_hash = content_hash(&invalid.config).unwrap();
        assert!(receive_on(&b, &bc, &invalid).is_err());
        assert_eq!(before, read(&b, &bc).unwrap().documents);
    }

    #[test]
    fn pending_survives_reopen_and_old_ack_cannot_clear_new_work() {
        let (a, ac, url) = database("gateway-a", "192.0.2.10");
        let (_, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "pair-one");
        let old = write(&a, &ac, 8080);
        record_result_on(&a, &ac, &old, Some("peer unavailable".into())).unwrap();
        drop(a);
        let a = Repository::start(url).unwrap();
        let (_, retried, pending) = outgoing_on(&a, &ac).unwrap().unwrap();
        assert!(pending);
        assert_eq!(retried.sequence, old.sequence);
        assert_eq!(retried.content_hash, old.content_hash);
        let new = write(&a, &ac, 8081);
        record_result_on(&a, &ac, &old, None).unwrap();
        assert!(read(&a, &ac).unwrap().sync.pending);
        record_result_on(&a, &ac, &new, None).unwrap();
        let before = read(&a, &ac).unwrap().documents;
        assert!(!read(&a, &ac).unwrap().sync.pending);
        record_result_on(&a, &ac, &new, None).unwrap();
        assert_eq!(before, read(&a, &ac).unwrap().documents);
    }

    #[test]
    fn role_change_fences_commit_and_promotion_only_changes_replication_metadata() {
        let (a, ac, _) = database("gateway-a", "192.0.2.10");
        let (b, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "pair-one");
        pair(&b, &ac, &ac.node_name, "pair-one");
        let snapshot = write(&a, &ac, 8080);
        receive_on(&b, &bc, &snapshot).unwrap();
        let stale = read(&a, &ac).unwrap();
        let next = stale.local_version(&ac, &stale.config).unwrap();
        put(&a, "ha_active_gateway", "current", bc.node_name.clone());
        assert!(!stale.commit(&a, &stale.config, &next, true).unwrap());
        assert!(read(&a, &ac).unwrap().require_local_writer().is_err());
        put(&b, "ha_active_gateway", "current", bc.node_name.clone());
        assert!(receive_on(&b, &bc, &snapshot).is_err());
        let before = read(&b, &bc).unwrap().documents;
        let (_, promoted, pending) = outgoing_on(&b, &bc).unwrap().unwrap();
        assert!(pending && promoted.sequence > snapshot.sequence);
        assert_eq!(&before[..2], &read(&b, &bc).unwrap().documents[..2]);
        // Identical content on the former MASTER must not rebuild its maps.
        assert!(!receive_on(&a, &ac, &promoted).unwrap().1);
        assert_eq!(
            &stale.documents[..2],
            &read(&a, &ac).unwrap().documents[..2]
        );
    }

    #[test]
    fn re_pairing_rejects_old_identity_and_allows_new_authority_baseline() {
        let (a, ac, _) = database("gateway-a", "192.0.2.10");
        let (b, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "old-pair");
        pair(&b, &ac, &ac.node_name, "old-pair");
        let old = write(&a, &ac, 8080);
        receive_on(&b, &bc, &old).unwrap();
        pair(&b, &ac, &ac.node_name, "new-pair");
        assert!(receive_on(&b, &bc, &old).is_err());
        let mut new = old.clone();
        new.pairing_id = "new-pair".into();
        new.sequence = 1;
        assert!(receive_on(&b, &bc, &new).is_ok());
    }

    #[test]
    fn outbox_failure_rolls_back_business_documents_and_cursor() {
        let (repo, cfg, url) = database("gateway-a", "192.0.2.10");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let db = runtime.block_on(Database::connect(&url)).unwrap();
        runtime.block_on(db.execute(Statement::from_string(DatabaseBackend::Sqlite,
            "CREATE TRIGGER reject_cursor BEFORE INSERT ON resource_documents WHEN NEW.resource_type = 'proxy_replication' BEGIN SELECT RAISE(ABORT, 'outbox failure'); END".to_string()))).unwrap();
        let bundle = read(&repo, &cfg).unwrap();
        let config = ProxyConfig {
            listeners: vec![],
            target_groups: vec![TargetGroup {
                name: "web".into(),
                ..Default::default()
            }],
        };
        let next = bundle.local_version(&cfg, &config).unwrap();
        assert!(bundle.commit(&repo, &config, &next, true).is_err());
        assert_eq!(bundle.documents, read(&repo, &cfg).unwrap().documents);
    }

    #[test]
    fn lost_http_receipt_retries_same_snapshot_without_reapplying() {
        let (a, ac, _) = database("gateway-a", "192.0.2.10");
        let (b, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "pair-one");
        pair(&b, &ac, &ac.node_name, "pair-one");
        let snapshot = write(&a, &ac, 8080);
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/api/v1/ha/peer/proxy-config/replica",
            server.server_addr()
        );
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                let mut after_first = Vec::new();
                for attempt in 0..2 {
                    let mut request = server
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap()
                        .unwrap();
                    let mut body = String::new();
                    request.as_reader().read_to_string(&mut body).unwrap();
                    let incoming: Snapshot = serde_json::from_str(&body).unwrap();
                    let (receipt, changed) = receive_on(&b, &bc, &incoming).unwrap();
                    if attempt == 0 {
                        assert!(changed);
                        after_first = read(&b, &bc).unwrap().documents;
                        request.respond(tiny_http::Response::empty(500)).unwrap();
                    } else {
                        assert!(!changed);
                        assert_eq!(after_first, read(&b, &bc).unwrap().documents);
                        request
                            .respond(tiny_http::Response::from_string(
                                serde_json::to_string(&receipt).unwrap(),
                            ))
                            .unwrap();
                    }
                }
            });
            let client = reqwest::blocking::Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap();
            let failed = client.post(&url).json(&snapshot).send().unwrap();
            assert_eq!(failed.status().as_u16(), 500);
            failed.text().unwrap();
            record_result_on(&a, &ac, &snapshot, Some("receipt unavailable".into())).unwrap();
            let (_, retry, pending) = outgoing_on(&a, &ac).unwrap().unwrap();
            assert!(pending);
            let receipt: Receipt = client
                .post(&url)
                .json(&retry)
                .send()
                .unwrap()
                .json()
                .unwrap();
            assert!(receipt.matches(&snapshot));
            record_result_on(&a, &ac, &retry, None).unwrap();
            assert!(!read(&a, &ac).unwrap().sync.pending);
            worker.join().unwrap();
        });
    }

    #[test]
    fn empty_snapshot_removes_listeners_and_groups_together() {
        let (a, ac, _) = database("gateway-a", "192.0.2.10");
        let (b, bc, _) = database("gateway-b", "192.0.2.11");
        pair(&a, &bc, &ac.node_name, "pair-one");
        pair(&b, &ac, &ac.node_name, "pair-one");
        receive_on(&b, &bc, &write(&a, &ac, 8080)).unwrap();
        let bundle = read(&a, &ac).unwrap();
        let empty = ProxyConfig {
            listeners: vec![],
            target_groups: vec![],
        };
        let cursor = bundle.local_version(&ac, &empty).unwrap();
        assert!(bundle.commit(&a, &empty, &cursor, true).unwrap());
        let snapshot = read(&a, &ac).unwrap().snapshot();
        assert!(receive_on(&b, &bc, &snapshot).unwrap().1);
        let result = read(&b, &bc).unwrap();
        assert!(result.config.listeners.is_empty() && result.config.target_groups.is_empty());
        assert_eq!(
            result.documents[0].as_ref().unwrap().revision,
            result.documents[1].as_ref().unwrap().revision
        );
    }

    #[test]
    fn reopen_observes_persisted_revision_ahead_of_wall_clock() {
        let (repo, cfg, url) = database("gateway-a", "192.0.2.10");
        let future = crate::storage::next_revision() + 100_000;
        repo.put("unrelated", "config", future, "{}".into())
            .unwrap();
        drop(repo);
        let repo = Repository::start(url).unwrap();
        let bundle = read(&repo, &cfg).unwrap();
        let cursor = bundle.local_version(&cfg, &bundle.config).unwrap();
        assert!(bundle.commit(&repo, &bundle.config, &cursor, true).unwrap());
        assert!(
            read(&repo, &cfg).unwrap().documents[2]
                .as_ref()
                .unwrap()
                .revision
                > future
        );
    }
}
