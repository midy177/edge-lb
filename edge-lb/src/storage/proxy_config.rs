//! Canonical listener/target-group snapshot. Observed health and native maps
//! are not business configuration and must never be used to reconstruct it.

use super::repository::{Repository, StoredDocument};
use crate::config::{Config, Listener, TargetGroup};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub listeners: Vec<Listener>,
    pub target_groups: Vec<TargetGroup>,
}

#[derive(Debug)]
pub struct Rejection {
    pub status: u16,
    pub message: String,
}

impl Rejection {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
pub enum MutationError {
    Rejected(Rejection),
    Storage(anyhow::Error),
    Contended,
}

impl From<anyhow::Error> for MutationError {
    fn from(error: anyhow::Error) -> Self {
        Self::Storage(error)
    }
}

const RESOURCES: [&str; 2] = ["listeners", "target_groups"];

fn read(repo: &Repository, cfg: &Config) -> Result<(ProxyConfig, Vec<Option<StoredDocument>>)> {
    let documents = repo.get_many(
        RESOURCES
            .iter()
            .map(|name| (name.to_string(), "config".into()))
            .collect(),
    )?;
    let state = ProxyConfig {
        listeners: documents[0]
            .as_ref()
            .map(|document| serde_json::from_str(&document.payload))
            .transpose()
            .context("parsing stored listeners")?
            .unwrap_or_else(|| cfg.listeners.clone()),
        target_groups: documents[1]
            .as_ref()
            .map(|document| serde_json::from_str(&document.payload))
            .transpose()
            .context("parsing stored target groups")?
            .unwrap_or_else(|| cfg.target_groups.clone()),
    };
    Ok((state, documents))
}

pub fn load(cfg: &Config) -> Result<ProxyConfig> {
    read(super::repository()?.as_ref(), cfg).map(|(state, _)| state)
}

pub fn hydrate(cfg: &mut Config) -> Result<()> {
    let state = load(cfg)?;
    cfg.file.listeners = state.listeners;
    cfg.file.target_groups = state.target_groups;
    Ok(())
}

pub fn mutate<T>(
    cfg: &Config,
    update: impl FnMut(&mut ProxyConfig) -> std::result::Result<T, Rejection>,
) -> std::result::Result<(T, bool), MutationError> {
    mutate_on(super::repository()?.as_ref(), cfg, update)
}

fn mutate_on<T>(
    repo: &Repository,
    cfg: &Config,
    mut update: impl FnMut(&mut ProxyConfig) -> std::result::Result<T, Rejection>,
) -> std::result::Result<(T, bool), MutationError> {
    // Validation runs outside the storage worker. It may inspect local config,
    // but must have no external side effects because a CAS retry reruns it.
    for _ in 0..16 {
        let bundle = super::proxy_replication::read(repo, cfg)?;
        bundle.require_local_writer()?;
        let mut state = bundle.config.clone();
        let previous = serde_json::to_string(&(&state.listeners, &state.target_groups))
            .map_err(anyhow::Error::from)?;
        let result = update(&mut state).map_err(MutationError::Rejected)?;
        let next = serde_json::to_string(&(&state.listeners, &state.target_groups))
            .map_err(anyhow::Error::from)?;
        if previous == next {
            return Ok((result, false));
        }
        let sync = bundle.local_version(cfg, &state)?;
        if bundle.commit(repo, &state, &sync, true)? {
            return Ok((result, true));
        }
    }
    Err(MutationError::Contended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn database() -> (Repository, Config) {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "edge-proxy-txn-{}-{suffix}.sqlite3",
            std::process::id()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::storage::initialize_async(&url))
            .unwrap();
        (
            Repository::start(url).unwrap(),
            Config {
                path,
                file: Default::default(),
            },
        )
    }

    #[test]
    fn concurrent_mutations_retry_without_losing_other_writers() {
        let (repo, cfg) = database();
        let barrier = Arc::new(Barrier::new(8));
        std::thread::scope(|scope| {
            for index in 0..8 {
                let barrier = barrier.clone();
                let repo = &repo;
                let cfg = &cfg;
                scope.spawn(move || {
                    let mut first = true;
                    mutate_on(repo, cfg, |state| {
                        if first {
                            first = false;
                            barrier.wait();
                        }
                        state.target_groups.push(TargetGroup {
                            name: format!("group-{index}"),
                            ..Default::default()
                        });
                        Ok(())
                    })
                    .unwrap();
                });
            }
        });
        let (state, documents) = read(&repo, &cfg).unwrap();
        assert_eq!(state.target_groups.len(), 8);
        assert_eq!(
            documents[0].as_ref().unwrap().revision,
            documents[1].as_ref().unwrap().revision
        );
    }

    #[test]
    fn rejected_batch_commits_nothing_and_noop_keeps_revision() {
        let (repo, cfg) = database();
        mutate_on(&repo, &cfg, |state| {
            state.target_groups.push(TargetGroup {
                name: "web".into(),
                ..Default::default()
            });
            Ok(())
        })
        .unwrap();
        let (_, before) = read(&repo, &cfg).unwrap();
        let rejected = mutate_on(&repo, &cfg, |state| {
            state.listeners.push(Listener {
                name: "tcp-8080".into(),
                target_group: "web".into(),
                port: 8080,
                target_port: 18080,
                ..Default::default()
            });
            Err::<(), _>(Rejection::new(400, "second import item is invalid"))
        });
        assert!(matches!(rejected, Err(MutationError::Rejected(_))));
        assert_eq!(read(&repo, &cfg).unwrap().1, before);
        assert_eq!(mutate_on(&repo, &cfg, |_| Ok(())).unwrap(), ((), false));
        assert_eq!(read(&repo, &cfg).unwrap().1, before);
    }

    #[test]
    fn reference_validation_is_repeated_after_a_concurrent_commit() {
        let (repo, cfg) = database();
        mutate_on(&repo, &cfg, |state| {
            state.target_groups.push(TargetGroup {
                name: "web".into(),
                ..Default::default()
            });
            Ok(())
        })
        .unwrap();
        let mut first = true;
        let result = mutate_on(&repo, &cfg, |state| {
            if first {
                first = false;
                mutate_on(&repo, &cfg, |newer| {
                    newer.listeners.push(Listener {
                        name: "tcp-8080".into(),
                        target_group: "web".into(),
                        port: 8080,
                        target_port: 18080,
                        ..Default::default()
                    });
                    Ok(())
                })
                .unwrap();
            }
            if state
                .listeners
                .iter()
                .any(|item| item.target_group == "web")
            {
                return Err(Rejection::new(409, "group is referenced"));
            }
            state.target_groups.clear();
            Ok(())
        });
        assert!(matches!(
            result,
            Err(MutationError::Rejected(Rejection { status: 409, .. }))
        ));
        let (state, _) = read(&repo, &cfg).unwrap();
        assert_eq!(state.listeners.len(), 1);
        assert_eq!(state.target_groups.len(), 1);
    }

    #[test]
    fn empty_canonical_snapshot_never_resurrects_stale_runtime_configuration() {
        let (repo, mut cfg) = database();
        repo.put(
            "listeners",
            "config",
            crate::storage::next_revision(),
            "[]".into(),
        )
        .unwrap();
        repo.put(
            "target_groups",
            "config",
            crate::storage::next_revision(),
            "[]".into(),
        )
        .unwrap();
        cfg.file.listeners.push(Listener {
            name: "stale".into(),
            ..Default::default()
        });
        cfg.file.target_groups.push(TargetGroup {
            name: "stale".into(),
            ..Default::default()
        });
        let (state, _) = read(&repo, &cfg).unwrap();
        assert!(state.listeners.is_empty());
        assert!(state.target_groups.is_empty());
        repo.put(
            "listeners",
            "config",
            crate::storage::next_revision(),
            "broken".into(),
        )
        .unwrap();
        assert!(read(&repo, &cfg).is_err());
    }
}
