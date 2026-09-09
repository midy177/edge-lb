#![allow(dead_code)]

use std::{sync::mpsc, thread};

use anyhow::{Context, Result, anyhow};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement, TransactionTrait};
use sha2::{Digest, Sha256};

enum Command {
    GetMany {
        keys: Vec<(String, String)>,
        reply: mpsc::SyncSender<Result<Vec<Option<StoredDocument>>>>,
    },
    CompareAndPut {
        changes: Vec<DocumentChange>,
        guards: Vec<DocumentGuard>,
        revision: i64,
        reply: mpsc::SyncSender<Result<bool>>,
    },
    Get {
        resource_type: String,
        resource_name: String,
        reply: mpsc::SyncSender<Result<Option<String>>>,
    },
    GetDocument {
        resource_type: String,
        resource_name: String,
        reply: mpsc::SyncSender<Result<Option<StoredDocument>>>,
    },
    List {
        resource_type: String,
        reply: mpsc::SyncSender<Result<Vec<String>>>,
    },
    Put {
        resource_type: String,
        resource_name: String,
        revision: i64,
        payload: String,
        reply: mpsc::SyncSender<Result<()>>,
    },
    PutIfChanged {
        resource_type: String,
        resource_name: String,
        revision: i64,
        payload: String,
        reply: mpsc::SyncSender<Result<bool>>,
    },
    Delete {
        resource_type: String,
        resource_name: String,
        revision: i64,
        reply: mpsc::SyncSender<Result<bool>>,
    },
    Prune {
        resource_type: String,
        keep_latest: usize,
        reply: mpsc::SyncSender<Result<u64>>,
    },
}

pub struct Repository {
    tx: mpsc::SyncSender<Command>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocument {
    pub payload: String,
    pub revision: i64,
    pub updated_at: String,
}

pub struct DocumentChange {
    pub resource_type: String,
    pub resource_name: String,
    pub expected_revision: Option<i64>,
    pub payload: String,
}

pub struct DocumentGuard {
    pub resource_type: String,
    pub resource_name: String,
    pub expected_revision: Option<i64>,
}

async fn get_document_on(
    db: &impl ConnectionTrait,
    resource_type: &str,
    resource_name: &str,
) -> Result<Option<StoredDocument>> {
    let row = db.query_one(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "SELECT payload, revision, updated_at FROM resource_documents WHERE resource_type = ? AND resource_name = ?",
        [resource_type.into(), resource_name.into()],
    )).await?;
    row.map(|row| {
        Ok(StoredDocument {
            payload: row.try_get_by_index(0)?,
            revision: row.try_get_by_index(1)?,
            updated_at: row.try_get_by_index(2)?,
        })
    })
    .transpose()
}

async fn compare_and_put(
    db: &impl TransactionTrait,
    changes: Vec<DocumentChange>,
    guards: Vec<DocumentGuard>,
    revision: i64,
) -> Result<bool> {
    let mut keys = std::collections::HashSet::new();
    for change in &changes {
        anyhow::ensure!(
            keys.insert((&change.resource_type, &change.resource_name)),
            "duplicate document in transaction"
        );
    }
    let txn = db.begin().await?;
    for guard in guards {
        let current = get_document_on(&txn, &guard.resource_type, &guard.resource_name).await?;
        if current.as_ref().map(|value| value.revision) != guard.expected_revision {
            txn.rollback().await?;
            return Ok(false);
        }
    }
    for change in &changes {
        let current = get_document_on(&txn, &change.resource_type, &change.resource_name).await?;
        if current.as_ref().map(|value| value.revision) != change.expected_revision {
            txn.rollback().await?;
            return Ok(false);
        }
        anyhow::ensure!(
            change.expected_revision.is_none_or(|old| revision > old),
            "revision must advance"
        );
    }
    let mut digest = Sha256::new();
    for change in &changes {
        for part in [
            &change.resource_type,
            &change.resource_name,
            &change.payload,
        ] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
    }
    let hash = format!("{:x}", digest.finalize());
    txn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO config_revisions (revision, content_hash, source_node, committed_at) VALUES (?, ?, 'edge-lb', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [revision.into(), hash.into()],
    )).await?;
    for change in changes {
        txn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO resource_documents (resource_type, resource_name, revision, payload, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(resource_type, resource_name) DO UPDATE SET revision=excluded.revision, payload=excluded.payload, updated_at=excluded.updated_at",
            [change.resource_type.into(), change.resource_name.into(), revision.into(), change.payload.into()],
        )).await?;
    }
    txn.commit().await?;
    Ok(true)
}

async fn put_if_changed(
    db: &impl TransactionTrait,
    resource_type: String,
    resource_name: String,
    revision: i64,
    payload: String,
) -> Result<bool> {
    let txn = db.begin().await?;
    let current = txn
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "SELECT payload FROM resource_documents WHERE resource_type = ? AND resource_name = ?",
            [resource_type.clone().into(), resource_name.clone().into()],
        ))
        .await?
        .map(|row| row.try_get_by_index::<String>(0))
        .transpose()?;
    if current.as_deref() == Some(payload.as_str()) {
        txn.rollback().await?;
        return Ok(false);
    }
    let mut digest = Sha256::new();
    digest.update(payload.as_bytes());
    let content_hash = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    txn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO config_revisions (revision, content_hash, source_node, committed_at) VALUES (?, ?, 'edge-lb', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        [revision.into(), content_hash.into()],
    )).await?;
    txn.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO resource_documents (resource_type, resource_name, revision, payload, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(resource_type, resource_name) DO UPDATE SET revision=excluded.revision, payload=excluded.payload, updated_at=excluded.updated_at",
        [resource_type.into(), resource_name.into(), revision.into(), payload.into()],
    )).await?;
    txn.commit().await?;
    Ok(true)
}

impl Repository {
    pub fn start(url: String) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<Command>(128);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("edge-lb-storage".to_string())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(anyhow!("building storage runtime: {error}")));
                        return;
                    }
                };
                runtime.block_on(async move {
                    let db = match Database::connect(super::connection_options(&url)).await {
                        Ok(db) => db,
                        Err(error) => {
                            let _ = ready_tx.send(Err(anyhow!("connecting to SQLite: {error}")));
                            return;
                        }
                    };
                    let revision = db.query_one(Statement::from_string(
                        DatabaseBackend::Sqlite,
                        "SELECT COALESCE(MAX(revision), 0) AS revision FROM config_revisions".to_string(),
                    )).await.and_then(|row| row.expect("aggregate revision row").try_get_by_index::<i64>(0));
                    match revision {
                        Ok(revision) => super::observe_revision(revision),
                        Err(error) => {
                            let _ = ready_tx.send(Err(anyhow!("reading SQLite revision floor: {error}")));
                            return;
                        }
                    }
                    let _ = ready_tx.send(Ok(()));
                    while let Ok(command) = rx.recv() {
                        match command {
                            Command::GetMany { keys, reply } => {
                                let result = async {
                                    let txn = db.begin().await?;
                                    let mut documents = Vec::with_capacity(keys.len());
                                    for (resource_type, resource_name) in keys {
                                        documents.push(get_document_on(&txn, &resource_type, &resource_name).await?);
                                    }
                                    txn.commit().await?;
                                    Ok(documents)
                                }.await;
                                let _ = reply.send(result);
                            }
                            Command::CompareAndPut { changes, guards, revision, reply } => {
                                let _ = reply.send(compare_and_put(&db, changes, guards, revision).await);
                            }
                            Command::Get { resource_type, resource_name, reply } => {
                                let result = async {
                                    let statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "SELECT payload FROM resource_documents WHERE resource_type = ? AND resource_name = ?",
                                        [resource_type.into(), resource_name.into()],
                                    );
                                    let row = db.query_one(statement).await?;
                                    row.map(|row| row.try_get_by_index::<String>(0)).transpose()
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                            Command::GetDocument { resource_type, resource_name, reply } => {
                                let result = async {
                                    let statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "SELECT payload, revision, updated_at FROM resource_documents WHERE resource_type = ? AND resource_name = ?",
                                        [resource_type.into(), resource_name.into()],
                                    );
                                    let row = db.query_one(statement).await?;
                                    row.map(|row| {
                                        Ok(StoredDocument {
                                            payload: row.try_get_by_index::<String>(0)?,
                                            revision: row.try_get_by_index::<i64>(1)?,
                                            updated_at: row.try_get_by_index::<String>(2)?,
                                        })
                                    })
                                    .transpose()
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                            Command::List { resource_type, reply } => {
                                let result = async {
                                    let statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "SELECT payload FROM resource_documents WHERE resource_type = ? ORDER BY resource_name",
                                        [resource_type.into()],
                                    );
                                    let rows = db.query_all(statement).await?;
                                    rows.into_iter().map(|row| row.try_get_by_index::<String>(0)).collect::<Result<Vec<_>, _>>()
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                            Command::Put { resource_type, resource_name, revision, payload, reply } => {
                                let result = async {
                                    let mut digest = Sha256::new();
                                    digest.update(payload.as_bytes());
                                    let content_hash = digest
                                        .finalize()
                                        .iter()
                                        .map(|byte| format!("{byte:02x}"))
                                        .collect::<String>();
                                    let txn = db.begin().await?;
                                    let revision_statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "INSERT INTO config_revisions (revision, content_hash, source_node, committed_at) VALUES (?, ?, 'edge-lb', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                                        [revision.into(), content_hash.into()],
                                    );
                                    txn.execute(revision_statement).await?;
                                    let document_statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "INSERT INTO resource_documents (resource_type, resource_name, revision, payload, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(resource_type, resource_name) DO UPDATE SET revision=excluded.revision, payload=excluded.payload, updated_at=excluded.updated_at",
                                        [resource_type.into(), resource_name.into(), revision.into(), payload.into()],
                                    );
                                    txn.execute(document_statement).await?;
                                    txn.commit().await
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                            Command::PutIfChanged { resource_type, resource_name, revision, payload, reply } => {
                                let result = put_if_changed(
                                    &db,
                                    resource_type,
                                    resource_name,
                                    revision,
                                    payload,
                                )
                                .await;
                                let _ = reply.send(result);
                            }
                            Command::Delete { resource_type, resource_name, revision, reply } => {
                                let result = async {
                                    let txn = db.begin().await?;
                                    let revision_statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "INSERT INTO config_revisions (revision, content_hash, source_node, committed_at) VALUES (?, '', 'edge-lb', strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                                        [revision.into()],
                                    );
                                    txn.execute(revision_statement).await?;
                                    let statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "DELETE FROM resource_documents WHERE resource_type = ? AND resource_name = ?",
                                        [resource_type.into(), resource_name.into()],
                                    );
                                    let changed = txn.execute(statement).await?.rows_affected() > 0;
                                    txn.commit().await?;
                                    Ok(changed)
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                            Command::Prune { resource_type, keep_latest, reply } => {
                                let result = async {
                                    let statement = Statement::from_sql_and_values(
                                        DatabaseBackend::Sqlite,
                                        "DELETE FROM resource_documents
                                         WHERE resource_type = ?
                                           AND resource_name NOT IN (
                                             SELECT resource_name
                                             FROM resource_documents
                                             WHERE resource_type = ?
                                             ORDER BY revision DESC, resource_name DESC
                                             LIMIT ?
                                           )",
                                        [resource_type.clone().into(), resource_type.into(), (keep_latest as i64).into()],
                                    );
                                    db.execute(statement).await.map(|result| result.rows_affected())
                                }.await.map_err(|error: sea_orm::DbErr| anyhow!(error));
                                let _ = reply.send(result);
                            }
                        };
                    }
                });
            })
            .context("starting SQLite storage thread")?;
        ready_rx.recv().context("waiting for SQLite storage")??;
        Ok(Self { tx })
    }

    pub fn get(&self, resource_type: &str, resource_name: &str) -> Result<Option<String>> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::Get {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            reply,
        })?;
        rx.recv().context("reading SQLite resource")?
    }

    pub fn get_many(&self, keys: Vec<(String, String)>) -> Result<Vec<Option<StoredDocument>>> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::GetMany { keys, reply })?;
        rx.recv().context("reading SQLite snapshot")?
    }

    pub fn compare_and_put(&self, changes: Vec<DocumentChange>, revision: i64) -> Result<bool> {
        self.compare_and_put_guarded(changes, Vec::new(), revision)
    }

    pub fn compare_and_put_guarded(
        &self,
        changes: Vec<DocumentChange>,
        guards: Vec<DocumentGuard>,
        revision: i64,
    ) -> Result<bool> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::CompareAndPut {
            changes,
            guards,
            revision,
            reply,
        })?;
        rx.recv().context("committing SQLite snapshot")?
    }

    pub fn get_document(
        &self,
        resource_type: &str,
        resource_name: &str,
    ) -> Result<Option<StoredDocument>> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::GetDocument {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            reply,
        })?;
        rx.recv().context("reading SQLite resource document")?
    }

    pub fn list(&self, resource_type: &str) -> Result<Vec<String>> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::List {
            resource_type: resource_type.into(),
            reply,
        })?;
        rx.recv().context("listing SQLite resources")?
    }

    pub fn put(
        &self,
        resource_type: &str,
        resource_name: &str,
        revision: i64,
        payload: String,
    ) -> Result<()> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::Put {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            revision,
            payload,
            reply,
        })?;
        rx.recv().context("writing SQLite resource")?
    }

    pub fn put_if_changed(
        &self,
        resource_type: &str,
        resource_name: &str,
        revision: i64,
        payload: String,
    ) -> Result<bool> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::PutIfChanged {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            revision,
            payload,
            reply,
        })?;
        rx.recv().context("writing changed SQLite resource")?
    }

    pub fn delete(&self, resource_type: &str, resource_name: &str) -> Result<bool> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::Delete {
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            revision: crate::storage::next_revision(),
            reply,
        })?;
        rx.recv().context("deleting SQLite resource")?
    }

    pub fn prune_resource(&self, resource_type: &str, keep_latest: usize) -> Result<u64> {
        let (reply, rx) = mpsc::sync_channel(1);
        self.tx.send(Command::Prune {
            resource_type: resource_type.into(),
            keep_latest,
            reply,
        })?;
        rx.recv().context("pruning SQLite resources")?
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{DocumentChange, Repository};
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    #[test]
    fn compare_and_put_rolls_back_every_document_and_revision_on_sql_failure() {
        let (_path, url) = temporary_database_url();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(super::super::initialize_async(&url))
            .unwrap();
        let db = runtime.block_on(Database::connect(&url)).unwrap();
        runtime.block_on(db.execute(Statement::from_string(DatabaseBackend::Sqlite,
            "CREATE TRIGGER reject_group BEFORE INSERT ON resource_documents WHEN NEW.resource_type = 'target_groups' BEGIN SELECT RAISE(ABORT, 'injected failure'); END".to_string()
        ))).unwrap();
        let repo = Repository::start(url).unwrap();
        let changes = ["listeners", "target_groups"]
            .map(|name| DocumentChange {
                resource_type: name.into(),
                resource_name: "config".into(),
                expected_revision: None,
                payload: "[]".into(),
            })
            .into();
        assert!(repo.compare_and_put(changes, 1).is_err());
        assert!(repo.get("listeners", "config").unwrap().is_none());
        assert!(repo.get("target_groups", "config").unwrap().is_none());
        let row = runtime
            .block_on(db.query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM config_revisions".to_string(),
            )))
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), 0);
        runtime.block_on(db.close()).unwrap();
    }

    #[test]
    fn compare_and_put_rejects_stale_read_set_without_touching_other_documents() {
        let (_path, url) = temporary_database_url();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(super::super::initialize_async(&url))
            .unwrap();
        let repo = Repository::start(url).unwrap();
        repo.put("target_groups", "config", 1, "new".into())
            .unwrap();
        let changes = ["listeners", "target_groups"]
            .map(|name| DocumentChange {
                resource_type: name.into(),
                resource_name: "config".into(),
                expected_revision: None,
                payload: "stale".into(),
            })
            .into();
        assert!(!repo.compare_and_put(changes, 2).unwrap());
        assert!(repo.get("listeners", "config").unwrap().is_none());
        assert_eq!(
            repo.get("target_groups", "config").unwrap().as_deref(),
            Some("new")
        );
    }

    fn temporary_database_url() -> (PathBuf, String) {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("edge-lb-storage-{suffix}.sqlite3"));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        (path, url)
    }

    #[test]
    fn repository_round_trip_and_delete_are_transactional() {
        let (path, url) = temporary_database_url();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        runtime
            .block_on(super::super::initialize_async(&url))
            .expect("initialize test database");

        let repository = Repository::start(url).expect("start repository");
        repository
            .put(
                "listeners",
                "config",
                1,
                r#"[{"name":"tcp-80"}]"#.to_string(),
            )
            .expect("write resource");
        assert_eq!(
            repository
                .get("listeners", "config")
                .expect("read resource")
                .as_deref(),
            Some(r#"[{"name":"tcp-80"}]"#)
        );
        assert_eq!(
            repository.list("listeners").expect("list resources"),
            vec![r#"[{"name":"tcp-80"}]"#]
        );
        assert!(
            repository
                .put(
                    "listeners",
                    "config",
                    1,
                    r#"[{"name":"should-not-commit"}]"#.to_string()
                )
                .is_err()
        );
        assert_eq!(
            repository
                .get("listeners", "config")
                .expect("read after rejected revision")
                .as_deref(),
            Some(r#"[{"name":"tcp-80"}]"#)
        );
        assert!(
            repository
                .delete("listeners", "config")
                .expect("delete resource")
        );
        assert_eq!(
            repository.get("listeners", "config").expect("read deleted"),
            None
        );
        assert!(
            !repository
                .delete("listeners", "config")
                .expect("delete missing")
        );

        drop(repository);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn prune_resource_keeps_newest_documents_for_one_type_only() {
        let (path, url) = temporary_database_url();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime")
            .block_on(super::super::initialize_async(&url))
            .expect("initialize test database");

        let repository = Repository::start(url).expect("start repository");
        for revision in 1..=5 {
            repository
                .put(
                    "notification_deliveries",
                    &format!("delivery-{revision}"),
                    revision,
                    format!("delivery-{revision}"),
                )
                .expect("write delivery");
        }
        repository
            .put("listeners", "config", 6, "listener".to_string())
            .expect("write unrelated resource");

        assert_eq!(
            repository
                .prune_resource("notification_deliveries", 2)
                .expect("prune deliveries"),
            3
        );
        assert_eq!(
            repository
                .list("notification_deliveries")
                .expect("list deliveries"),
            vec!["delivery-4", "delivery-5"]
        );
        assert_eq!(
            repository.list("listeners").expect("list listeners"),
            vec!["listener"]
        );
        assert_eq!(
            repository
                .prune_resource("notification_deliveries", 0)
                .expect("prune all deliveries"),
            2
        );
        assert!(
            repository
                .list("notification_deliveries")
                .expect("list empty deliveries")
                .is_empty()
        );

        drop(repository);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn put_if_changed_skips_identical_payload_without_new_revision() {
        let (path, url) = temporary_database_url();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        runtime
            .block_on(super::super::initialize_async(&url))
            .expect("initialize test database");

        let repository = Repository::start(url.clone()).expect("start repository");
        assert!(
            repository
                .put_if_changed("automation", "config", 1, "same".to_string())
                .expect("write first payload")
        );
        assert!(
            !repository
                .put_if_changed("automation", "config", 2, "same".to_string())
                .expect("skip identical payload")
        );
        assert!(
            repository
                .put_if_changed("automation", "config", 3, "changed".to_string())
                .expect("write changed payload")
        );
        assert_eq!(
            repository
                .get_document("automation", "config")
                .expect("read document")
                .expect("document exists")
                .revision,
            3
        );
        drop(repository);

        let db = runtime
            .block_on(Database::connect(&url))
            .expect("connect test database");
        let revision_count = runtime
            .block_on(db.query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM config_revisions".to_string(),
            )))
            .expect("count revisions")
            .expect("count row")
            .try_get_by_index::<i64>(0)
            .expect("read count");
        assert_eq!(revision_count, 2);
        runtime.block_on(db.close()).expect("close db");
        std::fs::remove_file(path).expect("remove test database");
    }
}
