#![allow(dead_code)]

use std::{sync::mpsc, thread};

use anyhow::{Context, Result, anyhow};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement, TransactionTrait,
};
use sha2::{Digest, Sha256};

enum Command {
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
    Delete {
        resource_type: String,
        resource_name: String,
        revision: i64,
        reply: mpsc::SyncSender<Result<bool>>,
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
                    let mut options = ConnectOptions::new(&url);
                    options.sqlx_logging(false);
                    let db = match Database::connect(options).await {
                        Ok(db) => db,
                        Err(error) => {
                            let _ = ready_tx.send(Err(anyhow!("connecting to SQLite: {error}")));
                            return;
                        }
                    };
                    let _ = ready_tx.send(Ok(()));
                    while let Ok(command) = rx.recv() {
                        match command {
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
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::Repository;

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
}
