//! SQLite persistence foundation for gateway business configuration.

pub mod entity;
mod repository;

use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement,
};

static REPOSITORY: OnceLock<Arc<repository::Repository>> = OnceLock::new();
static LAST_REVISION: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS schema_meta (\n    key TEXT PRIMARY KEY NOT NULL,\n    value TEXT NOT NULL\n);\nCREATE TABLE IF NOT EXISTS config_revisions (\n    revision INTEGER PRIMARY KEY NOT NULL,\n    content_hash TEXT NOT NULL,\n    source_node TEXT NOT NULL,\n    committed_at TEXT NOT NULL\n);\nCREATE TABLE IF NOT EXISTS resource_documents (\n    resource_type TEXT NOT NULL,\n    resource_name TEXT NOT NULL,\n    revision INTEGER NOT NULL,\n    payload TEXT NOT NULL,\n    updated_at TEXT NOT NULL,\n    PRIMARY KEY (resource_type, resource_name),\n    FOREIGN KEY (revision) REFERENCES config_revisions(revision)\n);\nCREATE INDEX IF NOT EXISTS resource_documents_revision_idx\n    ON resource_documents(revision);\n";
const SCHEMA_VERSION: &str = "1";

pub fn initialize(state_dir: &Path) -> Result<()> {
    if REPOSITORY.get().is_some() {
        return Ok(());
    }
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating state directory {}", state_dir.display()))?;
    let path = state_dir.join("edge-lb.sqlite3");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building storage initialization runtime")?;
    runtime.block_on(initialize_async(&url))?;
    let repo = repository::Repository::start(url)?;
    let _ = REPOSITORY.set(Arc::new(repo));
    tracing::debug!(
        "[storage] SQLite database initialized at {}",
        path.display()
    );
    Ok(())
}

pub fn repository() -> Result<Arc<repository::Repository>> {
    REPOSITORY
        .get()
        .cloned()
        .context("SQLite storage is not initialized")
}

pub fn next_revision() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or_default();
    loop {
        let previous = LAST_REVISION.load(std::sync::atomic::Ordering::Relaxed);
        let next = now.max(previous.saturating_add(1));
        if LAST_REVISION
            .compare_exchange(
                previous,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return next;
        }
    }
}

async fn initialize_async(url: &str) -> Result<()> {
    let mut options = ConnectOptions::new(url);
    options.sqlx_logging(false);
    let db = Database::connect(options)
        .await
        .with_context(|| format!("connecting to SQLite database {url}"))?;
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "PRAGMA journal_mode=WAL".to_string(),
    ))
    .await
    .context("enabling SQLite WAL")?;
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "PRAGMA foreign_keys=ON".to_string(),
    ))
    .await
    .context("enabling SQLite foreign keys")?;
    db.execute(Statement::from_string(
        DatabaseBackend::Sqlite,
        "PRAGMA busy_timeout=5000".to_string(),
    ))
    .await
    .context("setting SQLite busy timeout")?;
    for statement in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        db.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            statement.to_string(),
        ))
        .await
        .context("applying SQLite schema")?;
    }
    db.execute(Statement::from_sql_and_values(
        DatabaseBackend::Sqlite,
        "INSERT INTO schema_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        ["schema_version".into(), SCHEMA_VERSION.into()],
    ))
    .await
    .context("recording SQLite schema version")?;
    db.close().await.context("closing SQLite connection")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn corrupted_database_is_rejected() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("edge-lb-corrupt-{suffix}.sqlite3"));
        fs::write(&path, b"not a sqlite database").expect("write corrupt database");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");

        assert!(runtime.block_on(super::initialize_async(&url)).is_err());
        remove_database(path);
    }

    fn remove_database(path: PathBuf) {
        fs::remove_file(path).expect("remove corrupt database");
    }
}

#[allow(dead_code)]
fn _connection_type_is_sea_orm(_: DatabaseConnection) {}
