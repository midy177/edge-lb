//! SQLite persistence foundation for gateway business configuration.

pub mod entity;
pub mod proxy_config;
pub mod proxy_replication;
mod repository;

use std::{
    fs::File,
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseBackend, Statement};

static REPOSITORY: OnceLock<Arc<repository::Repository>> = OnceLock::new();
static STORAGE_LOCK: OnceLock<File> = OnceLock::new();
static LAST_REVISION: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS schema_meta (\n    key TEXT PRIMARY KEY NOT NULL,\n    value TEXT NOT NULL\n);\nCREATE TABLE IF NOT EXISTS config_revisions (\n    revision INTEGER PRIMARY KEY NOT NULL,\n    content_hash TEXT NOT NULL,\n    source_node TEXT NOT NULL,\n    committed_at TEXT NOT NULL\n);\nCREATE TABLE IF NOT EXISTS resource_documents (\n    resource_type TEXT NOT NULL,\n    resource_name TEXT NOT NULL,\n    revision INTEGER NOT NULL,\n    payload TEXT NOT NULL,\n    updated_at TEXT NOT NULL,\n    PRIMARY KEY (resource_type, resource_name),\n    FOREIGN KEY (revision) REFERENCES config_revisions(revision)\n);\nCREATE INDEX IF NOT EXISTS resource_documents_revision_idx\n    ON resource_documents(revision);\n";
const SCHEMA_VERSION: &str = "1";

pub fn initialize(state_dir: &Path) -> Result<()> {
    if REPOSITORY.get().is_some() {
        return Ok(());
    }
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating state directory {}", state_dir.display()))?;
    let lock = acquire_process_lock(state_dir)?;
    let path = state_dir.join("edge-lb.sqlite3");
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building storage initialization runtime")?;
    runtime.block_on(initialize_async(&url))?;
    let repo = repository::Repository::start(url)?;
    let _ = STORAGE_LOCK.set(lock);
    let _ = REPOSITORY.set(Arc::new(repo));
    tracing::debug!(
        "[storage] SQLite database initialized at {}",
        path.display()
    );
    Ok(())
}

fn acquire_process_lock(state_dir: &Path) -> Result<File> {
    let path = state_dir.join("edge-lb.process.lock");
    let file = File::create(&path)
        .with_context(|| format!("creating SQLite process lock {}", path.display()))?;
    #[cfg(unix)]
    {
        let result = unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("acquiring SQLite process lock {}", path.display()));
        }
    }
    Ok(file)
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

pub(super) fn observe_revision(revision: i64) {
    LAST_REVISION.fetch_max(revision, std::sync::atomic::Ordering::Relaxed);
}

fn connection_options(url: &str) -> ConnectOptions {
    let mut options = ConnectOptions::new(url);
    options
        .sqlx_logging(false)
        .max_connections(1)
        .min_connections(1);
    // Apply connection-local settings to every connection, including a pool
    // replacement, rather than only the temporary schema initialization handle.
    options.map_sqlx_sqlite_opts(|options| {
        options
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5))
            .pragma("journal_mode", "WAL")
            .pragma("synchronous", "FULL")
    });
    options
}

async fn initialize_async(url: &str) -> Result<()> {
    let db = Database::connect(connection_options(url))
        .await
        .with_context(|| format!("connecting to SQLite database {url}"))?;
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
    use super::*;
    use sea_orm::TransactionTrait;
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

    #[test]
    #[cfg(unix)]
    fn process_lock_rejects_a_second_manager_for_the_same_state_dir() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("edge-lb-process-lock-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        let first = acquire_process_lock(&dir).unwrap();
        assert!(acquire_process_lock(&dir).is_err());
        drop(first);
        assert!(acquire_process_lock(&dir).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sqlite_profile_and_foreign_keys_apply_to_each_connection_and_reopen() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "edge-lb-profile-{}-{nonce}.sqlite3",
            std::process::id()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            initialize_async(&url).await.unwrap();
            for _ in 0..2 {
                let mut options = connection_options(&url);
                assert_eq!(options.get_max_connections(), Some(1));
                // Keep the first transaction checked out to force a second
                // physical connection, then repeat after closing the pool.
                options.max_connections(2).acquire_timeout(Duration::from_secs(5));
                let db = Database::connect(options).await.unwrap();
                let first = db.begin().await.unwrap();
                let second = db.begin().await.unwrap();
                for tx in [first, second] {
                    let row = tx.query_one(Statement::from_string(DatabaseBackend::Sqlite,
                        "PRAGMA journal_mode")).await.unwrap().unwrap();
                    assert_eq!(row.try_get_by_index::<String>(0).unwrap(), "wal");
                    for (pragma, expected) in [("foreign_keys", 1_i64), ("busy_timeout", 5000), ("synchronous", 2)] {
                        let row = tx.query_one(Statement::from_string(DatabaseBackend::Sqlite,
                            format!("PRAGMA {pragma}"))).await.unwrap().unwrap();
                        assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), expected, "{pragma}");
                    }
                    let orphan = tx.execute(Statement::from_string(DatabaseBackend::Sqlite,
                        "INSERT INTO resource_documents (resource_type, resource_name, revision, payload, updated_at) VALUES ('test', 'orphan', -1, '{}', 'test')")).await;
                    assert!(orphan.unwrap_err().to_string().contains("FOREIGN KEY constraint failed"));
                    tx.rollback().await.unwrap();
                }
                db.close().await.unwrap();
            }
        });
        fs::remove_file(&path).unwrap();
        for suffix in ["-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn remove_database(path: PathBuf) {
        fs::remove_file(path).expect("remove corrupt database");
    }
}
