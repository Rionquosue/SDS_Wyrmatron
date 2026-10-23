//! SQLite access. One connection runs on a dedicated thread behind
//! `tokio-rusqlite`, so synchronous calls never block the async executor.
//! Write transactions use `BEGIN IMMEDIATE` (SDS §2, SQLite configuration).

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use rusqlite_migration::{Migrations, M};

const MIGRATIONS: &[M<'static>] = &[M::up(include_str!("../migrations/0001_initial.sql"))];

#[derive(Clone)]
pub struct Db {
    conn: tokio_rusqlite::Connection,
}

/// Current UTC time as Unix seconds.
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

fn configure(conn: &mut Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.pragma_update(None, "journal_size_limit", 64 * 1024 * 1024)?;
    conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
    Ok(())
}

impl Db {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let conn = tokio_rusqlite::Connection::open(path)
            .await
            .with_context(|| format!("opening database {}", path.display()))?;
        Self::init(conn).await
    }

    pub async fn open_in_memory() -> Result<Self> {
        Self::init(tokio_rusqlite::Connection::open_in_memory().await?).await
    }

    async fn init(conn: tokio_rusqlite::Connection) -> Result<Self> {
        conn.call(|c| -> Result<()> {
            configure(c)?;
            Migrations::from_slice(MIGRATIONS).to_latest(c)?;
            Ok(())
        })
        .await
        .map_err(flatten)?;
        Ok(Self { conn })
    }

    /// Runs `f` on the database thread.
    pub async fn read<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Connection) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        self.conn.call(move |c| f(c)).await.map_err(flatten)
    }

    /// Runs `f` inside a `BEGIN IMMEDIATE` transaction and commits on success.
    pub async fn write<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Transaction<'_>) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        self.conn
            .call(move |c| -> Result<R> {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let out = f(&tx)?;
                tx.commit()?;
                Ok(out)
            })
            .await
            .map_err(flatten)
    }

    /// Truncating checkpoint, run periodically to bound WAL growth.
    pub async fn checkpoint(&self) -> Result<()> {
        self.read(|c| {
            c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
            Ok(())
        })
        .await
    }

    pub async fn get_kv(&self, key: &'static str) -> Result<Option<String>> {
        self.read(move |c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0)).optional()?)
        })
        .await
    }
}

fn flatten(e: tokio_rusqlite::Error<anyhow::Error>) -> anyhow::Error {
    match e {
        tokio_rusqlite::Error::Error(e) => e,
        tokio_rusqlite::Error::ConnectionClosed => anyhow::anyhow!("database connection closed"),
        tokio_rusqlite::Error::Close((_, e)) => anyhow::Error::new(e).context("closing database"),
        _ => anyhow::anyhow!("database error"),
    }
}

/// Sets a key/value entry inside an existing transaction.
pub fn set_kv(tx: &Transaction<'_>, key: &str, value: &str) -> rusqlite::Result<()> {
    tx.execute(
        "INSERT INTO kv (key, value) VALUES (?1, ?2) ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_valid() {
        Migrations::from_slice(MIGRATIONS).validate().unwrap();
    }

    #[tokio::test]
    async fn opens_and_round_trips_kv() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.sqlite3")).await.unwrap();
        db.write(|tx| Ok(set_kv(tx, "offset", "42")?)).await.unwrap();
        assert_eq!(db.get_kv("offset").await.unwrap().as_deref(), Some("42"));
        let mode: String = db.read(|c| Ok(c.query_row("PRAGMA journal_mode", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(mode, "wal");
        let fk: i64 = db.read(|c| Ok(c.query_row("PRAGMA foreign_keys", [], |r| r.get(0))?)).await.unwrap();
        assert_eq!(fk, 1);
        db.checkpoint().await.unwrap();
    }
}
