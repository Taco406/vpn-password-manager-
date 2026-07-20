//! Local encrypted-at-rest vault store (SQLite). Rows hold sealed item envelopes; the
//! store never sees the vault key. A stolen `vault.db` is opaque ciphertext
//! (SECURITY.md T2).

use super::document::VaultDocument;
use super::envelope::{envelope_meta, ItemEnvelope};
use crate::error::Result;
use rusqlite::Connection;
use uuid::Uuid;

pub struct LocalVault {
    conn: Connection,
}

/// Outcome of merging a remote document into the local store.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub conflicts: usize,
}

impl LocalVault {
    /// Open (creating if needed) a vault at `path`. Use `":memory:"` for tests.
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        // The browser-autofill native-messaging host opens this same vault.db while the desktop
        // app also has it open, so a save from one can race a write from the other. A busy
        // timeout makes the loser wait for the lock instead of failing immediately with BUSY.
        let _ = conn.busy_timeout(std::time::Duration::from_secs(3));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS items (
                 id BLOB PRIMARY KEY,
                 envelope BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tombstones (
                 id BLOB PRIMARY KEY,
                 deleted_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
        )?;
        Ok(LocalVault { conn })
    }

    /// Insert or replace a sealed item.
    pub fn upsert(&self, env: &ItemEnvelope) -> Result<()> {
        let (id, updated_at) = envelope_meta(env)?;
        self.conn.execute(
            "INSERT INTO items (id, envelope, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET envelope = excluded.envelope, updated_at = excluded.updated_at",
            rusqlite::params![id.as_bytes().to_vec(), env.0, updated_at],
        )?;
        // Clear any tombstone for a resurrected id.
        self.conn.execute(
            "DELETE FROM tombstones WHERE id = ?1",
            [id.as_bytes().to_vec()],
        )?;
        Ok(())
    }

    /// Fetch a single sealed item.
    pub fn get(&self, id: Uuid) -> Result<Option<ItemEnvelope>> {
        let mut stmt = self
            .conn
            .prepare("SELECT envelope FROM items WHERE id = ?1")?;
        let mut rows = stmt.query([id.as_bytes().to_vec()])?;
        if let Some(row) = rows.next()? {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(Some(ItemEnvelope(bytes)))
        } else {
            Ok(None)
        }
    }

    /// All sealed items, newest first.
    pub fn list_envelopes(&self) -> Result<Vec<ItemEnvelope>> {
        let mut stmt = self
            .conn
            .prepare("SELECT envelope FROM items ORDER BY updated_at DESC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        Ok(rows.filter_map(|r| r.ok()).map(ItemEnvelope).collect())
    }

    /// Delete an item and record a tombstone at `deleted_at`.
    pub fn delete(&self, id: Uuid, deleted_at: i64) -> Result<()> {
        self.conn
            .execute("DELETE FROM items WHERE id = ?1", [id.as_bytes().to_vec()])?;
        self.conn.execute(
            "INSERT INTO tombstones (id, deleted_at) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET deleted_at = excluded.deleted_at",
            rusqlite::params![id.as_bytes().to_vec(), deleted_at],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<usize> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Build a document snapshot of the whole local vault for syncing.
    pub fn to_document(&self) -> Result<VaultDocument> {
        let envs = self.list_envelopes()?;
        let mut stmt = self.conn.prepare("SELECT id, deleted_at FROM tombstones")?;
        let tombstones = stmt
            .query_map([], |row| {
                let id: Vec<u8> = row.get(0)?;
                let ts: i64 = row.get(1)?;
                Ok((id, ts))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, ts)| {
                let a: [u8; 16] = id.try_into().ok()?;
                Some((Uuid::from_bytes(a), ts))
            })
            .collect();
        Ok(VaultDocument::from_envelopes(&envs, tombstones))
    }

    /// Merge a remote document. Conflict rule: newest `updated_at` wins; tombstones
    /// newer than a local item delete it. Returns what changed.
    pub fn merge(&self, remote: &VaultDocument) -> Result<MergeReport> {
        let mut report = MergeReport::default();

        for env in remote.envelopes()? {
            let (id, remote_ts) = envelope_meta(&env)?;
            let local_ts: Option<i64> = self
                .conn
                .query_row(
                    "SELECT updated_at FROM items WHERE id = ?1",
                    [id.as_bytes().to_vec()],
                    |r| r.get(0),
                )
                .ok();
            match local_ts {
                None => {
                    self.upsert(&env)?;
                    report.added += 1;
                }
                Some(l) if remote_ts > l => {
                    self.upsert(&env)?;
                    report.updated += 1;
                }
                Some(l) if remote_ts < l => {
                    report.conflicts += 1; // local is newer; keep it
                }
                Some(_) => {} // equal: no-op
            }
        }

        for (id, deleted_at) in &remote.tombstones {
            let local_ts: Option<i64> = self
                .conn
                .query_row(
                    "SELECT updated_at FROM items WHERE id = ?1",
                    [id.as_bytes().to_vec()],
                    |r| r.get(0),
                )
                .ok();
            if let Some(l) = local_ts {
                if *deleted_at >= l {
                    self.delete(*id, *deleted_at)?;
                    report.deleted += 1;
                }
            }
        }

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::VaultKey;
    use crate::vault::envelope::{open_item, seal_item};
    use crate::vault::model::Item;

    #[test]
    fn upsert_get_list_delete() {
        let vk = VaultKey::generate();
        let store = LocalVault::open(":memory:").unwrap();
        let item = Item::new_login("A", 100);
        let env = seal_item(&vk, &item).unwrap();
        store.upsert(&env).unwrap();
        assert_eq!(store.count().unwrap(), 1);

        let got = store.get(item.id).unwrap().unwrap();
        assert_eq!(open_item(&vk, &got).unwrap().title, "A");

        store.delete(item.id, 200).unwrap();
        assert_eq!(store.count().unwrap(), 0);
        assert!(store.get(item.id).unwrap().is_none());
    }

    #[test]
    fn merge_newest_wins_and_tombstones_delete() {
        let vk = VaultKey::generate();
        let store = LocalVault::open(":memory:").unwrap();

        // Local item at t=100.
        let mut item = Item::new_login("orig", 100);
        store.upsert(&seal_item(&vk, &item).unwrap()).unwrap();

        // Remote has a newer version of the same id at t=200.
        item.updated_at = 200;
        item.title = "newer".into();
        let remote = VaultDocument::from_envelopes(&[seal_item(&vk, &item).unwrap()], vec![]);
        let r = store.merge(&remote).unwrap();
        assert_eq!(r.updated, 1);
        let got = open_item(&vk, &store.get(item.id).unwrap().unwrap()).unwrap();
        assert_eq!(got.title, "newer");

        // Remote tombstone newer than local deletes it.
        let tomb = VaultDocument::from_envelopes(&[], vec![(item.id, 300)]);
        let r = store.merge(&tomb).unwrap();
        assert_eq!(r.deleted, 1);
        assert_eq!(store.count().unwrap(), 0);
    }

    #[test]
    fn merge_keeps_local_when_newer() {
        let vk = VaultKey::generate();
        let store = LocalVault::open(":memory:").unwrap();
        let mut item = Item::new_login("local-new", 500);
        store.upsert(&seal_item(&vk, &item).unwrap()).unwrap();

        item.updated_at = 100; // stale remote
        item.title = "remote-old".into();
        let remote = VaultDocument::from_envelopes(&[seal_item(&vk, &item).unwrap()], vec![]);
        let r = store.merge(&remote).unwrap();
        assert_eq!(r.conflicts, 1);
        let got = open_item(&vk, &store.get(item.id).unwrap().unwrap()).unwrap();
        assert_eq!(got.title, "local-new");
    }
}
