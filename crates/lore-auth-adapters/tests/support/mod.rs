use std::path::{Path, PathBuf};

use lore_auth_adapters::sqlite::Store;
use rusqlite::Connection as RawConnection;

pub struct TestStore {
    pub store: Store,
    pub path: PathBuf,
    _dir: tempfile::TempDir,
}

pub async fn migrated_store() -> TestStore {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("test.sqlite3");
    let store = Store::open(&path).await.expect("open sqlite");
    store.migrate().await.expect("migrate sqlite");
    TestStore {
        store,
        path,
        _dir: dir,
    }
}

pub fn raw_connection(path: &Path) -> RawConnection {
    RawConnection::open(path).expect("open raw sqlite")
}
