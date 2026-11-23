//! Ordered schema migrations, shared by the project file and the account database.
//!
//! Each database has a list of [`Migration`]s numbered 1, 2, 3 and so on. A database's `user_version` says how many
//! of them it has had. Opening runs the missing ones in order, each in its own transaction that also records the new
//! version, so a migration that fails leaves the file as it was. Migrations that have shipped are never edited: a
//! change is a new entry at the end of the list.

use std::path::PathBuf;

use rusqlite::{Connection, OptionalExtension};

use crate::StoreError;

/// One step of a schema's history.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// 1 for the first, then counting up with no gaps.
    pub version: i64,
    /// The step drops and recreates a table that others refer to. The runner turns reference checks off while it
    /// runs and checks them all before committing.
    pub rebuild: bool,
    /// What it does, for the error message when it fails.
    pub what: &'static str,
    /// The SQL. Do not set `user_version` here; the runner does, in the same transaction.
    pub sql: &'static str,
}

/// The version a database is at once every migration in the list has run.
pub fn latest(migrations: &[Migration]) -> i64 {
    migrations.last().map_or(0, |m| m.version)
}

/// Where the copy of a database goes before it is migrated away from `from`.
pub fn backup_path(db: &str, from: i64) -> PathBuf {
    PathBuf::from(format!("{db}.pre-v{from}.bak"))
}

/// Bring `conn` up to the newest version in `migrations`.
///
/// A database that already has content is copied to `<file>.pre-v<N>.bak` first (when it lives in a file). Files
/// from a newer Bosun are refused. Only a list in order, starting at 1, is accepted.
pub fn run(conn: &mut Connection, migrations: &[Migration]) -> Result<(), StoreError> {
    for (i, m) in migrations.iter().enumerate() {
        if m.version != i as i64 + 1 {
            return Err(StoreError::Migration(format!(
                "the migration list is out of order at entry {} (version {})",
                i + 1,
                m.version
            )));
        }
    }
    let have: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let want = latest(migrations);
    if have > want {
        return Err(StoreError::NewerSchema(have));
    }
    if have == want {
        return Ok(());
    }
    if have >= 1 {
        back_up(conn, have)?;
    }
    for m in migrations.iter().filter(|m| m.version > have) {
        let fail = |e: &dyn std::fmt::Display| {
            StoreError::Migration(format!("step {} ({}): {e}", m.version, m.what))
        };
        // The pragma has no effect inside a transaction, so it is set around it.
        let checks: bool = conn.pragma_query_value(None, "foreign_keys", |r| r.get(0))?;
        if m.rebuild && checks {
            conn.pragma_update(None, "foreign_keys", "OFF")?;
        }
        let result = (|| {
            let tx = conn.transaction()?;
            tx.execute_batch(m.sql).map_err(|e| fail(&e))?;
            if m.rebuild {
                let broken: Option<String> = tx
                    .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
                    .optional()?;
                if let Some(table) = broken {
                    return Err(fail(&format!("a reference from {table} is left dangling")));
                }
            }
            tx.pragma_update(None, "user_version", m.version)?;
            tx.commit()?;
            Ok(())
        })();
        if m.rebuild && checks {
            conn.pragma_update(None, "foreign_keys", "ON")?;
        }
        result?;
    }
    Ok(())
}

fn back_up(conn: &Connection, from: i64) -> Result<(), StoreError> {
    let Some(db) = conn.path().filter(|p| !p.is_empty()) else {
        return Ok(()); // in memory: nothing to keep
    };
    let dest = backup_path(db, from);
    // VACUUM INTO refuses to overwrite, and an older copy of the same version is just as good as a new one.
    let _ = std::fs::remove_file(&dest);
    conn.execute("VACUUM INTO ?1", [dest.to_string_lossy()])
        .map_err(|e| StoreError::Migration(format!("could not back up the file before migrating: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &[Migration] = &[
        Migration {
            version: 1,
            rebuild: false,
            what: "first table",
            sql: "CREATE TABLE a (x INTEGER); INSERT INTO a VALUES (1);",
        },
        Migration {
            version: 2,
            rebuild: false,
            what: "second table",
            sql: "CREATE TABLE b (y TEXT); ALTER TABLE a ADD COLUMN z TEXT;",
        },
    ];

    fn version(c: &Connection) -> i64 {
        c.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap()
    }

    fn tables(c: &Connection) -> Vec<String> {
        let mut s = c
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn a_new_database_gets_everything() {
        let mut c = Connection::open_in_memory().unwrap();
        run(&mut c, LIST).unwrap();
        assert_eq!(version(&c), 2);
        assert_eq!(tables(&c), ["a", "b"]);
        run(&mut c, LIST).unwrap(); // already current: nothing happens
    }

    #[test]
    fn a_v1_file_moves_to_v2_and_keeps_its_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");
        let mut c = Connection::open(&path).unwrap();
        run(&mut c, &LIST[..1]).unwrap(); // a database as v1 left it
        assert_eq!(version(&c), 1);
        run(&mut c, LIST).unwrap();
        assert_eq!(version(&c), 2);
        let n: i64 = c.query_row("SELECT x FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
        // The v1 file was kept, and it is still v1.
        let old = Connection::open(backup_path(path.to_str().unwrap(), 1)).unwrap();
        assert_eq!(version(&old), 1);
        assert_eq!(tables(&old), ["a"]);
    }

    #[test]
    fn a_failing_migration_leaves_the_file_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");
        let mut c = Connection::open(&path).unwrap();
        run(&mut c, &LIST[..1]).unwrap();
        let bad: Vec<Migration> = [
            LIST[0],
            Migration {
                version: 2,
                rebuild: false,
                what: "breaks half way",
                sql: "CREATE TABLE half (q); INSERT INTO nowhere VALUES (1);",
            },
        ]
        .into();
        let err = run(&mut c, &bad).unwrap_err().to_string();
        assert!(err.contains("step 2") && err.contains("breaks half way"), "{err}");
        assert_eq!(version(&c), 1);
        assert_eq!(tables(&c), ["a"], "the half-made table was rolled back");
        let n: i64 = c.query_row("SELECT count(*) FROM a", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn a_later_step_failing_keeps_the_earlier_steps() {
        let mut c = Connection::open_in_memory().unwrap();
        let list = [
            LIST[0],
            Migration {
                version: 2,
                rebuild: false,
                what: "bad",
                sql: "SELECT * FROM nowhere;",
            },
        ];
        assert!(run(&mut c, &list).is_err());
        assert_eq!(
            version(&c),
            1,
            "step 1 is complete and recorded; step 2 left nothing"
        );
    }

    #[test]
    fn newer_files_and_bad_lists_are_refused() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "user_version", 9).unwrap();
        assert!(matches!(run(&mut c, LIST), Err(StoreError::NewerSchema(9))));
        let mut c = Connection::open_in_memory().unwrap();
        let gap = [Migration {
            version: 2,
            rebuild: false,
            ..LIST[1]
        }];
        assert!(matches!(run(&mut c, &gap), Err(StoreError::Migration(_))));
    }

    #[test]
    fn a_rebuild_that_breaks_references_is_refused_and_checks_come_back_on() {
        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        let setup = Migration {
            version: 1,
            rebuild: false,
            what: "parent and child",
            sql: "CREATE TABLE p (id INTEGER PRIMARY KEY); CREATE TABLE ch (p INTEGER REFERENCES p(id));
                  INSERT INTO p VALUES (1); INSERT INTO ch VALUES (1);",
        };
        let good = Migration {
            version: 2,
            rebuild: true,
            what: "rebuild p keeping ids",
            sql: "CREATE TABLE p2 (id INTEGER PRIMARY KEY, x TEXT); INSERT INTO p2 (id) SELECT id FROM p;
                  DROP TABLE p; ALTER TABLE p2 RENAME TO p;",
        };
        run(&mut c, &[setup, good]).unwrap();
        assert_eq!(version(&c), 2);
        let on: i64 = c.pragma_query_value(None, "foreign_keys", |r| r.get(0)).unwrap();
        assert_eq!(on, 1);

        let mut c = Connection::open_in_memory().unwrap();
        c.pragma_update(None, "foreign_keys", "ON").unwrap();
        let bad = Migration {
            sql: "CREATE TABLE p2 (id INTEGER PRIMARY KEY); DROP TABLE p; ALTER TABLE p2 RENAME TO p;",
            ..good
        };
        let err = run(&mut c, &[setup, bad]).unwrap_err().to_string();
        assert!(err.contains("dangling"), "{err}");
        assert_eq!(version(&c), 1, "nothing of the rebuild stayed");
        assert!(tables(&c).contains(&"p".to_string()));
        let on: i64 = c.pragma_query_value(None, "foreign_keys", |r| r.get(0)).unwrap();
        assert_eq!(on, 1);
    }
}
