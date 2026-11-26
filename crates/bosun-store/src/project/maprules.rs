//! Map Local, Map Remote and throttle rules, kept in list order. The store holds each rule as the JSON the proxy
//! reads; checking what a rule means is the proxy's job.

use rusqlite::params;

use super::Project;
use crate::StoreError;

/// The most rules a project keeps.
pub const MAX_MAP_RULES: usize = 200;

impl Project {
    /// The saved rules, in the order they are tried.
    pub fn map_rule_specs(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.db.read()?;
        let mut stmt = conn.prepare("SELECT spec FROM map_rules ORDER BY position")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Replace the whole list in one transaction.
    pub fn set_map_rule_specs(&self, specs: &[String]) -> Result<(), StoreError> {
        if specs.len() > MAX_MAP_RULES {
            return Err(StoreError::Conflict(format!(
                "a project holds at most {MAX_MAP_RULES} map rules"
            )));
        }
        let mut conn = self.db.write();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM map_rules", [])?;
        for (i, s) in specs.iter().enumerate() {
            tx.execute(
                "INSERT INTO map_rules (position, spec) VALUES (?1, ?2)",
                params![i as i64, s],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_in_order_and_replaced() {
        let p = Project::open_in_memory().unwrap();
        assert!(p.map_rule_specs().unwrap().is_empty());
        p.set_map_rule_specs(&["b".into(), "a".into()]).unwrap();
        assert_eq!(p.map_rule_specs().unwrap(), ["b", "a"]);
        p.set_map_rule_specs(&["c".into()]).unwrap();
        assert_eq!(p.map_rule_specs().unwrap(), ["c"]);
        let many = vec![String::new(); MAX_MAP_RULES + 1];
        assert!(p.set_map_rule_specs(&many).is_err());
        assert_eq!(
            p.map_rule_specs().unwrap(),
            ["c"],
            "a refused list changes nothing"
        );
    }
}
