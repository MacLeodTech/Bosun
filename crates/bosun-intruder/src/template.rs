//! The request with its marked positions.

use crate::{MAX_POSITIONS, MAX_TEMPLATE, PlanError, invalid};

/// The marker, `§` in UTF-8.
const MARK: &[u8] = "§".as_bytes();

/// A request cut at its positions: `parts` has one more entry than `defaults`, and the request is
/// `parts[0] defaults[0] parts[1] defaults[1] ... parts[n]` with the defaults standing in for the positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    parts: Vec<Vec<u8>>,
    defaults: Vec<Vec<u8>>,
}

impl Template {
    /// Parse a request in which `§value§` marks a position. The markers must pair up and cannot nest.
    pub fn parse(raw: &[u8]) -> Result<Self, PlanError> {
        if raw.len() > MAX_TEMPLATE {
            return invalid("the request is over 1 MiB");
        }
        let mut parts = vec![Vec::new()];
        let mut defaults = Vec::new();
        let mut inside = false;
        let mut i = 0;
        while i < raw.len() {
            if raw[i..].starts_with(MARK) {
                i += MARK.len();
                if inside {
                    inside = false;
                    parts.push(Vec::new());
                } else {
                    inside = true;
                    defaults.push(Vec::new());
                    if defaults.len() > MAX_POSITIONS {
                        return invalid(format!("more than {MAX_POSITIONS} positions"));
                    }
                }
                continue;
            }
            if inside {
                if let Some(d) = defaults.last_mut() {
                    d.push(raw[i]);
                }
            } else {
                if let Some(p) = parts.last_mut() {
                    p.push(raw[i]);
                }
            }
            i += 1;
        }
        if inside {
            return invalid("a position is not closed: every § needs a second § after it");
        }
        Ok(Self { parts, defaults })
    }

    /// How many positions there are.
    pub fn positions(&self) -> usize {
        self.defaults.len()
    }

    /// The text that stands in position `i` when it is not attacked.
    pub fn default_of(&self, i: usize) -> &[u8] {
        &self.defaults[i]
    }

    /// The request with `values[i]` in position `i`.
    pub fn render(&self, values: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.parts.iter().map(Vec::len).sum::<usize>() + values.iter().map(|v| v.len()).sum::<usize>(),
        );
        for (i, p) in self.parts.iter().enumerate() {
            out.extend_from_slice(p);
            if let Some(v) = values.get(i) {
                out.extend_from_slice(v);
            }
        }
        out
    }

    /// The request as it is with no position attacked.
    pub fn base(&self) -> Vec<u8> {
        let v: Vec<&[u8]> = self.defaults.iter().map(Vec::as_slice).collect();
        self.render(&v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_are_cut_out_and_defaults_kept() {
        let t = Template::parse("GET /§a§?x=§b§ HTTP/1.1\r\n\r\n".as_bytes()).unwrap();
        assert_eq!(t.positions(), 2);
        assert_eq!(t.default_of(0), b"a");
        assert_eq!(t.base(), b"GET /a?x=b HTTP/1.1\r\n\r\n");
        assert_eq!(t.render(&[b"1", b"22"]), b"GET /1?x=22 HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn unpaired_markers_and_too_many_positions_are_refused() {
        assert!(Template::parse("GET /§a HTTP/1.1".as_bytes()).is_err());
        let many = "§x§".repeat(MAX_POSITIONS + 1);
        assert!(Template::parse(many.as_bytes()).is_err());
        assert_eq!(Template::parse(b"no positions").unwrap().positions(), 0);
    }

    #[test]
    fn an_empty_position_is_allowed() {
        let t = Template::parse("a§§b".as_bytes()).unwrap();
        assert_eq!(t.positions(), 1);
        assert_eq!(t.render(&[b"-"]), b"a-b");
    }
}
