//! How the positions and the payload sets combine into requests.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::payload::{CompiledSet, PayloadSet};
use crate::template::Template;
use crate::{MAX_REQUESTS, PlanError, invalid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    /// One payload set. Each position in turn gets every payload while the others keep their own text.
    Sniper,
    /// One payload set. Every position gets the same payload at once.
    BatteringRam,
    /// One set per position, stepped together: the first payloads together, then the second, and so on, until the
    /// shortest set runs out.
    Pitchfork,
    /// One set per position, every combination.
    ClusterBomb,
}

impl AttackType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sniper => "sniper",
            Self::BatteringRam => "battering_ram",
            Self::Pitchfork => "pitchfork",
            Self::ClusterBomb => "cluster_bomb",
        }
    }
}

/// One request to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Its number in the attack (0-based), also counting the ones that were skipped.
    pub index: u64,
    /// The request, with the payloads in place.
    pub request: Vec<u8>,
    /// The position being attacked (sniper); `None` when several are filled at once.
    pub position: Option<usize>,
    /// The payloads that were used: one for sniper and battering ram, one per position otherwise.
    pub payloads: Vec<Vec<u8>>,
}

/// An attack, ready to hand out its requests by number.
#[derive(Debug)]
pub struct Plan {
    template: Template,
    kind: AttackType,
    sets: Vec<CompiledSet>,
    total: u64,
}

impl Plan {
    /// Check the request, the sets and their number for the attack type, and the size of the attack.
    pub fn new(template: Template, kind: AttackType, sets: &[PayloadSet]) -> Result<Self, PlanError> {
        let n = template.positions();
        if n == 0 {
            return invalid("the request has no positions: mark where payloads go with § on both sides");
        }
        match kind {
            AttackType::Sniper | AttackType::BatteringRam if sets.len() != 1 => {
                return invalid("this attack type takes one payload set");
            }
            AttackType::Pitchfork | AttackType::ClusterBomb if sets.len() != n => {
                return invalid(format!(
                    "this attack type takes one payload set per position: {n} positions, {} sets",
                    sets.len()
                ));
            }
            _ => {}
        }
        let sets: Vec<CompiledSet> = sets.iter().map(PayloadSet::compile).collect::<Result<_, _>>()?;
        let too_big = || PlanError::Invalid(format!("that is more than {MAX_REQUESTS} requests"));
        let total = match kind {
            AttackType::Sniper => sets[0].len().checked_mul(n as u64).ok_or_else(too_big)?,
            AttackType::BatteringRam => sets[0].len(),
            AttackType::Pitchfork => sets.iter().map(CompiledSet::len).min().unwrap_or(0),
            AttackType::ClusterBomb => sets
                .iter()
                .try_fold(1u64, |acc, s| acc.checked_mul(s.len()))
                .ok_or_else(too_big)?,
        };
        if total > MAX_REQUESTS {
            return Err(too_big());
        }
        Ok(Self {
            template,
            kind,
            sets,
            total,
        })
    }

    /// How many requests the attack makes, skipped ones included.
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn kind(&self) -> AttackType {
        self.kind
    }

    pub fn positions(&self) -> usize {
        self.template.positions()
    }

    /// The `i`-th request, or `None` if `i` is out of range or a payload was skipped.
    pub fn job(&self, i: u64) -> Option<Job> {
        if i >= self.total {
            return None;
        }
        let n = self.template.positions();
        let defaults: Vec<&[u8]> = (0..n).map(|p| self.template.default_of(p)).collect();
        let (position, payloads): (Option<usize>, Vec<Vec<u8>>) = match self.kind {
            AttackType::Sniper => {
                let len = self.sets[0].len();
                (Some((i / len) as usize), vec![self.sets[0].get(i % len)?])
            }
            AttackType::BatteringRam => (None, vec![self.sets[0].get(i)?]),
            AttackType::Pitchfork => (None, self.sets.iter().map(|s| s.get(i)).collect::<Option<_>>()?),
            AttackType::ClusterBomb => {
                // Mixed radix, the last position changing fastest.
                let mut rest = i;
                let mut idx = vec![0u64; n];
                for (slot, set) in idx.iter_mut().zip(&self.sets).rev() {
                    *slot = rest % set.len();
                    rest /= set.len();
                }
                (
                    None,
                    self.sets
                        .iter()
                        .zip(idx)
                        .map(|(s, k)| s.get(k))
                        .collect::<Option<_>>()?,
                )
            }
        };
        let values: Vec<&[u8]> = match self.kind {
            AttackType::Sniper => {
                let at = position.unwrap_or(0);
                (0..n)
                    .map(|p| {
                        if p == at {
                            payloads[0].as_slice()
                        } else {
                            defaults[p]
                        }
                    })
                    .collect()
            }
            AttackType::BatteringRam => vec![payloads[0].as_slice(); n],
            _ => payloads.iter().map(Vec::as_slice).collect(),
        };
        Some(Job {
            index: i,
            request: self.template.render(&values),
            position,
            payloads,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PayloadSource;

    fn list(items: &[&str]) -> PayloadSet {
        PayloadSet {
            source: PayloadSource::List {
                items: items.iter().map(|s| (*s).to_string()).collect(),
            },
            processing: vec![],
        }
    }

    fn requests(plan: &Plan) -> Vec<String> {
        (0..plan.total())
            .filter_map(|i| plan.job(i))
            .map(|j| String::from_utf8(j.request).unwrap())
            .collect()
    }

    fn t(s: &str) -> Template {
        Template::parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn sniper_attacks_one_position_at_a_time() {
        let p = Plan::new(t("§a§-§b§"), AttackType::Sniper, &[list(&["1", "2"])]).unwrap();
        assert_eq!(p.total(), 4);
        assert_eq!(requests(&p), ["1-b", "2-b", "a-1", "a-2"]);
        assert_eq!(p.job(2).unwrap().position, Some(1));
    }

    #[test]
    fn battering_ram_fills_every_position_alike() {
        let p = Plan::new(t("§a§-§b§"), AttackType::BatteringRam, &[list(&["1", "2"])]).unwrap();
        assert_eq!(requests(&p), ["1-1", "2-2"]);
    }

    #[test]
    fn pitchfork_walks_the_sets_together_to_the_shortest() {
        let p = Plan::new(
            t("§a§-§b§"),
            AttackType::Pitchfork,
            &[list(&["1", "2", "3"]), list(&["x", "y"])],
        )
        .unwrap();
        assert_eq!(requests(&p), ["1-x", "2-y"]);
        assert_eq!(p.job(1).unwrap().payloads, vec![b"2".to_vec(), b"y".to_vec()]);
    }

    #[test]
    fn cluster_bomb_tries_every_combination() {
        let p = Plan::new(
            t("§a§-§b§"),
            AttackType::ClusterBomb,
            &[list(&["1", "2"]), list(&["x", "y", "z"])],
        )
        .unwrap();
        assert_eq!(p.total(), 6);
        assert_eq!(requests(&p), ["1-x", "1-y", "1-z", "2-x", "2-y", "2-z"]);
    }

    #[test]
    fn a_skipped_payload_leaves_its_request_out() {
        let mut s = list(&["keep", "drop"]);
        s.processing = vec![crate::Processing::SkipIfMatches {
            pattern: "drop".into(),
        }];
        let p = Plan::new(t("§a§"), AttackType::Sniper, &[s]).unwrap();
        assert_eq!(p.total(), 2);
        assert_eq!(requests(&p), ["keep"]);
    }

    #[test]
    fn the_wrong_number_of_sets_or_positions_is_refused() {
        assert!(Plan::new(t("none"), AttackType::Sniper, &[list(&["1"])]).is_err());
        assert!(Plan::new(t("§a§"), AttackType::Sniper, &[]).is_err());
        assert!(Plan::new(t("§a§§b§"), AttackType::Pitchfork, &[list(&["1"])]).is_err());
        let big = PayloadSet {
            source: PayloadSource::Null { count: 5000 },
            processing: vec![],
        };
        assert!(Plan::new(t("§a§§b§"), AttackType::ClusterBomb, &[big.clone(), big]).is_err());
    }
}
