//! Where payloads come from, and what is done to them on the way.

use bosun_codec::Op;
use regex::bytes::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{MAX_ITEMS, MAX_PAYLOAD, MAX_REQUESTS, PlanError, invalid};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NumberBase {
    #[default]
    Decimal,
    /// Lower-case hex digits.
    Hex,
}

/// A source of payloads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PayloadSource {
    /// These strings, in order.
    List { items: Vec<String> },
    /// `from` to `to` (inclusive) in steps of `step`; a negative step counts down.
    Numbers {
        from: i64,
        to: i64,
        #[serde(default = "one")]
        step: i64,
        #[serde(default)]
        base: NumberBase,
        /// Pad with leading zeros to this many digits.
        #[serde(default)]
        min_digits: u8,
    },
    /// Every string of `min_len` to `max_len` characters from `charset`.
    BruteForce {
        charset: String,
        min_len: u8,
        max_len: u8,
    },
    /// `count` empty payloads: send the same request many times.
    Null { count: u64 },
    /// Each item as it is, in lower case, in upper case, capitalised and with its case swapped.
    CaseChanges { items: Vec<String> },
}

fn one() -> i64 {
    1
}

/// A step applied to every payload, in order.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Processing {
    Prefix {
        value: String,
    },
    Suffix {
        value: String,
    },
    /// Encode, escape or hash with one of the Decoder's operations (URL, HTML, Base64, hex, SHA-256, ...).
    Encode {
        op: Op,
    },
    /// Replace every match of the regular expression; `$1` in the replacement is the first group.
    ReplaceRegex {
        pattern: String,
        replacement: String,
    },
    /// Leave out any payload that matches the regular expression.
    SkipIfMatches {
        pattern: String,
    },
}

/// A source and the processing for what it yields.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct PayloadSet {
    pub source: PayloadSource,
    #[serde(default)]
    pub processing: Vec<Processing>,
}

enum Source {
    Items(Vec<Vec<u8>>),
    Numbers {
        from: i64,
        step: i64,
        count: u64,
        hex: bool,
        digits: usize,
    },
    Brute {
        chars: Vec<char>,
        min: u32,
        /// `bounds[k]` is how many strings are shorter than `min + k`.
        bounds: Vec<u64>,
        count: u64,
    },
    Null(u64),
}

enum Step {
    Prefix(Vec<u8>),
    Suffix(Vec<u8>),
    Encode(Op),
    Replace(Regex, Vec<u8>),
    Skip(Regex),
}

/// A payload set ready to be indexed.
pub struct CompiledSet {
    source: Source,
    steps: Vec<Step>,
}

impl std::fmt::Debug for CompiledSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledSet").field("len", &self.len()).finish()
    }
}

fn regex(pattern: &str) -> Result<Regex, PlanError> {
    if pattern.len() > 4096 {
        return invalid("a regular expression is over 4096 bytes");
    }
    RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(4 << 20)
        .build()
        .map_err(|e| PlanError::Invalid(format!("not a valid regular expression ({pattern:?}): {e}")))
}

fn case_variants(s: &str) -> Vec<String> {
    let mut chars = s.chars();
    let capital: String = match chars.next() {
        Some(c) => c
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect(),
        None => String::new(),
    };
    let swapped: String = s
        .chars()
        .flat_map(|c| {
            if c.is_uppercase() {
                c.to_lowercase().collect::<Vec<_>>()
            } else {
                c.to_uppercase().collect()
            }
        })
        .collect();
    let mut out: Vec<String> = Vec::with_capacity(5);
    for v in [
        s.to_string(),
        s.to_lowercase(),
        s.to_uppercase(),
        capital,
        swapped,
    ] {
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

impl PayloadSet {
    pub fn compile(&self) -> Result<CompiledSet, PlanError> {
        let source = match &self.source {
            PayloadSource::List { items } => {
                if items.len() > MAX_ITEMS {
                    return invalid(format!("a list holds at most {MAX_ITEMS} payloads"));
                }
                Source::Items(items.iter().map(|s| s.as_bytes().to_vec()).collect())
            }
            PayloadSource::CaseChanges { items } => {
                if items.len() > MAX_ITEMS / 5 {
                    return invalid(format!("case changes take at most {} items", MAX_ITEMS / 5));
                }
                Source::Items(
                    items
                        .iter()
                        .flat_map(|s| case_variants(s))
                        .map(String::into_bytes)
                        .collect(),
                )
            }
            PayloadSource::Numbers {
                from,
                to,
                step,
                base,
                min_digits,
            } => {
                if *step == 0 {
                    return invalid("the step of a number range cannot be 0");
                }
                let span = i128::from(*to) - i128::from(*from);
                let count = if span == 0 || (span > 0) == (*step > 0) {
                    (span.unsigned_abs() / u128::from(step.unsigned_abs())) + 1
                } else {
                    0
                };
                if count > u128::from(MAX_REQUESTS) {
                    return invalid("that number range is over a million payloads");
                }
                Source::Numbers {
                    from: *from,
                    step: *step,
                    count: count as u64,
                    hex: *base == NumberBase::Hex,
                    digits: usize::from(*min_digits).min(32),
                }
            }
            PayloadSource::BruteForce {
                charset,
                min_len,
                max_len,
            } => {
                let mut chars: Vec<char> = Vec::new();
                for c in charset.chars() {
                    if !chars.contains(&c) {
                        chars.push(c);
                    }
                }
                if chars.is_empty() {
                    return invalid("the brute-force character set is empty");
                }
                if *min_len == 0 || min_len > max_len || *max_len > 16 {
                    return invalid("brute-force lengths go from 1 to at most 16, shortest first");
                }
                let too_many =
                    || PlanError::Invalid("that brute-force range is over a million payloads".into());
                let mut bounds = vec![0u64];
                let mut total: u64 = 0;
                for len in u32::from(*min_len)..=u32::from(*max_len) {
                    let n = (chars.len() as u64)
                        .checked_pow(len)
                        .filter(|n| *n <= MAX_REQUESTS)
                        .ok_or_else(too_many)?;
                    total += n;
                    if total > MAX_REQUESTS {
                        return Err(too_many());
                    }
                    bounds.push(total);
                }
                Source::Brute {
                    chars,
                    min: u32::from(*min_len),
                    bounds,
                    count: total,
                }
            }
            PayloadSource::Null { count } => {
                if *count > MAX_REQUESTS {
                    return invalid("null payloads are limited to a million");
                }
                Source::Null(*count)
            }
        };
        if self.processing.len() > 20 {
            return invalid("at most 20 processing rules");
        }
        let steps = self
            .processing
            .iter()
            .map(|p| {
                Ok(match p {
                    Processing::Prefix { value } => Step::Prefix(value.as_bytes().to_vec()),
                    Processing::Suffix { value } => Step::Suffix(value.as_bytes().to_vec()),
                    Processing::Encode { op } => Step::Encode(*op),
                    Processing::ReplaceRegex { pattern, replacement } => {
                        Step::Replace(regex(pattern)?, replacement.as_bytes().to_vec())
                    }
                    Processing::SkipIfMatches { pattern } => Step::Skip(regex(pattern)?),
                })
            })
            .collect::<Result<_, PlanError>>()?;
        Ok(CompiledSet { source, steps })
    }
}

impl CompiledSet {
    /// How many payloads the source has (before any are skipped).
    pub fn len(&self) -> u64 {
        match &self.source {
            Source::Items(v) => v.len() as u64,
            Source::Numbers { count, .. } => *count,
            Source::Brute { count, .. } => *count,
            Source::Null(n) => *n,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn raw(&self, i: u64) -> Option<Vec<u8>> {
        if i >= self.len() {
            return None;
        }
        Some(match &self.source {
            Source::Items(v) => v[i as usize].clone(),
            Source::Numbers {
                from,
                step,
                hex,
                digits,
                ..
            } => {
                let n = i128::from(*from) + i128::from(i) * i128::from(*step);
                let (neg, mag) = (n < 0, n.unsigned_abs());
                let body = if *hex { format!("{mag:x}") } else { mag.to_string() };
                let pad = digits.saturating_sub(body.len());
                format!("{}{}{body}", if neg { "-" } else { "" }, "0".repeat(pad)).into_bytes()
            }
            Source::Brute {
                chars, min, bounds, ..
            } => {
                // Find the length this index falls in, then write the rest of it as digits in the alphabet.
                let k = bounds.iter().rposition(|b| *b <= i).unwrap_or(0);
                let len = *min as usize + k;
                let mut rest = i - bounds[k];
                let base = chars.len() as u64;
                let mut out = vec![chars[0]; len];
                for slot in out.iter_mut().rev() {
                    *slot = chars[(rest % base) as usize];
                    rest /= base;
                }
                out.into_iter().collect::<String>().into_bytes()
            }
            Source::Null(_) => Vec::new(),
        })
    }

    /// The `i`-th payload after processing. `None` when it is out of range, skipped by a rule, or cannot be
    /// processed (an encoding that fails): the request is left out.
    pub fn get(&self, i: u64) -> Option<Vec<u8>> {
        let mut p = self.raw(i)?;
        for s in &self.steps {
            match s {
                Step::Prefix(x) => {
                    let mut v = x.clone();
                    v.extend_from_slice(&p);
                    p = v;
                }
                Step::Suffix(x) => p.extend_from_slice(x),
                Step::Encode(op) => p = bosun_codec::apply(*op, &p, MAX_PAYLOAD).ok()?,
                Step::Replace(re, with) => p = re.replace_all(&p, with.as_slice()).into_owned(),
                Step::Skip(re) => {
                    if re.is_match(&p) {
                        return None;
                    }
                }
            }
            if p.len() > MAX_PAYLOAD {
                return None;
            }
        }
        Some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(source: PayloadSource, processing: Vec<Processing>) -> CompiledSet {
        PayloadSet { source, processing }.compile().unwrap()
    }

    fn all(s: &CompiledSet) -> Vec<String> {
        (0..s.len())
            .filter_map(|i| s.get(i))
            .map(|p| String::from_utf8(p).unwrap())
            .collect()
    }

    fn numbers(from: i64, to: i64, step: i64, base: NumberBase, min_digits: u8) -> Vec<String> {
        all(&set(
            PayloadSource::Numbers {
                from,
                to,
                step,
                base,
                min_digits,
            },
            vec![],
        ))
    }

    #[test]
    fn numbers_count_up_down_pad_and_use_hex() {
        assert_eq!(numbers(1, 7, 3, NumberBase::Decimal, 0), ["1", "4", "7"]);
        assert_eq!(numbers(3, 1, -1, NumberBase::Decimal, 2), ["03", "02", "01"]);
        assert_eq!(numbers(250, 256, 3, NumberBase::Hex, 0), ["fa", "fd", "100"]);
        assert_eq!(numbers(-1, 1, 1, NumberBase::Decimal, 0), ["-1", "0", "1"]);
        // The wrong direction is empty, not an endless range.
        assert!(numbers(5, 1, 1, NumberBase::Decimal, 0).is_empty());
    }

    #[test]
    fn brute_force_lists_every_string_shortest_first() {
        let s = set(
            PayloadSource::BruteForce {
                charset: "abba".into(),
                min_len: 1,
                max_len: 2,
            },
            vec![],
        );
        assert_eq!(all(&s), ["a", "b", "aa", "ab", "ba", "bb"]);
    }

    #[test]
    fn brute_force_that_is_too_large_is_refused() {
        let r = PayloadSet {
            source: PayloadSource::BruteForce {
                charset: "abcdefghijklmnopqrstuvwxyz".into(),
                min_len: 1,
                max_len: 8,
            },
            processing: vec![],
        }
        .compile();
        assert!(r.is_err());
    }

    #[test]
    fn case_changes_and_null_payloads() {
        let s = set(
            PayloadSource::CaseChanges {
                items: vec!["aDmin".into(), "1".into()],
            },
            vec![],
        );
        assert_eq!(all(&s), ["aDmin", "admin", "ADMIN", "Admin", "AdMIN", "1"]);
        assert_eq!(all(&set(PayloadSource::Null { count: 3 }, vec![])), ["", "", ""]);
    }

    #[test]
    fn processing_runs_in_order_and_skips() {
        let s = set(
            PayloadSource::List {
                items: vec!["a b".into(), "skip".into(), "c".into()],
            },
            vec![
                Processing::SkipIfMatches {
                    pattern: "^skip".into(),
                },
                Processing::Prefix { value: "<".into() },
                Processing::Encode { op: Op::UrlEncode },
                Processing::Suffix { value: ">".into() },
                Processing::ReplaceRegex {
                    pattern: "%20".into(),
                    replacement: "+".into(),
                },
            ],
        );
        assert_eq!(all(&s), ["%3Ca+b>", "%3Cc>"]);
        let h = set(
            PayloadSource::List {
                items: vec!["a".into()],
            },
            vec![Processing::Encode { op: Op::Sha256 }],
        );
        assert!(!h.get(0).unwrap().is_empty());
    }

    #[test]
    fn bad_input_is_refused() {
        let bad = |source, processing| PayloadSet { source, processing }.compile().is_err();
        assert!(bad(
            PayloadSource::Numbers {
                from: 0,
                to: 1,
                step: 0,
                base: NumberBase::Decimal,
                min_digits: 0
            },
            vec![]
        ));
        assert!(bad(PayloadSource::Null { count: u64::MAX }, vec![]));
        assert!(bad(
            PayloadSource::Null { count: 1 },
            vec![Processing::SkipIfMatches { pattern: "(".into() }]
        ));
        assert!(bad(
            PayloadSource::Numbers {
                from: i64::MIN,
                to: i64::MAX,
                step: 1,
                base: NumberBase::Decimal,
                min_digits: 0
            },
            vec![]
        ));
    }
}
