//! The Sequencer's analysis: how random are a set of tokens (session ids, CSRF tokens, reset codes)?
//!
//! Pure computation on strings, with bounded input and bounded output. Nothing is fetched here: the API collects
//! the tokens (by hand or by sending requests through the gate) and hands them to [`analyze`].
//!
//! What is computed:
//!
//! - **Character level**: for each position, the distribution of characters and its Shannon entropy (with the
//!   Miller-Madow correction for small samples, never above `log2` of the characters seen there). The sum over
//!   positions is the *effective entropy* of a token in bits. Positions that never vary add nothing.
//! - **Bit level**: each character is mapped to its rank among the characters seen at that position; the low
//!   `floor(log2 k)` bits of the rank are used, and characters whose rank does not fit are skipped, so that tokens
//!   drawn uniformly give uniform bits. Per bit, the share of ones and a z-test against one half.
//! - **FIPS 140-2** on the concatenated bits, in blocks of 20 000 bits: monobit, poker, runs, long run.
//! - **Sequence checks**: duplicates, and numbers that grow in small steps (counters, timestamps).
//!
//! The verdict follows from these (see [`Verdict`]). With fewer than 100 tokens it is marked unreliable.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The most tokens one analysis takes.
pub const MAX_TOKENS: usize = 10_000;
/// The fewest tokens that can be analysed.
pub const MIN_TOKENS: usize = 20;
/// The fewest tokens for a result to be called reliable.
pub const RELIABLE_TOKENS: usize = 100;
/// The longest token, in characters.
pub const MAX_TOKEN_CHARS: usize = 1024;
/// The most characters over all tokens.
pub const MAX_TOTAL_CHARS: usize = 4 << 20;
/// Bits in one FIPS 140-2 block.
pub const FIPS_BLOCK_BITS: usize = 20_000;
/// The most FIPS blocks tested (the first 160 000 bits).
pub const MAX_FIPS_BLOCKS: usize = 8;
/// The longest regular expression accepted for extraction.
pub const MAX_PATTERN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("at least {MIN_TOKENS} tokens are needed (got {0})")]
    TooFew(usize),
    #[error("at most {MAX_TOKENS} tokens can be analysed (got {0})")]
    TooMany(usize),
    #[error("a token is longer than {MAX_TOKEN_CHARS} characters")]
    TokenTooLong,
    #[error("the tokens hold more than {MAX_TOTAL_CHARS} characters in all")]
    TooLarge,
    #[error("the pattern is not usable: {0}")]
    BadPattern(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Fails statistical tests, repeats, counts up, or varies hardly at all: predictable.
    NotRandom,
    /// Looks random but carries few bits (under 64), or fails some of the tests.
    Poor,
    /// 64 to 100 effective bits and no test failed.
    Good,
    /// 100 or more effective bits and no test failed.
    Excellent,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FipsTest {
    /// The statistic (ones, poker X, total runs or the longest run).
    pub value: f64,
    /// The range that passes, as text.
    pub limit: String,
    pub pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FipsBlock {
    pub monobit: FipsTest,
    pub poker: FipsTest,
    /// Run counts for lengths 1 to 6 and over, for zeros and for ones: all must be inside their ranges.
    pub runs: FipsTest,
    pub long_run: FipsTest,
}

impl FipsBlock {
    pub fn passed(&self) -> bool {
        self.monobit.pass && self.poker.pass && self.runs.pass && self.long_run.pass
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FipsReport {
    /// Bits that went into the tests.
    pub bits_tested: usize,
    pub blocks: Vec<FipsBlock>,
    /// Blocks in which every test passed.
    pub blocks_passed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PositionStat {
    /// 0-based character position.
    pub position: usize,
    /// Tokens that have this position.
    pub count: usize,
    /// Distinct characters seen.
    pub distinct: usize,
    pub entropy_bits: f64,
    /// The most common character and its share.
    pub top_char: String,
    pub top_share: f64,
    /// Bits taken from this character for the bit-level analysis.
    pub bits: usize,
    /// For each of those bits (most significant first): the share of ones.
    pub bit_ones: Vec<f64>,
    /// How many of those bits are off one half by more than chance allows (|z| above 3.29).
    pub biased_bits: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CharCount {
    pub ch: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Analysis {
    pub tokens: usize,
    pub unique: usize,
    pub min_length: usize,
    pub max_length: usize,
    /// Distinct characters over all tokens.
    pub charset_size: usize,
    /// The most common characters over all tokens (up to 64).
    pub charset: Vec<CharCount>,
    pub positions: Vec<PositionStat>,
    /// Effective entropy of a token in bits, character level.
    pub entropy_bits: f64,
    /// What the same positions would carry if every character seen there were equally likely.
    pub capacity_bits: f64,
    /// Bits in the bit-level stream (capped at 160 000).
    pub bit_stream_len: usize,
    /// Bit positions off one half beyond chance, and how many bit positions there are.
    pub biased_bits: usize,
    pub bit_positions: usize,
    /// None when there are fewer than 20 000 bits.
    pub fips: Option<FipsReport>,
    /// Share of consecutive tokens that are numbers 1 to 65 536 above the one before (0 when they are not numbers).
    pub sequential_share: f64,
    pub verdict: Verdict,
    /// False under 100 tokens.
    pub reliable: bool,
    /// Why the verdict is what it is.
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------------------------------------------------------
// FIPS 140-2

fn fips_block(bits: &[u8]) -> FipsBlock {
    debug_assert_eq!(bits.len(), FIPS_BLOCK_BITS);
    let ones: usize = bits.iter().map(|b| usize::from(*b)).sum();
    let mono_ok = ones > 9725 && ones < 10275;

    let mut f = [0u32; 16];
    for c in bits.as_chunks::<4>().0 {
        let v = (usize::from(c[0]) << 3)
            | (usize::from(c[1]) << 2)
            | (usize::from(c[2]) << 1)
            | usize::from(c[3]);
        f[v] += 1;
    }
    let sq: f64 = f.iter().map(|x| f64::from(*x) * f64::from(*x)).sum();
    let x = 16.0 / 5000.0 * sq - 5000.0;
    let poker_ok = x > 2.16 && x < 46.17;

    // runs[bit][len - 1]; the last slot is "6 or more"
    let mut runs = [[0u32; 6]; 2];
    let mut longest = 0usize;
    let mut i = 0;
    while i < bits.len() {
        let b = bits[i];
        let mut j = i;
        while j < bits.len() && bits[j] == b {
            j += 1;
        }
        let len = j - i;
        longest = longest.max(len);
        runs[usize::from(b)][len.min(6) - 1] += 1;
        i = j;
    }
    const RANGES: [(u32, u32); 6] = [
        (2315, 2685),
        (1114, 1386),
        (527, 723),
        (240, 384),
        (103, 209),
        (103, 209),
    ];
    let runs_ok = runs
        .iter()
        .all(|r| r.iter().zip(RANGES).all(|(n, (lo, hi))| *n >= lo && *n <= hi));
    let total_runs: u32 = runs.iter().flatten().sum();
    FipsBlock {
        monobit: FipsTest {
            value: ones as f64,
            limit: "9725 < ones < 10275".into(),
            pass: mono_ok,
        },
        poker: FipsTest {
            value: x,
            limit: "2.16 < X < 46.17".into(),
            pass: poker_ok,
        },
        runs: FipsTest {
            value: f64::from(total_runs),
            limit: "counts of runs of length 1 to 6+, zeros and ones, within the FIPS 140-2 ranges".into(),
            pass: runs_ok,
        },
        long_run: FipsTest {
            value: longest as f64,
            limit: "longest run < 26".into(),
            pass: longest < 26,
        },
    }
}

/// Run the FIPS 140-2 tests on a stream of bits (each element's lowest bit counts): in blocks of 20 000, at most
/// 8 blocks. None when there are fewer than 20 000 bits.
pub fn fips_140_2(bits: &[u8]) -> Option<FipsReport> {
    let blocks: Vec<FipsBlock> = bits
        .as_chunks::<FIPS_BLOCK_BITS>()
        .0
        .iter()
        .take(MAX_FIPS_BLOCKS)
        .map(|c| {
            let norm: Vec<u8> = c.iter().map(|b| b & 1).collect();
            fips_block(&norm)
        })
        .collect();
    if blocks.is_empty() {
        return None;
    }
    let blocks_passed = blocks.iter().filter(|b| b.passed()).count();
    Some(FipsReport {
        bits_tested: blocks.len() * FIPS_BLOCK_BITS,
        blocks,
        blocks_passed,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Entropy

/// Shannon entropy in bits of a distribution given as counts, with the Miller-Madow bias correction, never above
/// `log2` of the number of non-zero counts.
pub fn entropy_mm(counts: &[usize]) -> f64 {
    let n: usize = counts.iter().sum();
    let k = counts.iter().filter(|c| **c > 0).count();
    if n == 0 || k <= 1 {
        return 0.0;
    }
    let nf = n as f64;
    let h: f64 = counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / nf;
            -p * p.log2()
        })
        .sum();
    let corrected = h + (k as f64 - 1.0) / (2.0 * nf * std::f64::consts::LN_2);
    corrected.min((k as f64).log2()).max(0.0)
}

/// The number a token stands for: all hex digits (with a letter in them) as hex, else the trailing run of decimal
/// digits. The second part is what is left before it, which must match for two tokens to be compared.
fn numeric(t: &str) -> Option<(u128, &str)> {
    let all_hex = t.len() > 1 && t.len() <= 32 && t.bytes().all(|b| b.is_ascii_hexdigit());
    if all_hex && !t.bytes().all(|b| b.is_ascii_digit()) {
        return Some((u128::from_str_radix(t, 16).ok()?, ""));
    }
    let head = t.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = &t[head.len()..];
    if digits.is_empty() || digits.len() > 30 {
        return None;
    }
    Some((digits.parse().ok()?, head))
}

/// The share of consecutive pairs where the second token is a number 1 to 65 536 above the first.
fn sequential_share(tokens: &[String]) -> f64 {
    let mut seq = 0usize;
    for w in tokens.windows(2) {
        if let (Some((x, hx)), Some((y, hy))) = (numeric(&w[0]), numeric(&w[1]))
            && hx == hy
            && y > x
            && y - x <= 65_536
        {
            seq += 1;
        }
    }
    seq as f64 / tokens.len().saturating_sub(1).max(1) as f64
}

/// Analyse a set of tokens.
pub fn analyze<S: AsRef<str>>(tokens: &[S]) -> Result<Analysis, Error> {
    let n = tokens.len();
    if n < MIN_TOKENS {
        return Err(Error::TooFew(n));
    }
    if n > MAX_TOKENS {
        return Err(Error::TooMany(n));
    }
    let mut total = 0usize;
    for t in tokens {
        // Bytes bound chars, so this check is cheap and safe before collecting.
        let len = t.as_ref().len();
        if len > MAX_TOKEN_CHARS * 4 || t.as_ref().chars().count() > MAX_TOKEN_CHARS {
            return Err(Error::TokenTooLong);
        }
        total += len;
    }
    if total > MAX_TOTAL_CHARS * 4 {
        return Err(Error::TooLarge);
    }
    let strs: Vec<String> = tokens.iter().map(|t| t.as_ref().to_string()).collect();
    let toks: Vec<Vec<char>> = strs.iter().map(|t| t.chars().collect()).collect();
    if toks.iter().map(Vec::len).sum::<usize>() > MAX_TOTAL_CHARS {
        return Err(Error::TooLarge);
    }
    let max_len = toks.iter().map(Vec::len).max().unwrap_or(0);
    let min_len = toks.iter().map(Vec::len).min().unwrap_or(0);
    let unique = toks.iter().collect::<HashSet<_>>().len();

    let mut global: BTreeMap<char, usize> = BTreeMap::new();
    for t in &toks {
        for c in t {
            *global.entry(*c).or_default() += 1;
        }
    }
    let mut charset: Vec<CharCount> = global
        .iter()
        .map(|(c, n)| CharCount {
            ch: c.to_string(),
            count: *n,
        })
        .collect();
    charset.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.ch.cmp(&b.ch)));
    charset.truncate(64);

    let mut positions = Vec::new();
    let mut entropy_bits = 0.0;
    let mut capacity_bits = 0.0;
    // Per position: the rank of each character among those seen there, and how many low bits of it are used.
    let mut ranks: Vec<(BTreeMap<char, usize>, usize)> = Vec::new();
    let mut biased_total = 0usize;
    let mut bit_positions = 0usize;
    for p in 0..max_len {
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        for t in &toks {
            if let Some(c) = t.get(p) {
                *counts.entry(*c).or_default() += 1;
            }
        }
        let count: usize = counts.values().sum();
        let rank: BTreeMap<char, usize> = counts.keys().enumerate().map(|(i, c)| (*c, i)).collect();
        let k = counts.len();
        let bits = if k >= 2 {
            (usize::BITS - 1 - k.leading_zeros()) as usize
        } else {
            0
        };
        let cv: Vec<usize> = counts.values().copied().collect();
        let e = entropy_mm(&cv);
        entropy_bits += e;
        capacity_bits += if k > 1 { (k as f64).log2() } else { 0.0 };
        let (top_char, top_n) = counts
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(c, n)| (c.to_string(), *n))
            .unwrap_or_default();
        let mut stats = vec![(0usize, 0usize); bits];
        for t in &toks {
            if let Some(c) = t.get(p) {
                let r = rank[c];
                if r >> bits != 0 {
                    continue;
                }
                for (b, s) in stats.iter_mut().enumerate() {
                    s.1 += 1;
                    s.0 += (r >> (bits - 1 - b)) & 1;
                }
            }
        }
        let mut biased = 0;
        let bit_ones: Vec<f64> = stats
            .iter()
            .map(|(o, t)| {
                if *t == 0 {
                    return 0.5;
                }
                let tf = *t as f64;
                let z = (*o as f64 - tf / 2.0) / (tf.sqrt() / 2.0);
                if *t >= 20 && z.abs() > 3.29 {
                    biased += 1;
                }
                *o as f64 / tf
            })
            .collect();
        biased_total += biased;
        bit_positions += bits;
        positions.push(PositionStat {
            position: p,
            count,
            distinct: k,
            entropy_bits: e,
            top_char,
            top_share: if count == 0 {
                0.0
            } else {
                top_n as f64 / count as f64
            },
            bits,
            bit_ones,
            biased_bits: biased,
        });
        ranks.push((rank, bits));
    }

    // The bit stream: token by token, position by position, most significant bit first.
    let mut stream: Vec<u8> = Vec::new();
    let cap = MAX_FIPS_BLOCKS * FIPS_BLOCK_BITS;
    'outer: for t in &toks {
        for (p, c) in t.iter().enumerate() {
            let (rank, bits) = &ranks[p];
            let r = rank[c];
            if *bits == 0 || r >> bits != 0 {
                continue;
            }
            for b in (0..*bits).rev() {
                stream.push(((r >> b) & 1) as u8);
            }
            if stream.len() >= cap {
                break 'outer;
            }
        }
    }
    stream.truncate(cap);
    let bit_stream_len = stream.len();
    let fips = fips_140_2(&stream);
    let seq = sequential_share(&strs);

    let mut reasons = Vec::new();
    let mut not_random = false;
    let mut poor = false;
    let dup = n - unique;
    if dup * 100 > n {
        not_random = true;
        reasons.push(format!("{dup} of {n} tokens repeat an earlier one"));
    } else if dup > 0 {
        poor = true;
        reasons.push(format!("{dup} of {n} tokens repeat an earlier one"));
    }
    if seq > 0.5 {
        not_random = true;
        reasons.push(format!(
            "{:.0}% of consecutive tokens are numbers a small step above the last: they count up",
            seq * 100.0
        ));
    }
    if entropy_bits < 8.0 {
        not_random = true;
        reasons.push(format!(
            "the tokens carry only {entropy_bits:.1} bits: they hardly vary"
        ));
    }
    match &fips {
        Some(f) => {
            let failed = f.blocks.len() - f.blocks_passed;
            if failed > 0 {
                if failed * 2 >= f.blocks.len() {
                    not_random = true;
                } else {
                    poor = true;
                }
                reasons.push(format!(
                    "FIPS 140-2 failed in {failed} of {} blocks of 20 000 bits",
                    f.blocks.len()
                ));
            }
        }
        None => reasons.push(format!(
            "only {bit_stream_len} bits: too few (20 000 needed) for the FIPS 140-2 tests"
        )),
    }
    if (8.0..64.0).contains(&entropy_bits) {
        poor = true;
        reasons.push(format!(
            "only {entropy_bits:.0} effective bits (64 or more is wanted)"
        ));
    }
    if entropy_bits >= 8.0 && entropy_bits < capacity_bits * 0.6 {
        poor = true;
        reasons.push(format!(
            "the characters are unevenly spread: {entropy_bits:.0} of {capacity_bits:.0} bits are used"
        ));
    }
    let verdict = if not_random {
        Verdict::NotRandom
    } else if poor {
        Verdict::Poor
    } else if entropy_bits >= 100.0 {
        Verdict::Excellent
    } else {
        Verdict::Good
    };
    if verdict >= Verdict::Good {
        reasons.push(format!("{entropy_bits:.0} effective bits and no test failed"));
    }
    let reliable = n >= RELIABLE_TOKENS;
    if !reliable {
        reasons.push(format!(
            "only {n} tokens: {RELIABLE_TOKENS} or more are needed to trust this"
        ));
    }
    Ok(Analysis {
        tokens: n,
        unique,
        min_length: min_len,
        max_length: max_len,
        charset_size: global.len(),
        charset,
        positions,
        entropy_bits,
        capacity_bits,
        bit_stream_len,
        biased_bits: biased_total,
        bit_positions,
        fips,
        sequential_share: seq,
        verdict,
        reliable,
        reasons,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Extraction

/// Where a token sits in a response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenSource {
    /// The value of a response header (the first with that name).
    Header { name: String },
    /// The value of a `Set-Cookie` cookie.
    Cookie { name: String },
    /// A regular expression over the body: capture group 1 if there is one, else the whole match.
    Regex { pattern: String },
}

/// A compiled [`TokenSource`].
pub struct Extractor(Kind);

enum Kind {
    Header(Vec<u8>),
    Cookie(Vec<u8>),
    Regex(regex::bytes::Regex),
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).chars().take(MAX_TOKEN_CHARS).collect()
}

impl Extractor {
    pub fn new(src: &TokenSource) -> Result<Self, Error> {
        Ok(Self(match src {
            TokenSource::Header { name } if !name.is_empty() && name.len() <= 256 => {
                Kind::Header(name.as_bytes().to_vec())
            }
            TokenSource::Cookie { name } if !name.is_empty() && name.len() <= 256 => {
                Kind::Cookie(name.as_bytes().to_vec())
            }
            TokenSource::Header { .. } | TokenSource::Cookie { .. } => {
                return Err(Error::BadPattern("the name is empty or too long".into()));
            }
            TokenSource::Regex { pattern } => {
                if pattern.len() > MAX_PATTERN {
                    return Err(Error::BadPattern("too long".into()));
                }
                Kind::Regex(
                    regex::bytes::RegexBuilder::new(pattern)
                        .size_limit(1 << 20)
                        .dfa_size_limit(1 << 20)
                        .build()
                        .map_err(|e| Error::BadPattern(e.to_string()))?,
                )
            }
        }))
    }

    /// Pull the token out of a raw HTTP/1 response (head and body). None when it is not there. A token is cut at
    /// 1 024 characters.
    pub fn extract(&self, response: &[u8]) -> Option<String> {
        let (head, body) = match response.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(i) => (&response[..i], &response[i + 4..]),
            None => (response, &response[response.len()..]),
        };
        let header_lines = || {
            head.split(|b| *b == b'\n').skip(1).filter_map(|l| {
                let l = l.strip_suffix(b"\r").unwrap_or(l);
                let c = l.iter().position(|b| *b == b':')?;
                Some((&l[..c], l[c + 1..].trim_ascii()))
            })
        };
        match &self.0 {
            Kind::Header(name) => header_lines()
                .find(|(k, _)| k.trim_ascii().eq_ignore_ascii_case(name))
                .map(|(_, v)| lossy(v)),
            Kind::Cookie(name) => header_lines()
                .filter(|(k, _)| k.eq_ignore_ascii_case(b"set-cookie"))
                .find_map(|(_, v)| {
                    let pair = v.split(|b| *b == b';').next()?;
                    let eq = pair.iter().position(|b| *b == b'=')?;
                    (pair[..eq].trim_ascii() == name.as_slice()).then(|| lossy(pair[eq + 1..].trim_ascii()))
                }),
            Kind::Regex(re) => {
                let caps = re.captures(body)?;
                let m = caps.get(1).or_else(|| caps.get(0))?;
                Some(lossy(m.as_bytes()))
            }
        }
    }
}

#[cfg(test)]
mod tests;
