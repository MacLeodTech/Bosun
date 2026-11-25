//! The Comparer: a word-level or byte-level diff of two messages.
//!
//! Equal prefixes and suffixes are trimmed first, then the middle is compared with a longest-common-subsequence
//! table. The table is capped, so two huge, very different inputs cost bounded time and memory: past the cap the
//! differing middle is reported as one deletion and one insertion.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The most table cells the comparison may use (4 bytes each: about 16 MiB).
const MAX_CELLS: usize = 4_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffLevel {
    /// Split on whitespace and punctuation; whitespace is kept, so the pieces rejoin to the original.
    Words,
    Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Equal,
    Delete,
    Insert,
}

/// A run of pieces. `a_start` and `b_start` are byte offsets into the two inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DiffOp {
    pub kind: DiffKind,
    pub a_start: usize,
    pub b_start: usize,
    /// Length in bytes (of `a` for equal and delete, of `b` for insert).
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct DiffResult {
    pub ops: Vec<DiffOp>,
    /// True when the inputs were too different or too large to compare piece by piece.
    pub coarse: bool,
    /// Bytes that are the same / different, for a one-line summary.
    pub equal_bytes: usize,
    pub changed_bytes: usize,
}

/// Cut `data` into pieces. Returns the end offset of each piece.
fn pieces(data: &[u8], level: DiffLevel) -> Vec<usize> {
    match level {
        DiffLevel::Bytes => (1..=data.len()).collect(),
        DiffLevel::Words => {
            let mut ends = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let start = i;
                let class = |b: u8| {
                    if b.is_ascii_alphanumeric() || b >= 0x80 {
                        0
                    } else if b.is_ascii_whitespace() {
                        1
                    } else {
                        2
                    }
                };
                let c = class(data[i]);
                i += 1;
                // Punctuation is one piece per byte; words and whitespace run together.
                if c != 2 {
                    while i < data.len() && class(data[i]) == c {
                        i += 1;
                    }
                }
                debug_assert!(i > start);
                ends.push(i);
            }
            ends
        }
    }
}

fn slice<'a>(data: &'a [u8], ends: &[usize], i: usize) -> &'a [u8] {
    let s = if i == 0 { 0 } else { ends[i - 1] };
    &data[s..ends[i]]
}

pub fn diff(a: &[u8], b: &[u8], level: DiffLevel) -> DiffResult {
    let (ae, be) = (pieces(a, level), pieces(b, level));
    let (n, m) = (ae.len(), be.len());
    let eq = |i: usize, j: usize| slice(a, &ae, i) == slice(b, &be, j);

    let mut pre = 0;
    while pre < n && pre < m && eq(pre, pre) {
        pre += 1;
    }
    let mut suf = 0;
    while suf < n - pre && suf < m - pre && eq(n - 1 - suf, m - 1 - suf) {
        suf += 1;
    }
    let (n2, m2) = (n - pre - suf, m - pre - suf);

    // The middle, as a list of (kind, a piece index, b piece index, count) before it is turned into byte runs.
    let mut mid: Vec<(DiffKind, usize, usize)> = Vec::new(); // one entry per piece
    let mut coarse = false;
    if n2 == 0 || m2 == 0 || n2.saturating_mul(m2) > MAX_CELLS {
        coarse = n2 != 0 && m2 != 0;
        for i in 0..n2 {
            mid.push((DiffKind::Delete, pre + i, 0));
        }
        for j in 0..m2 {
            mid.push((DiffKind::Insert, 0, pre + j));
        }
    } else {
        let w = m2 + 1;
        let mut t = vec![0u32; (n2 + 1) * w];
        for i in (0..n2).rev() {
            for j in (0..m2).rev() {
                t[i * w + j] = if eq(pre + i, pre + j) {
                    t[(i + 1) * w + j + 1] + 1
                } else {
                    t[(i + 1) * w + j].max(t[i * w + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n2 || j < m2 {
            if i < n2 && j < m2 && eq(pre + i, pre + j) {
                mid.push((DiffKind::Equal, pre + i, pre + j));
                i += 1;
                j += 1;
            } else if j < m2 && (i == n2 || t[i * w + j + 1] >= t[(i + 1) * w + j]) {
                mid.push((DiffKind::Insert, 0, pre + j));
                j += 1;
            } else {
                mid.push((DiffKind::Delete, pre + i, 0));
                i += 1;
            }
        }
    }

    // Assemble byte runs: prefix, middle, suffix, merging neighbours of the same kind.
    let mut ops: Vec<DiffOp> = Vec::new();
    let mut push = |kind: DiffKind, a_start: usize, b_start: usize, len: usize| {
        if len == 0 {
            return;
        }
        if let Some(last) = ops.last_mut()
            && last.kind == kind
            && (kind == DiffKind::Insert || last.a_start + last.len == a_start)
            && (kind == DiffKind::Delete || last.b_start + last.len == b_start)
        {
            last.len += len;
            return;
        }
        ops.push(DiffOp {
            kind,
            a_start,
            b_start,
            len,
        });
    };
    let a_off = |i: usize| if i == 0 { 0 } else { ae[i - 1] };
    let b_off = |j: usize| if j == 0 { 0 } else { be[j - 1] };
    if pre > 0 {
        push(DiffKind::Equal, 0, 0, a_off(pre));
    }
    for &(kind, i, j) in &mid {
        match kind {
            DiffKind::Equal => push(kind, a_off(i), b_off(j), ae[i] - a_off(i)),
            DiffKind::Delete => push(kind, a_off(i), 0, ae[i] - a_off(i)),
            DiffKind::Insert => push(kind, 0, b_off(j), be[j] - b_off(j)),
        }
    }
    if suf > 0 {
        push(
            DiffKind::Equal,
            a_off(n - suf),
            b_off(m - suf),
            a.len() - a_off(n - suf),
        );
    }
    // Inserts carry the a offset of the point they land at, so a viewer can place them.
    let (mut ap, mut equal_bytes, mut changed_bytes) = (0, 0, 0);
    for op in &mut ops {
        match op.kind {
            DiffKind::Equal => {
                equal_bytes += op.len;
                ap = op.a_start + op.len;
            }
            DiffKind::Delete => {
                changed_bytes += op.len;
                ap = op.a_start + op.len;
            }
            DiffKind::Insert => {
                changed_bytes += op.len;
                op.a_start = ap;
            }
        }
    }
    DiffResult {
        ops,
        coarse,
        equal_bytes,
        changed_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Rebuild both inputs from the ops: the check that a diff is faithful.
    fn rebuild(a: &[u8], b: &[u8], r: &DiffResult) -> (Vec<u8>, Vec<u8>) {
        let (mut ra, mut rb) = (Vec::new(), Vec::new());
        for op in &r.ops {
            match op.kind {
                DiffKind::Equal => {
                    ra.extend_from_slice(&a[op.a_start..op.a_start + op.len]);
                    rb.extend_from_slice(&b[op.b_start..op.b_start + op.len]);
                }
                DiffKind::Delete => ra.extend_from_slice(&a[op.a_start..op.a_start + op.len]),
                DiffKind::Insert => rb.extend_from_slice(&b[op.b_start..op.b_start + op.len]),
            }
        }
        (ra, rb)
    }

    #[test]
    fn identical_inputs_are_one_equal_run() {
        let r = diff(b"same text", b"same text", DiffLevel::Words);
        assert_eq!(r.ops.len(), 1);
        assert_eq!(r.changed_bytes, 0);
        assert!(!r.coarse);
    }

    #[test]
    fn a_changed_word_shows_as_delete_and_insert() {
        let (a, b) = (&b"GET /a HTTP/1.1"[..], &b"GET /b HTTP/1.1"[..]);
        let r = diff(a, b, DiffLevel::Words);
        assert_eq!(rebuild(a, b, &r), (a.to_vec(), b.to_vec()));
        assert!(
            r.ops
                .iter()
                .any(|o| o.kind == DiffKind::Delete && &a[o.a_start..o.a_start + o.len] == b"a")
        );
        assert!(
            r.ops
                .iter()
                .any(|o| o.kind == DiffKind::Insert && &b[o.b_start..o.b_start + o.len] == b"b")
        );
    }

    #[test]
    fn empty_sides() {
        assert!(diff(b"", b"", DiffLevel::Bytes).ops.is_empty());
        let r = diff(b"", b"abc", DiffLevel::Bytes);
        assert_eq!(
            r.ops,
            vec![DiffOp {
                kind: DiffKind::Insert,
                a_start: 0,
                b_start: 0,
                len: 3
            }]
        );
        let r = diff(b"abc", b"", DiffLevel::Bytes);
        assert_eq!(
            r.ops,
            vec![DiffOp {
                kind: DiffKind::Delete,
                a_start: 0,
                b_start: 0,
                len: 3
            }]
        );
    }

    #[test]
    fn huge_different_inputs_stay_bounded_and_faithful() {
        let a: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let b: Vec<u8> = (0..20_000u32).map(|i| (i % 241) as u8 ^ 1).collect();
        let r = diff(&a, &b, DiffLevel::Bytes);
        assert!(r.coarse);
        assert_eq!(rebuild(&a, &b, &r), (a, b));
    }

    #[test]
    fn non_ascii_is_not_split_inside_a_character() {
        let (a, b) = ("héllo wörld".as_bytes(), "héllo wörld!".as_bytes());
        let r = diff(a, b, DiffLevel::Words);
        assert_eq!(rebuild(a, b, &r), (a.to_vec(), b.to_vec()));
    }

    proptest! {
        #[test]
        fn rebuilds_both_inputs(a in proptest::collection::vec(any::<u8>(), 0..120), b in proptest::collection::vec(any::<u8>(), 0..120)) {
            for level in [DiffLevel::Words, DiffLevel::Bytes] {
                let r = diff(&a, &b, level);
                prop_assert_eq!(rebuild(&a, &b, &r), (a.clone(), b.clone()));
                prop_assert_eq!(r.equal_bytes + r.changed_bytes >= a.len().max(b.len()), true);
            }
        }

        #[test]
        fn words_of_text(a in "[a-c ,.]{0,60}", b in "[a-c ,.]{0,60}") {
            let r = diff(a.as_bytes(), b.as_bytes(), DiffLevel::Words);
            prop_assert_eq!(rebuild(a.as_bytes(), b.as_bytes(), &r), (a.clone().into_bytes(), b.clone().into_bytes()));
        }
    }
}
