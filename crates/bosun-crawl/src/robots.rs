//! `robots.txt`: the rules for our user agent, and the sitemaps it names.

/// The product token matched against `User-agent` lines.
pub const AGENT: &str = "bosun";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Robots {
    /// `(allow, pattern)` for the group that applies to us.
    rules: Vec<(bool, String)>,
    pub sitemaps: Vec<String>,
}

impl Robots {
    pub fn parse(text: &str) -> Self {
        type Group = (Vec<String>, Vec<(bool, String)>);
        let mut groups: Vec<Group> = Vec::new();
        let mut sitemaps = Vec::new();
        let mut in_rules = true;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "user-agent" => {
                    if in_rules || groups.is_empty() {
                        groups.push((Vec::new(), Vec::new()));
                        in_rules = false;
                    }
                    if let Some(g) = groups.last_mut() {
                        g.0.push(v.to_ascii_lowercase());
                    }
                }
                "allow" | "disallow" => {
                    in_rules = true;
                    if let Some(g) = groups.last_mut()
                        && !v.is_empty()
                    {
                        g.1.push((k == "allow", v.to_string()));
                    }
                }
                "sitemap" if !v.is_empty() => sitemaps.push(v.to_string()),
                _ => {}
            }
        }
        let named = groups.iter().find(|g| {
            g.0.iter()
                .any(|a| a != "*" && !a.is_empty() && AGENT.contains(a.as_str()))
        });
        let star = groups.iter().find(|g| g.0.iter().any(|a| a == "*"));
        Self {
            rules: named.or(star).map(|g| g.1.clone()).unwrap_or_default(),
            sitemaps,
        }
    }

    /// May we fetch `path` (with its query)? The longest matching rule wins; `Allow` wins a tie.
    pub fn allowed(&self, path: &str) -> bool {
        let mut best: Option<(usize, bool)> = None;
        for (allow, pat) in &self.rules {
            if matches(pat.as_bytes(), path.as_bytes()) {
                let cand = (pat.len(), *allow);
                if best.is_none_or(|b| cand.0 > b.0 || (cand.0 == b.0 && cand.1)) {
                    best = Some(cand);
                }
            }
        }
        best.is_none_or(|b| b.1)
    }

    /// The paths named by `Disallow` rules that are plain paths, which a tester usually wants to look at.
    pub fn disallowed_paths(&self) -> Vec<String> {
        self.rules
            .iter()
            .filter(|(a, p)| !a && p.starts_with('/') && !p.contains(['*', '$']))
            .map(|(_, p)| p.clone())
            .collect()
    }
}

/// Prefix match with `*` (any run) and a trailing `$` (end of path). Iterative, so a hostile pattern such as
/// `*a*a*a*b` costs at most pattern length times path length.
fn matches(pat: &[u8], s: &[u8]) -> bool {
    let (pat, anchored) = match pat.split_last() {
        Some((b'$', head)) => (head, true),
        _ => (pat, false),
    };
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if j == pat.len() && (!anchored || i == s.len()) {
            return true;
        }
        if j < pat.len() {
            if pat[j] == b'*' {
                star = Some((j, i));
                j += 1;
                continue;
            }
            if i < s.len() && pat[j] == s[i] {
                i += 1;
                j += 1;
                continue;
            }
        }
        // Mismatch: let the last star take one more byte.
        match star {
            Some((sj, si)) if si < s.len() => {
                star = Some((sj, si + 1));
                j = sj + 1;
                i = si + 1;
            }
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_precedence() {
        let r = Robots::parse(
            "User-agent: *\nDisallow: /private\nAllow: /private/ok\nDisallow: /*.pdf$\n\nUser-agent: other\nDisallow: /\n\nSitemap: http://h/sm.xml\n",
        );
        assert!(r.allowed("/"));
        assert!(!r.allowed("/private/x"));
        assert!(r.allowed("/private/ok/1"));
        assert!(!r.allowed("/a/b.pdf"));
        assert!(r.allowed("/a/b.pdf?x"));
        assert_eq!(r.sitemaps, ["http://h/sm.xml"]);
        assert_eq!(r.disallowed_paths(), ["/private"]);
    }

    #[test]
    fn our_own_group_beats_star() {
        let r = Robots::parse("User-agent: *\nDisallow: /\n\nUser-agent: Bosun\nDisallow: /x\n");
        assert!(r.allowed("/y"));
        assert!(!r.allowed("/x"));
    }

    #[test]
    fn hostile_patterns_are_cheap() {
        let pat = format!("{}b", "*a".repeat(2000));
        let r = Robots::parse(&format!("User-agent: *\nDisallow: {pat}\n"));
        assert!(r.allowed(&"a".repeat(5000)));
        assert!(matches(b"/*.pdf$", b"/a.pdf.pdf"));
    }

    #[test]
    fn empty_disallow_allows_everything() {
        assert!(Robots::parse("User-agent: *\nDisallow:\n").allowed("/anything"));
    }
}
