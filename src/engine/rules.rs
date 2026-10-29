//! Multi-pattern heuristic rules, matched in a single Aho-Corasick pass.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

static EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rules.bin"));

/// Inverse of the obfuscation in build.rs.
fn decode(data: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, b)| b ^ (0xA5u8.wrapping_add((i as u8).wrapping_mul(31)))).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Any,
    Pe,
    Script,
    Shortcut,
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub desc: String,
    pub weight: i32,
    pub min: usize,
    pub scope: Scope,
    /// Match case-sensitively (`case exact`), for names that would otherwise hit ordinary words.
    pub exact: bool,
    pub patterns: Vec<String>,
    /// Every group must have at least one hit, in addition to `min`.
    pub required: Vec<Vec<usize>>,
}

pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    pub matched: Vec<&'a str>,
    pub decoded: bool,
}

pub struct RuleSet {
    rules: Vec<Rule>,
    /// Case-insensitive and exact-case automatons, each with a map from automaton
    /// pattern index to (rule index, pattern index within the rule).
    automatons: Vec<(AhoCorasick, Vec<(usize, usize)>)>,
}

impl RuleSet {
    /// Builtin rules plus the user's optional custom rules file.
    pub fn load(custom: Option<&str>) -> (Self, Vec<String>) {
        let builtin = String::from_utf8_lossy(&decode(EMBEDDED)).into_owned();
        let (mut rules, mut errors) = parse(&builtin);
        if let Some(text) = custom {
            let (more, errs) = parse(text);
            rules.extend(more);
            errors.extend(errs.into_iter().map(|e| format!("custom.rules: {e}")));
        }
        (Self::build(rules), errors)
    }

    fn build(rules: Vec<Rule>) -> Self {
        let mut automatons = Vec::new();
        for exact in [false, true] {
            let mut needles: Vec<Vec<u8>> = Vec::new();
            let mut map = Vec::new();
            for (ri, rule) in rules.iter().enumerate().filter(|(_, r)| r.exact == exact) {
                for (pi, pat) in rule.patterns.iter().enumerate() {
                    for v in variants(pat) {
                        needles.push(v);
                        map.push((ri, pi));
                    }
                }
            }
            if needles.is_empty() {
                continue;
            }
            let ac = AhoCorasickBuilder::new()
                .ascii_case_insensitive(!exact)
                .match_kind(MatchKind::Standard)
                .build(&needles)
                .expect("rule automaton");
            automatons.push((ac, map));
        }
        Self { rules, automatons }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns every rule whose `min` threshold is met for a file of the given scope.
    pub fn scan(&self, data: &[u8], scope: Scope) -> Vec<RuleMatch<'_>> {
        self.scan_views(data, &[], scope)
    }

    /// Merge evidence across representations; each rule contributes only once.
    pub fn scan_views(&self, data: &[u8], views: &[Vec<u8>], scope: Scope) -> Vec<RuleMatch<'_>> {
        let mut seen: Vec<Vec<bool>> = self.rules.iter().map(|r| vec![false; r.patterns.len()]).collect();
        let mut raw = seen.clone();
        for (view_index, view) in std::iter::once(data).chain(views.iter().map(Vec::as_slice)).enumerate() {
            for (ac, map) in &self.automatons {
                for m in ac.find_overlapping_iter(view) {
                    let (ri, pi) = map[m.pattern().as_usize()];
                    seen[ri][pi] = true;
                    if view_index == 0 {
                        raw[ri][pi] = true;
                    }
                }
            }
        }
        self.rules
            .iter()
            .zip(seen)
            .zip(raw)
            .filter(|((r, _), _)| r.scope == Scope::Any || r.scope == scope)
            .filter_map(|((rule, s), raw)| {
                let matched: Vec<&str> = rule.patterns.iter().zip(&s).filter(|(_, hit)| **hit).map(|(p, _)| p.as_str()).collect();
                let groups_met = |hits: &[bool]| rule.required.iter().all(|g| g.iter().any(|&i| hits[i]));
                let decoded = raw.iter().filter(|&&hit| hit).count() < rule.min.max(1) || !groups_met(&raw);
                (matched.len() >= rule.min.max(1) && groups_met(&s)).then_some(RuleMatch { rule, matched, decoded })
            })
            .collect()
    }
}

/// A pattern is searched as written, with doubled backslashes (escaped in source
/// code/JSON), and as UTF-16LE (how .NET and Win32 store string literals).
fn variants(pat: &str) -> Vec<Vec<u8>> {
    let mut out = vec![pat.as_bytes().to_vec()];
    if pat.contains('\\') {
        out.push(pat.replace('\\', "\\\\").into_bytes());
    }
    out.push(pat.encode_utf16().flat_map(|u| u.to_le_bytes()).collect());
    out.push(pat.encode_utf16().flat_map(|u| u.to_be_bytes()).collect());
    out
}

fn parse(text: &str) -> (Vec<Rule>, Vec<String>) {
    let mut rules = Vec::new();
    let mut errors = Vec::new();
    let mut cur: Option<Rule> = None;
    for (n, raw) in text.trim_start_matches('\u{feff}').lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = line.split_once(char::is_whitespace).map(|(k, r)| (k, r.trim())).unwrap_or((line, ""));
        match (key, cur.as_mut()) {
            ("rule", None) => {
                cur = Some(Rule {
                    id: rest.to_string(),
                    desc: rest.to_string(),
                    weight: 10,
                    min: 1,
                    scope: Scope::Any,
                    exact: false,
                    patterns: Vec::new(),
                    required: Vec::new(),
                })
            }
            ("end", Some(_)) => {
                let r = cur.take().unwrap();
                if r.patterns.is_empty() {
                    errors.push(format!("line {}: rule {} has no patterns", n + 1, r.id));
                } else {
                    rules.push(r);
                }
            }
            ("desc", Some(r)) => r.desc = rest.to_string(),
            ("weight", Some(r)) => r.weight = rest.parse().unwrap_or(r.weight),
            ("min", Some(r)) => r.min = rest.parse().unwrap_or(r.min),
            ("scope", Some(r)) => {
                r.scope = match rest {
                    "pe" => Scope::Pe,
                    "script" => Scope::Script,
                    "shortcut" => Scope::Shortcut,
                    _ => Scope::Any,
                }
            }
            ("case", Some(r)) => r.exact = rest == "exact",
            ("str", Some(r)) if !rest.is_empty() => {
                add_pattern(r, rest);
            }
            ("require", Some(r)) if !rest.is_empty() => {
                let group: Vec<usize> = rest.split(" | ").map(str::trim).filter(|p| !p.is_empty()).map(|p| add_pattern(r, p)).collect();
                if !group.is_empty() {
                    r.required.push(group);
                }
            }
            _ => errors.push(format!("line {}: unexpected `{line}`", n + 1)),
        }
    }
    if let Some(r) = cur {
        errors.push(format!("rule {} is missing `end`", r.id));
    }
    (rules, errors)
}

fn add_pattern(rule: &mut Rule, pattern: &str) -> usize {
    if let Some(i) = rule.patterns.iter().position(|p| if rule.exact { p == pattern } else { p.eq_ignore_ascii_case(pattern) }) {
        i
    } else {
        rule.patterns.push(pattern.to_string());
        rule.patterns.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_parse() {
        let (set, errors) = RuleSet::load(None);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(set.len() > 15);
    }

    #[test]
    fn matches_utf16_and_case() {
        let (set, _) = RuleSet::build_for_test("rule t\n weight 5\n min 2\n str Alpha Beta\n str gamma\nend\n");
        let data: Vec<u8> = "xx ALPHA beta yy".bytes().chain("GAMMA".encode_utf16().flat_map(|u| u.to_le_bytes())).collect();
        assert_eq!(set.scan(&data, Scope::Pe).len(), 1);
        assert_eq!(set.scan(b"alpha beta only", Scope::Pe).len(), 0);
    }

    #[test]
    fn requires_independent_groups_and_distinct_patterns() {
        let (set, errors) =
            RuleSet::build_for_test("rule t\nmin 2\nrequire download | fetch\nrequire execute | invoke\nstr download\nstr DOWNLOAD\nend");
        assert!(errors.is_empty());
        assert!(set.scan(b"download fetch download", Scope::Script).is_empty());
        assert_eq!(set.scan(b"fetch execute", Scope::Script).len(), 1);
        let (set, _) = RuleSet::build_for_test("rule t\nmin 2\nstr alpha\nstr ALPHA\nend");
        assert!(set.scan(b"alpha ALPHA", Scope::Script).is_empty());
    }

    #[test]
    fn decoded_views_do_not_multiply_scores_or_bypass_scope() {
        let (set, _) = RuleSet::build_for_test("rule t\nscope script\nrequire download\nrequire execute\nend");
        let views = vec![b"download execute".to_vec(); 3];
        let hits = set.scan_views(b"download", &views, Scope::Script);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].decoded);
        assert_eq!(hits[0].matched.len(), 2);
        assert!(!set.scan_views(b"download execute", &views, Scope::Script)[0].decoded);
        assert!(set.scan_views(b"download", &views, Scope::Pe).is_empty());
    }

    #[test]
    fn exact_case_and_big_endian_are_preserved() {
        let (set, _) = RuleSet::build_for_test("rule t\ncase exact\nstr Alpha\nend");
        let wide: Vec<u8> = "Alpha".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(set.scan(&wide, Scope::Pe).len(), 1);
        assert!(set.scan(b"alpha", Scope::Pe).is_empty());
    }

    impl RuleSet {
        fn build_for_test(text: &str) -> (Self, Vec<String>) {
            let (r, e) = parse(text);
            (Self::build(r), e)
        }
    }
}
