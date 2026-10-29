//! Multi-pattern heuristic rules, matched in a single Aho-Corasick pass.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

static EMBEDDED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rules.bin"));

/// Inverse of the obfuscation in build.rs.
fn decode(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, b)| b ^ (0xA5u8.wrapping_add((i as u8).wrapping_mul(31))))
        .collect()
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
}

pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    pub matched: Vec<&'a str>,
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
        let mut seen: Vec<Vec<bool>> = self.rules.iter().map(|r| vec![false; r.patterns.len()]).collect();
        for (ac, map) in &self.automatons {
            for m in ac.find_overlapping_iter(data) {
                let (ri, pi) = map[m.pattern().as_usize()];
                seen[ri][pi] = true;
            }
        }
        self.rules
            .iter()
            .zip(seen)
            .filter(|(r, _)| r.scope == Scope::Any || r.scope == scope)
            .filter_map(|(rule, s)| {
                let matched: Vec<&str> = rule.patterns.iter().zip(&s).filter(|(_, hit)| **hit).map(|(p, _)| p.as_str()).collect();
                (matched.len() >= rule.min.max(1)).then_some(RuleMatch { rule, matched })
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
            ("str", Some(r)) if !rest.is_empty() => r.patterns.push(rest.to_string()),
            _ => errors.push(format!("line {}: unexpected `{line}`", n + 1)),
        }
    }
    if let Some(r) = cur {
        errors.push(format!("rule {} is missing `end`", r.id));
    }
    (rules, errors)
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

    impl RuleSet {
        fn build_for_test(text: &str) -> (Self, Vec<String>) {
            let (r, e) = parse(text);
            (Self::build(r), e)
        }
    }
}
