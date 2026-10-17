//! Threat feed parsing.
//!
//! Parsers are deliberately forgiving: feeds in the wild are plain text,
//! CSV, or "one URL per line" formats. Any token that looks like an IPv4
//! address, a CIDR range or a domain is extracted.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zs_core::error::{ZsError, ZsResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// `ip`, `cidr` or `domain`.
    pub kind: String,
    pub value: String,
    pub source: String,
}

impl FeedEntry {
    fn new(kind: &str, value: impl Into<String>, source: &str) -> Self {
        Self {
            kind: kind.to_string(),
            value: value.into(),
            source: source.to_string(),
        }
    }
}

/// Largest feed file accepted from disk (bytes). Downloads are bounded by the
/// same limit (`curl --max-filesize`).
pub const MAX_FEED_BYTES: u64 = 64 * 1024 * 1024;

/// Largest number of entries extracted from one feed; beyond this the parse
/// stops (with a warning) instead of growing without bound.
pub const MAX_FEED_ENTRIES: usize = 1_000_000;

/// Longest single feed line considered (bytes); longer lines are skipped.
pub const MAX_FEED_LINE_BYTES: usize = 8 * 1024;

pub fn load_feed_file(path: &Path, source: &str) -> ZsResult<Vec<FeedEntry>> {
    load_feed_file_limited(path, source, MAX_FEED_BYTES)
}

/// Like [`load_feed_file`], but with an explicit size cap (tests use small
/// caps to avoid writing huge files).
pub fn load_feed_file_limited(
    path: &Path,
    source: &str,
    max_bytes: u64,
) -> ZsResult<Vec<FeedEntry>> {
    let meta = std::fs::metadata(path).map_err(|e| ZsError::io(path, e))?;
    if meta.len() > max_bytes {
        return Err(ZsError::Net(format!(
            "feed {} is {} bytes (limit {max_bytes})",
            path.display(),
            meta.len()
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|e| ZsError::io(path, e))?;
    Ok(parse_feed(&text, source))
}

/// Parse any feed text into unique entries.
pub fn parse_feed(text: &str, source: &str) -> Vec<FeedEntry> {
    parse_feed_capped(text, source, MAX_FEED_ENTRIES)
}

/// Like [`parse_feed`], but with an explicit entry cap (tests use small caps).
pub fn parse_feed_capped(text: &str, source: &str, max_entries: usize) -> Vec<FeedEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut long_lines = 0u64;
    let mut capped = false;
    'lines: for line in text.lines() {
        if line.len() > MAX_FEED_LINE_BYTES {
            long_lines += 1;
            continue;
        }
        let line = strip_comment(line);
        if line.trim().is_empty() {
            continue;
        }
        for token in tokenize(line) {
            if out.len() >= max_entries {
                capped = true;
                break 'lines;
            }
            if let Some(entry) = classify(&token, source) {
                let key = format!("{}:{}", entry.kind, entry.value);
                if seen.insert(key) {
                    out.push(entry);
                }
            }
        }
    }
    if capped {
        tracing::warn!("feed {source}: entry limit ({max_entries}) reached, truncating");
    }
    if long_lines > 0 {
        tracing::warn!(
            "feed {source}: skipped {long_lines} line(s) longer than \
             {MAX_FEED_LINE_BYTES} bytes"
        );
    }
    out
}

fn strip_comment(line: &str) -> &str {
    if line.trim_start().starts_with('#') {
        return "";
    }
    match line.find(" #") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

fn tokenize(line: &str) -> Vec<String> {
    line.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '"' | '\'' | '(' | ')' | '[' | ']' | '<' | '>' | '\\'
            )
    })
    .filter(|t| !t.is_empty())
    .map(|t| t.to_string())
    .collect()
}

fn classify(token: &str, source: &str) -> Option<FeedEntry> {
    let mut t = token.trim().trim_matches('.').to_string();
    if t.is_empty() {
        return None;
    }

    // URLs: keep the hostname (this is the useful part of URLhaus text feeds).
    if let Some(rest) = t
        .strip_prefix("http://")
        .or_else(|| t.strip_prefix("https://"))
    {
        let host = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        t = host;
    }

    if t.contains('@') {
        return None; // e-mail address, not a network indicator
    }

    if let Some((addr, prefix)) = t.split_once('/') {
        if let (Some(net), Ok(len)) = (parse_ipv4(addr), prefix.parse::<u8>()) {
            if len <= 32 {
                return Some(FeedEntry::new("cidr", format!("{net}/{len}"), source));
            }
        }
        return None;
    }

    if let Some(net) = parse_ipv4(&t) {
        return Some(FeedEntry::new("ip", net, source));
    }

    if looks_like_domain(&t) {
        return Some(FeedEntry::new("domain", t.to_ascii_lowercase(), source));
    }

    None
}

pub fn parse_ipv4(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for part in &parts {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        if part.parse::<u16>().ok()? > 255 {
            return None;
        }
    }
    Some(parts.join("."))
}

fn looks_like_domain(s: &str) -> bool {
    if s.len() > 253 || !s.contains('.') || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if !labels.iter().all(|l| {
        !l.is_empty()
            && l.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }) {
        return false;
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_feed() {
        let text = r#"
# abuse.ch style comment
1.2.3.4
5.6.7.0/24
evil.example.com
https://bad.domain/path/payload.exe
102.33.55.1 # inline comment
not_a_target
"#;
        let entries = parse_feed(text, "test");
        let values: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.kind.as_str(), e.value.as_str()))
            .collect();
        assert!(values.contains(&("ip", "1.2.3.4")));
        assert!(values.contains(&("cidr", "5.6.7.0/24")));
        assert!(values.contains(&("domain", "evil.example.com")));
        assert!(values.contains(&("domain", "bad.domain")));
        assert!(values.contains(&("ip", "102.33.55.1")));
        assert!(!values.iter().any(|(_, v)| *v == "not_a_target"));
    }

    #[test]
    fn deduplicates() {
        let text = "1.1.1.1\n1.1.1.1\n";
        assert_eq!(parse_feed(text, "t").len(), 1);
    }

    #[test]
    fn rejects_bad_ipv4() {
        assert!(parse_ipv4("999.1.1.1").is_none());
        assert!(parse_ipv4("1.1.1").is_none());
        assert_eq!(parse_ipv4("10.0.0.1").unwrap(), "10.0.0.1");
    }

    #[test]
    fn caps_entries() {
        let text = "1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n";
        let entries = parse_feed_capped(text, "t", 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].value, "1.1.1.1");
        assert_eq!(entries[1].value, "2.2.2.2");
    }

    #[test]
    fn skips_giant_lines() {
        let mut text = String::from("1.2.3.4 ");
        text.push_str(&"a".repeat(MAX_FEED_LINE_BYTES));
        text.push('\n');
        text.push_str("5.6.7.8\n");
        let entries = parse_feed(&text, "t");
        assert!(!entries.iter().any(|e| e.value == "1.2.3.4"));
        assert!(entries.iter().any(|e| e.value == "5.6.7.8"));
    }

    #[test]
    fn rejects_oversized_files() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("feed.txt");
        std::fs::write(&p, "1.2.3.4\n").unwrap();
        let err = load_feed_file_limited(&p, "t", 4).unwrap_err();
        assert!(err.to_string().contains("limit 4"), "{err}");
        // Under the cap it loads normally.
        let entries = load_feed_file_limited(&p, "t", 1024).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
