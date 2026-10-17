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

pub fn load_feed_file(path: &Path, source: &str) -> ZsResult<Vec<FeedEntry>> {
    let text = std::fs::read_to_string(path).map_err(|e| ZsError::io(path, e))?;
    Ok(parse_feed(&text, source))
}

/// Parse any feed text into unique entries.
pub fn parse_feed(text: &str, source: &str) -> Vec<FeedEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line);
        if line.trim().is_empty() {
            continue;
        }
        for token in tokenize(line) {
            if let Some(entry) = classify(&token, source) {
                let key = format!("{}:{}", entry.kind, entry.value);
                if seen.insert(key) {
                    out.push(entry);
                }
            }
        }
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
}
