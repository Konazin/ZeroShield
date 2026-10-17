//! Block/allow decision logic (pure, easy to test).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed { rule: String },
    Blocked { rule: String },
    Unknown,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allowed { .. } => "allowed",
            Decision::Blocked { .. } => "blocked",
            Decision::Unknown => "unknown",
        }
    }

    pub fn rule(&self) -> Option<&str> {
        match self {
            Decision::Allowed { rule } | Decision::Blocked { rule } => Some(rule),
            Decision::Unknown => None,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Blocklist {
    blocked_nets: Vec<(u32, u8)>,
    blocked_domains: Vec<String>,
    allowed_nets: Vec<(u32, u8)>,
    allowed_domains: Vec<String>,
}

impl Blocklist {
    /// Add one entry. `allowed` selects the allow or block side.
    /// Returns false when the value cannot be parsed.
    pub fn add(&mut self, kind: &str, value: &str, allowed: bool) -> bool {
        match kind {
            "ip" => match parse_ipv4_u32(value) {
                Some(ip) => {
                    self.push_net(ip, 32, allowed);
                    true
                }
                None => false,
            },
            "cidr" => match parse_cidr(value) {
                Some((net, prefix)) => {
                    self.push_net(net, prefix, allowed);
                    true
                }
                None => false,
            },
            "domain" => {
                let d = value.trim().trim_end_matches('.').to_ascii_lowercase();
                if d.is_empty() {
                    return false;
                }
                if allowed {
                    self.allowed_domains.push(d);
                } else {
                    self.blocked_domains.push(d);
                }
                true
            }
            _ => false,
        }
    }

    fn push_net(&mut self, net: u32, prefix: u8, allowed: bool) {
        if allowed {
            self.allowed_nets.push((net, prefix));
        } else {
            self.blocked_nets.push((net, prefix));
        }
    }

    /// Validate an IP address string (used by audit).
    pub fn is_ip(value: &str) -> bool {
        parse_ipv4_u32(value).is_some()
    }

    pub fn decision_ip(&self, ip: &str) -> Decision {
        let Some(parsed) = parse_ipv4_u32(ip) else {
            return Decision::Unknown;
        };
        for (net, prefix) in &self.allowed_nets {
            if net_contains(*net, *prefix, parsed) {
                return Decision::Allowed {
                    rule: format!("{}/{}", u32_to_ip(*net), prefix),
                };
            }
        }
        for (net, prefix) in &self.blocked_nets {
            if net_contains(*net, *prefix, parsed) {
                return Decision::Blocked {
                    rule: format!("{}/{}", u32_to_ip(*net), prefix),
                };
            }
        }
        Decision::Unknown
    }

    pub fn decision_domain(&self, domain: &str) -> Decision {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        for allowed in &self.allowed_domains {
            if domain_matches(&d, allowed) {
                return Decision::Allowed {
                    rule: allowed.clone(),
                };
            }
        }
        for blocked in &self.blocked_domains {
            if domain_matches(&d, blocked) {
                return Decision::Blocked {
                    rule: blocked.clone(),
                };
            }
        }
        Decision::Unknown
    }

    pub fn counts(&self) -> (usize, usize, usize, usize) {
        (
            self.blocked_nets.len(),
            self.blocked_domains.len(),
            self.allowed_nets.len(),
            self.allowed_domains.len(),
        )
    }

    pub fn blocked_net_strings(&self) -> Vec<String> {
        self.blocked_nets
            .iter()
            .map(|(net, prefix)| format!("{}/{}", u32_to_ip(*net), prefix))
            .collect()
    }

    /// Blocked domains that are not overridden by the allowlist, sorted and
    /// deduplicated. Used to build the DNS sinkhole fragment.
    pub fn blocked_domain_strings(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .blocked_domains
            .iter()
            .filter(|d| !self.allowed_domains.iter().any(|a| domain_matches(d, a)))
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

fn domain_matches(domain: &str, rule: &str) -> bool {
    domain == rule || domain.ends_with(&format!(".{rule}"))
}

fn net_contains(net: u32, prefix: u8, ip: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    (net & mask) == (ip & mask)
}

pub fn parse_ipv4_u32(s: &str) -> Option<u32> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out: u32 = 0;
    for part in parts {
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        out = (out << 8) | v;
    }
    Some(out)
}

pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = s.trim().split_once('/')?;
    let net = parse_ipv4_u32(addr)?;
    let len: u8 = prefix.parse().ok()?;
    if len > 32 {
        return None;
    }
    Some((net, len))
}

pub fn u32_to_ip(v: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (v >> 24) & 0xff,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_wins_over_blocklist() {
        let mut bl = Blocklist::default();
        bl.add("cidr", "10.0.0.0/8", false);
        bl.add("ip", "10.1.1.1", true);
        assert!(matches!(
            bl.decision_ip("10.2.3.4"),
            Decision::Blocked { .. }
        ));
        assert!(matches!(
            bl.decision_ip("10.1.1.1"),
            Decision::Allowed { .. }
        ));
        assert!(matches!(bl.decision_ip("192.168.1.1"), Decision::Unknown));
    }

    #[test]
    fn domain_suffix_matching() {
        let mut bl = Blocklist::default();
        bl.add("domain", "evil.example", false);
        assert!(matches!(
            bl.decision_domain("evil.example"),
            Decision::Blocked { .. }
        ));
        assert!(matches!(
            bl.decision_domain("sub.evil.example"),
            Decision::Blocked { .. }
        ));
        assert!(matches!(
            bl.decision_domain("notevil.example"),
            Decision::Unknown
        ));
        assert!(matches!(
            bl.decision_domain("example.com"),
            Decision::Unknown
        ));
    }

    #[test]
    fn rejects_garbage() {
        let mut bl = Blocklist::default();
        assert!(!bl.add("ip", "not-an-ip", false));
        assert!(!bl.add("cidr", "10.0.0.0/33", false));
        assert!(!bl.add("domain", "  ", false));
    }

    #[test]
    fn cidr_edge_cases() {
        let mut bl = Blocklist::default();
        bl.add("cidr", "0.0.0.0/0", false);
        assert!(matches!(
            bl.decision_ip("8.8.8.8"),
            Decision::Blocked { .. }
        ));
    }

    #[test]
    fn roundtrip_u32() {
        let ip = parse_ipv4_u32("192.168.0.1").unwrap();
        assert_eq!(u32_to_ip(ip), "192.168.0.1");
    }
}
