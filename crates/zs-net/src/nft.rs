//! nftables ruleset generation and application.
//!
//! ZeroShield always owns a single isolated table (`netguard.nft_table`,
//! default `zeroshield`) and never touches other tables. Blocking policy is
//! applied to the `output` hook: outbound traffic to feed-listed addresses is
//! dropped, everything else is accepted.

use std::path::{Path, PathBuf};
use std::process::Command;

use zs_core::error::{ZsError, ZsResult};
use zs_core::util::is_root;

pub fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Generate the full ruleset text for the isolated table.
pub fn generate_ruleset(table: &str, blocked_ips: &[String]) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {table} {{\n"));
    s.push_str("    set blocked_v4 {\n");
    s.push_str("        type ipv4_addr\n");
    s.push_str("        flags interval\n");
    s.push_str("        comment \"ZeroShield threat feeds\"\n");
    if !blocked_ips.is_empty() {
        s.push_str("        elements = {\n");
        let last = blocked_ips.len() - 1;
        for (i, entry) in blocked_ips.iter().enumerate() {
            let comma = if i == last { "" } else { "," };
            s.push_str(&format!("            {entry}{comma}\n"));
        }
        s.push_str("        }\n");
    }
    s.push_str("    }\n\n");
    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority 10; policy accept;\n");
    s.push_str("        ip daddr @blocked_v4 counter drop comment \"zeroshield-block\"\n");
    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

pub fn write_ruleset(path: &Path, ruleset: &str) -> ZsResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| ZsError::io(parent, e))?;
    }
    std::fs::write(path, ruleset).map_err(|e| ZsError::io(path, e))
}

/// Remove the whole table (ignores "table not found").
pub fn flush(table: &str) -> ZsResult<()> {
    if !is_root() {
        return Err(ZsError::Permission(
            "flushing nftables requires root".into(),
        ));
    }
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", table])
        .output();
    Ok(())
}

/// Apply a ruleset file via `nft -f`. Replaces the table atomically.
pub fn apply_file(path: &Path) -> ZsResult<String> {
    if !is_root() {
        return Err(ZsError::Permission(
            "applying nftables rules requires root".into(),
        ));
    }
    if !nft_available() {
        return Err(ZsError::Net(
            "the 'nft' binary is not installed (package: nftables)".into(),
        ));
    }
    let output = Command::new("nft")
        .arg("-f")
        .arg(path)
        .output()
        .map_err(|e| ZsError::Net(format!("failed to run nft: {e}")))?;
    if !output.status.success() {
        return Err(ZsError::Net(format!(
            "nft rejected the ruleset: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Default location for the generated ruleset (inspectable by the user).
pub fn default_ruleset_path(data_dir: &Path) -> PathBuf {
    data_dir.join("netguard.nft")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_contains_elements_and_hook() {
        let text = generate_ruleset(
            "zeroshield",
            &["1.2.3.4".to_string(), "10.0.0.0/8".to_string()],
        );
        assert!(text.contains("table inet zeroshield"));
        assert!(text.contains("1.2.3.4,"));
        assert!(text.contains("10.0.0.0/8\n"));
        assert!(text.contains("hook output"));
        assert!(text.contains("drop"));
    }

    #[test]
    fn empty_ruleset_is_valid() {
        let text = generate_ruleset("zeroshield", &[]);
        assert!(!text.contains("elements"));
        assert!(text.contains("set blocked_v4"));
    }

    #[test]
    fn writes_ruleset_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/netguard.nft");
        write_ruleset(&path, &generate_ruleset("t", &[])).unwrap();
        assert!(path.exists());
    }
}
