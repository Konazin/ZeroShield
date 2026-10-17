//! `/proc` parsing.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use zs_core::model::ProcInfo;

pub fn list_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    pids.push(pid);
                }
            }
        }
    }
    pids.sort_unstable();
    pids
}

fn proc_path(pid: u32, file: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{file}"))
}

/// Read everything we can about one process. Returns `None` when the process
/// disappeared or is not visible.
pub fn read_proc(pid: u32) -> Option<ProcInfo> {
    let stat = fs::read_to_string(proc_path(pid, "stat")).ok()?;
    let (name, state, ppid, starttime) = parse_stat(&stat)?;

    let mut info = ProcInfo {
        pid,
        ppid,
        name,
        state,
        start_time: starttime,
        ..Default::default()
    };

    info.cmdline = read_cmdline(pid);

    if let Ok(target) = fs::read_link(proc_path(pid, "exe")) {
        let raw = target.display().to_string();
        if let Some(stripped) = raw.strip_suffix(" (deleted)") {
            info.exe_deleted = true;
            info.exe = Some(stripped.to_string());
        } else {
            info.exe = Some(raw);
        }
    }

    if let Ok(cwd) = fs::read_link(proc_path(pid, "cwd")) {
        info.cwd = Some(cwd.display().to_string());
    }

    // status: uid + rss + threads
    if let Ok(status) = fs::read_to_string(proc_path(pid, "status")) {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let mut it = rest.split_whitespace();
                if let Some(real) = it.next() {
                    info.uid = real.parse().unwrap_or(0);
                }
                if let Some(effective) = it.next() {
                    info.euid = effective.parse().unwrap_or(info.uid);
                }
            } else if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                info.rss_kb = kb;
            } else if let Some(rest) = line.strip_prefix("Threads:") {
                info.threads = rest.trim().parse().unwrap_or(1);
            }
        }
    }

    Some(info)
}

/// Parse `/proc/<pid>/stat`, handling comm values containing spaces/parens.
fn parse_stat(stat: &str) -> Option<(String, char, u32, u64)> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat[open + 1..close].to_string();
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // rest[0] = state (field 3), rest[1] = ppid (field 4), rest[19] = starttime
    let state = rest.first().and_then(|s| s.chars().next()).unwrap_or('?');
    let ppid = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let starttime = rest.get(19).and_then(|s| s.parse().ok()).unwrap_or(0);
    Some((name, state, ppid, starttime))
}

pub fn read_cmdline(pid: u32) -> Vec<String> {
    match fs::read(proc_path(pid, "cmdline")) {
        Ok(bytes) => bytes
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Join cmdline for pattern matching (falls back to the process name).
pub fn cmdline_string(info: &ProcInfo) -> String {
    if info.cmdline.is_empty() {
        info.name.clone()
    } else {
        info.cmdline.join(" ")
    }
}

/// Read `LD_PRELOAD` from the process environment, when readable.
pub fn read_ld_preload(pid: u32) -> Option<String> {
    let bytes = fs::read(proc_path(pid, "environ")).ok()?;
    for entry in bytes.split(|b| *b == 0) {
        if let Some(value) = entry.strip_prefix(b"LD_PRELOAD=") {
            return Some(String::from_utf8_lossy(value).to_string());
        }
    }
    None
}

/// Socket inodes owned by a process.
pub fn socket_inodes(pid: u32) -> Vec<u64> {
    let mut inodes = Vec::new();
    if let Ok(entries) = fs::read_dir(proc_path(pid, "fd")) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let s = target.display().to_string();
                if let Some(rest) = s.strip_prefix("socket:[") {
                    if let Some(num) = rest.strip_suffix(']') {
                        if let Ok(inode) = num.parse::<u64>() {
                            inodes.push(inode);
                        }
                    }
                }
            }
        }
    }
    inodes
}

/// Map socket inode -> remote endpoint string, from `/proc/net/tcp{,6}`.
pub fn tcp_remotes() -> HashMap<u64, String> {
    let mut map = HashMap::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(content) = fs::read_to_string(file) else {
            continue;
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let remote = decode_addr(fields[2]);
            let state = decode_state(fields[3]);
            let inode = fields[9].parse::<u64>().unwrap_or(0);
            if inode != 0 {
                map.insert(inode, format!("{remote} ({state})"));
            }
        }
    }
    map
}

/// Remote endpoints for one pid.
pub fn remote_endpoints(pid: u32) -> Vec<String> {
    let inodes = socket_inodes(pid);
    if inodes.is_empty() {
        return Vec::new();
    }
    let remotes = tcp_remotes();
    inodes
        .iter()
        .filter_map(|inode| remotes.get(inode).cloned())
        .collect()
}

fn decode_addr(hex: &str) -> String {
    let Some((addr, port_hex)) = hex.split_once(':') else {
        return hex.to_string();
    };
    let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
    match addr.len() {
        8 => {
            // IPv4, little endian hex
            let mut octets = [0u8; 4];
            for i in 0..4 {
                octets[i] = u8::from_str_radix(&addr[i * 2..i * 2 + 2], 16).unwrap_or(0);
            }
            format!(
                "{}.{}.{}.{}:{}",
                octets[3], octets[2], octets[1], octets[0], port
            )
        }
        32 => {
            // IPv6: four little-endian u32 groups
            let mut groups = Vec::new();
            for chunk in addr.as_bytes().chunks(8) {
                let s = std::str::from_utf8(chunk).unwrap_or("00000000");
                let mut bytes = [0u8; 4];
                for i in 0..4 {
                    bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0);
                }
                groups.push(format!("{:04x}", u32::from_le_bytes(bytes)));
            }
            format!("[{}]:{}", groups.join(":"), port)
        }
        _ => hex.to_string(),
    }
}

fn decode_state(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// All visible processes (score fields untouched).
pub fn list_processes() -> Vec<ProcInfo> {
    list_pids().into_iter().filter_map(read_proc).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_our_own_process() {
        let pid = std::process::id();
        let info = read_proc(pid).expect("own process must be visible");
        assert_eq!(info.pid, pid);
        assert!(!info.name.is_empty());
        assert!(info.exe.is_some());
        assert_eq!(info.euid, zs_core::util::euid());
    }

    #[test]
    fn lists_processes() {
        let all = list_processes();
        assert!(all.iter().any(|p| p.pid == std::process::id()));
    }

    #[test]
    fn decodes_ipv4() {
        // 127.0.0.1:80 -> 0100007F:0050
        assert_eq!(decode_addr("0100007F:0050"), "127.0.0.1:80");
    }

    #[test]
    fn decodes_ipv6() {
        // ::1:80 -> 0000...0001:0050
        assert_eq!(
            decode_addr("00000000000000000000000001000000:0050"),
            "[0000:0000:0000:0001]:80"
        );
    }
}
