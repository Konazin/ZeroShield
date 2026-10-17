//! Client authentication/authorization for the daemon socket (M9-C).
//!
//! Identity is taken from `SO_PEERCRED` (captured by `zs-ipc` on every
//! accepted connection): the kernel reports the uid/gid/pid of the process
//! holding the other end of the socket, so clients cannot spoof it.
//!
//! Policy (fail-closed):
//!
//! * root and the daemon's own user are always trusted (this preserves the
//!   previous behavior: a system daemon answers root, a user daemon answers
//!   its user);
//! * `daemon.client_uids` / `daemon.client_gids` (primary or supplementary
//!   group) are trusted;
//! * everyone else is checked through polkit — `org.zeroshield.read` for
//!   read-only methods, `org.zeroshield.manage` for state-changing ones —
//!   when `daemon.polkit_enabled` and the client process can be verified;
//! * without polkit, without kernel credentials, or when the client process
//!   cannot be verified, the request is denied.
//!
//! The polkit subject is a `unix-process` (pid + start time + uid) built
//! from `/proc`, so pid reuse cannot be used to impersonate a process; the
//! same uid check gates supplementary-group trust.
//!
//! The check shells out to a `pkcheck`-compatible helper (no D-Bus
//! dependency — same approach as `gpgv` for feed signatures and `nft` for
//! the firewall).

use std::fs;
use std::process::Command;

use zs_core::error::{ZsError, ZsResult};
use zs_ipc::protocol::methods;
use zs_ipc::PeerCred;

/// polkit action for read-only requests (status, lists, reports).
pub const ACTION_READ: &str = "org.zeroshield.read";
/// polkit action for state-changing requests (quarantine, rules, network).
pub const ACTION_MANAGE: &str = "org.zeroshield.manage";

/// What a request may change. Used to pick the polkit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Manage,
}

impl Access {
    /// Classify an IPC method. Anything not explicitly listed as `Read` is
    /// `Manage`, so a newly added method fails closed until classified.
    pub fn of(method: &str) -> Access {
        use methods::*;
        match method {
            STATUS | MODULES | SCAN_RUN | PROC_LIST | PROC_AUDIT | QUARANTINE_LIST | RULES_LIST
            | EVENTS_LIST | FINDINGS_LIST | NET_STATUS | NET_AUDIT | WATCH_FS_LIST | REPORT_GET
            | METRICS_GET => Access::Read,
            _ => Access::Manage,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Effective uid of the daemon process (implicitly trusted).
    pub daemon_uid: u32,
    /// Extra UIDs with full access (no polkit prompt).
    pub client_uids: Vec<u32>,
    /// Extra GIDs with full access (primary or supplementary group).
    pub client_gids: Vec<u32>,
    /// Ask polkit for untrusted local users instead of denying outright.
    pub polkit_enabled: bool,
    /// `pkcheck`-compatible helper.
    pub polkit_helper: String,
    /// Pass `--allow-user-interaction` so an authentication agent can prompt.
    pub polkit_allow_interaction: bool,
}

#[derive(Debug)]
pub struct AuthPolicy {
    cfg: AuthConfig,
}

/// Details read from `/proc/<pid>` for a client process.
struct ProcInfo {
    /// Start time in clock ticks since boot (`/proc/<pid>/stat` field 22).
    start_time: Option<u64>,
    /// Primary + supplementary groups.
    groups: Vec<u32>,
}

impl AuthPolicy {
    pub fn new(cfg: AuthConfig) -> Self {
        Self { cfg }
    }

    /// One-line summary for the startup log.
    pub fn describe(&self) -> String {
        let mut uids = self.cfg.client_uids.clone();
        uids.sort_unstable();
        let mut gids = self.cfg.client_gids.clone();
        gids.sort_unstable();
        format!(
            "trusted uids: root, daemon ({}), {:?}; gids: {:?}; polkit: {}",
            self.cfg.daemon_uid,
            uids,
            gids,
            if self.cfg.polkit_enabled {
                format!(
                    "enabled via {}{}",
                    self.cfg.polkit_helper,
                    if self.cfg.polkit_allow_interaction {
                        ", interaction allowed"
                    } else {
                        ""
                    }
                )
            } else {
                "disabled".to_string()
            }
        )
    }

    /// Authorize a request. `Err` means the request must be refused.
    pub fn authorize(&self, cred: &PeerCred, method: &str) -> ZsResult<()> {
        if cred.uid == 0 || cred.uid == self.cfg.daemon_uid {
            return Ok(());
        }
        if self.cfg.client_uids.contains(&cred.uid) {
            return Ok(());
        }
        // Primary gid from SO_PEERCRED is race-free; supplementary groups
        // need /proc and are only trusted when the pid still belongs to the
        // same uid (see `proc_info`).
        let info = proc_info(cred.pid, cred.uid);
        if self.cfg.client_gids.contains(&cred.gid)
            || info
                .as_ref()
                .is_some_and(|i| i.groups.iter().any(|g| self.cfg.client_gids.contains(g)))
        {
            return Ok(());
        }
        if !self.cfg.polkit_enabled {
            return Err(ZsError::Permission(format!(
                "request '{method}' denied for uid {}: not in daemon.client_uids/client_gids \
                 and polkit is disabled",
                cred.uid
            )));
        }
        let Some(info) = info else {
            return Err(ZsError::Permission(format!(
                "request '{method}' denied for uid {}: cannot verify client process {} \
                 (exited or /proc unreadable)",
                cred.uid, cred.pid
            )));
        };
        let action = match Access::of(method) {
            Access::Read => ACTION_READ,
            Access::Manage => ACTION_MANAGE,
        };
        self.polkit_check(action, cred, info.start_time.unwrap_or(0))
            .map_err(|reason| {
                ZsError::Permission(format!(
                    "request '{method}' denied for uid {}: {reason}",
                    cred.uid
                ))
            })
    }

    fn polkit_check(&self, action: &str, cred: &PeerCred, start_time: u64) -> Result<(), String> {
        let helper = &self.cfg.polkit_helper;
        // PID[,START_TIME,UID]: polkit refuses to authorize when the pid was
        // recycled meanwhile (start time mismatch).
        let process = format!("{},{},{}", cred.pid, start_time, cred.uid);
        let mut cmd = Command::new(helper);
        cmd.arg("--action-id")
            .arg(action)
            .arg("--process")
            .arg(process);
        if self.cfg.polkit_allow_interaction {
            cmd.arg("--allow-user-interaction");
        }
        let output = cmd
            .output()
            .map_err(|e| format!("cannot run polkit helper {helper:?}: {e}"))?;
        match output.status.code() {
            Some(0) => {
                tracing::info!(
                    "polkit authorized '{action}' for pid {} (uid {})",
                    cred.pid,
                    cred.uid
                );
                Ok(())
            }
            Some(1) => Err(format!("polkit did not authorize '{action}'")),
            Some(2) => Err(format!(
                "polkit requires authentication for '{action}' \
                 (no agent available or user interaction disabled)"
            )),
            other => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let detail = stderr
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("no details");
                Err(format!(
                    "polkit check failed ({}): {detail}",
                    match other {
                        Some(code) => format!("exit {code}"),
                        None => "killed by signal".to_string(),
                    }
                ))
            }
        }
    }
}

/// Read `/proc/<pid>` details, refusing to return anything when the process
/// does not (or no longer) belong to `expect_uid`. That check makes pid
/// reuse — e.g. after the client passed its socket fd on and exited —
/// harmless: reused pids belong to a different process, not to the peer.
fn proc_info(pid: u32, expect_uid: u32) -> Option<ProcInfo> {
    if pid == 0 {
        return None;
    }
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    if !status_uid_matches(&status, expect_uid) {
        return None;
    }
    let groups = status_groups(&status);
    let start_time = fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            // `comm` (field 2) may contain spaces and parentheses; everything
            // after the last ')' starts at field 3 (`state`), so
            // `starttime` (field 22) sits at index 19.
            let rest = stat.rsplit_once(')')?.1.to_string();
            rest.split_whitespace().nth(19)?.parse().ok()
        });
    Some(ProcInfo { start_time, groups })
}

/// `Uid:` line: real, effective, saved, fs. A match on real or effective
/// covers the `SO_PEERCRED` value (which is the effective uid).
fn status_uid_matches(status: &str, expect_uid: u32) -> bool {
    let Some(rest) = status.lines().find_map(|l| l.strip_prefix("Uid:")) else {
        return false;
    };
    let mut ids = rest.split_whitespace();
    let real = ids.next().and_then(|v| v.parse::<u32>().ok());
    let effective = ids.next().and_then(|v| v.parse::<u32>().ok());
    real == Some(expect_uid) || effective == Some(expect_uid)
}

fn status_groups(status: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|rest| {
            rest.split_whitespace()
                .filter_map(|g| g.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn cred(uid: u32, gid: u32, pid: u32) -> PeerCred {
        PeerCred { uid, gid, pid }
    }

    fn base_cfg() -> AuthConfig {
        AuthConfig {
            daemon_uid: 4242,
            client_uids: vec![1000],
            client_gids: vec![984],
            polkit_enabled: false,
            polkit_helper: "pkcheck".into(),
            polkit_allow_interaction: false,
        }
    }

    #[test]
    fn access_classification() {
        assert_eq!(Access::of(methods::STATUS), Access::Read);
        assert_eq!(Access::of(methods::SCAN_RUN), Access::Read);
        assert_eq!(Access::of(methods::EVENTS_LIST), Access::Read);
        assert_eq!(Access::of(methods::QUARANTINE_RESTORE), Access::Manage);
        assert_eq!(Access::of(methods::NET_APPLY), Access::Manage);
        assert_eq!(Access::of(methods::SHUTDOWN), Access::Manage);
        // Unknown/future methods fail closed.
        assert_eq!(Access::of("whatever.new"), Access::Manage);
    }

    #[test]
    fn trusts_root_daemon_uid_and_lists() {
        let policy = AuthPolicy::new(base_cfg());
        assert!(policy.authorize(&cred(0, 7, 123), methods::STATUS).is_ok());
        assert!(policy
            .authorize(&cred(4242, 7, 123), methods::STATUS)
            .is_ok());
        assert!(policy
            .authorize(&cred(1000, 7, 123), methods::QUARANTINE_PURGE)
            .is_ok());
        // Trusted by primary gid.
        assert!(policy
            .authorize(&cred(2000, 984, 123), methods::NET_APPLY)
            .is_ok());
    }

    #[test]
    fn denies_untrusted_when_polkit_disabled() {
        let policy = AuthPolicy::new(base_cfg());
        let err = policy
            .authorize(&cred(2000, 7, 123), methods::STATUS)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("denied"), "{msg}");
        assert!(msg.contains("client_uids"), "{msg}");
        assert!(msg.contains("polkit is disabled"), "{msg}");
    }

    #[test]
    fn denies_untrusted_without_verifiable_process() {
        let mut cfg = base_cfg();
        cfg.polkit_enabled = true;
        let policy = AuthPolicy::new(cfg);
        // pid 0: no credentials at all.
        let msg = policy
            .authorize(&cred(2000, 7, 0), methods::STATUS)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("cannot verify client process"), "{msg}");
        // Dead pid: /proc entry gone.
        let msg = policy
            .authorize(&cred(2000, 7, 4_000_000_000), methods::STATUS)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("cannot verify client process"), "{msg}");
    }

    #[test]
    fn describe_mentions_everything() {
        let text = AuthPolicy::new(base_cfg()).describe();
        assert!(text.contains("4242"), "{text}");
        assert!(text.contains("[1000]"), "{text}");
        assert!(text.contains("[984]"), "{text}");
        assert!(text.contains("disabled"), "{text}");
    }

    #[test]
    fn proc_parsers_reject_garbage() {
        assert!(status_uid_matches("Uid:\t1000\t1000\t1000\t1000\n", 1000));
        assert!(status_uid_matches("Uid:\t1000\t2000\t1000\t1000\n", 2000));
        assert!(!status_uid_matches("Uid:\t1000\t1000\t1000\t1000\n", 1));
        assert!(!status_uid_matches("Uid:\tgarbage\n", 0));
        assert!(!status_uid_matches("no uid line\n", 0));
        assert_eq!(
            status_groups("Groups:\t1000 984 27\nName:\tx\n"),
            vec![1000, 984, 27]
        );
        assert_eq!(status_groups("Name:\tx\n"), Vec::<u32>::new());
    }

    #[test]
    fn proc_info_matches_own_process() {
        let info = proc_info(std::process::id(), zs_core::util::euid())
            .expect("test process must be inspectable");
        assert!(info.start_time.is_some_and(|t| t > 0));
        assert!(
            info.groups.contains(&zs_core::util::egid()),
            "own primary gid must be listed in Groups:"
        );
    }

    #[test]
    fn proc_info_rejects_uid_mismatch() {
        let other_uid = zs_core::util::euid() ^ 1;
        assert!(
            proc_info(std::process::id(), other_uid).is_none(),
            "a foreign uid must not be able to reuse this pid's /proc data"
        );
    }

    // ----- polkit-path tests ------------------------------------------------
    //
    // These exercise a live client process (the test binary itself) so the
    // /proc identity check passes; they cannot run as root because uid 0 is
    // implicitly trusted.

    fn fake_helper(dir: &Path, exit_code: i32, log: Option<&Path>) -> PathBuf {
        let path = dir.join("fake-pkcheck");
        let mut body = String::from("#!/bin/sh\n");
        if let Some(log) = log {
            body.push_str(&format!("echo \"$@\" >> '{}'\n", log.display()));
        }
        if exit_code == 127 {
            body.push_str(
                "echo 'GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: \
                 Action org.zeroshield.read is not registered' >&2\n",
            );
        }
        body.push_str(&format!("exit {exit_code}\n"));
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// Policy for which the *current* test process is an untrusted user.
    fn untrusted_policy(helper: &Path, interaction: bool) -> AuthPolicy {
        AuthPolicy::new(AuthConfig {
            daemon_uid: zs_core::util::euid().wrapping_add(1),
            client_uids: Vec::new(),
            client_gids: Vec::new(),
            polkit_enabled: true,
            polkit_helper: helper.display().to_string(),
            polkit_allow_interaction: interaction,
        })
    }

    fn own_cred() -> PeerCred {
        cred(
            zs_core::util::euid(),
            zs_core::util::egid(),
            std::process::id(),
        )
    }

    fn skip_if_root(test: &str) -> bool {
        if zs_core::util::euid() == 0 {
            eprintln!("running as root: {test} cannot exercise untrusted clients");
            return true;
        }
        false
    }

    #[test]
    fn polkit_grants_when_helper_succeeds() {
        if skip_if_root("polkit_grants_when_helper_succeeds") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path(), 0, None);
        let policy = untrusted_policy(&helper, false);
        policy.authorize(&own_cred(), methods::STATUS).unwrap();
    }

    #[test]
    fn polkit_denies_when_helper_fails() {
        if skip_if_root("polkit_denies_when_helper_fails") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path(), 1, None);
        let policy = untrusted_policy(&helper, false);
        let msg = policy
            .authorize(&own_cred(), methods::STATUS)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("did not authorize"), "{msg}");
    }

    #[test]
    fn polkit_challenge_reports_authentication_required() {
        if skip_if_root("polkit_challenge_reports_authentication_required") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path(), 2, None);
        let policy = untrusted_policy(&helper, false);
        let msg = policy
            .authorize(&own_cred(), methods::NET_APPLY)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("requires authentication"), "{msg}");
    }

    #[test]
    fn polkit_error_reports_stderr_detail() {
        if skip_if_root("polkit_error_reports_stderr_detail") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path(), 127, None);
        let policy = untrusted_policy(&helper, false);
        let msg = policy
            .authorize(&own_cred(), methods::STATUS)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("exit 127"), "{msg}");
        assert!(msg.contains("is not registered"), "{msg}");
    }

    #[test]
    fn polkit_missing_helper_is_denied() {
        if skip_if_root("polkit_missing_helper_is_denied") {
            return;
        }
        let policy = untrusted_policy(Path::new("/nonexistent/pkcheck"), false);
        let msg = policy
            .authorize(&own_cred(), methods::STATUS)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("cannot run polkit helper"), "{msg}");
    }

    #[test]
    fn polkit_argv_carries_action_process_and_uid() {
        if skip_if_root("polkit_argv_carries_action_process_and_uid") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("args.log");
        let helper = fake_helper(dir.path(), 0, Some(&log));
        let policy = untrusted_policy(&helper, true);
        policy.authorize(&own_cred(), methods::NET_APPLY).unwrap();

        let logged = fs::read_to_string(&log).unwrap();
        let args: Vec<&str> = logged.split_whitespace().collect();
        assert!(
            args.contains(&ACTION_MANAGE),
            "manage action expected: {logged}"
        );
        assert!(
            args.contains(&"--allow-user-interaction"),
            "interaction flag expected: {logged}"
        );
        let pos = args.iter().position(|a| *a == "--process").unwrap();
        let subject: Vec<&str> = args[pos + 1].split(',').collect();
        assert_eq!(subject.len(), 3, "PID,START_TIME,UID expected: {logged}");
        assert_eq!(subject[0], std::process::id().to_string());
        assert!(
            subject[1].parse::<u64>().unwrap() > 0,
            "start time: {logged}"
        );
        assert_eq!(subject[2], zs_core::util::euid().to_string());
    }
}
