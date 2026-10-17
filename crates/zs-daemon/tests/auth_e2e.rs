//! End-to-end authorization test (M9-C).
//!
//! Starts the real `zeroshieldd` binary and drives it with the real CLI
//! running as `nobody` (uid 65534, via `setpriv`), so the
//! `SO_PEERCRED`-based authorization is exercised end to end — including
//! the polkit path (fake `pkcheck`-compatible helpers) and the
//! `/proc/<pid>` identity check.
//!
//! Requires root plus `setpriv`/`timeout`/`sh`; without them (or without
//! the CLI binary built alongside the daemon) the test skips with a
//! message. CI containers run as root, so this runs there; typical
//! developer machines skip.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// uid/gid of `nobody`, the unprivileged client used here.
const NOBODY: u32 = 65534;

fn is_root() -> bool {
    // SAFETY: geteuid is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

/// The `zeroshield` CLI, built next to the test binary by Cargo
/// (`target/debug/zeroshield`; `cargo test --workspace` builds it).
fn cli_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let candidate = exe.parent()?.parent()?.join("zeroshield");
    candidate.is_file().then_some(candidate)
}

fn skip_reason() -> Option<String> {
    if !is_root() {
        return Some("not root: cannot run a client with a different uid".into());
    }
    if cli_binary().is_none() {
        return Some("CLI binary not built next to the tests (run the workspace suite)".into());
    }
    for tool in ["setpriv", "timeout", "env"] {
        let ok = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return Some(format!("{tool} not available"));
        }
    }
    None
}

struct Daemon {
    child: Child,
    /// Kept alive for the whole test: hosts config, socket, logs, the CLI
    /// copy and the client home.
    dir: tempfile::TempDir,
    sock: PathBuf,
    log: PathBuf,
}

impl Daemon {
    /// Start a daemon on a fresh, world-traversable tempdir so the
    /// unprivileged client can reach the socket and exec the CLI copy.
    fn start(config_extra: &str) -> Daemon {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let extra = config_extra.replace("$DIR", &dir.path().display().to_string());
        let sock = dir.path().join("zeroshieldd.sock");
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let cfg = dir.path().join("config.toml");
        write!(
            std::fs::File::create(&cfg).unwrap(),
            "[general]\n\
             log_level = \"info\"\n\
             \n\
             [procmon]\n\
             enabled = false\n\
             \n\
             [netguard]\n\
             enabled = false\n\
             \n\
             [daemon]\n\
             socket_mode = \"0666\"\n\
             {extra}\n"
        )
        .unwrap();
        let log = dir.path().join("daemon.log");
        let child = Command::new(env!("CARGO_BIN_EXE_zeroshieldd"))
            .env("ZS_CONFIG", &cfg)
            .env("ZS_DATA_DIR", &data)
            .env("ZS_SOCKET", &sock)
            .stdin(Stdio::null())
            .stdout(Stdio::from(std::fs::File::create(&log).unwrap()))
            .stderr(Stdio::from(
                std::fs::File::create(dir.path().join("daemon.err")).unwrap(),
            ))
            .spawn()
            .expect("spawn zeroshieldd");

        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && !sock.exists() {
            std::thread::sleep(Duration::from_millis(100));
        }
        if !sock.exists() {
            let log = std::fs::read_to_string(&log).unwrap_or_default();
            panic!("daemon did not create {}; log:\n{log}", sock.display());
        }
        Daemon {
            child,
            dir,
            sock,
            log,
        }
    }

    /// Drop an executable helper script into this daemon's directory.
    fn helper(&self, name: &str, body: &str) {
        let path = self.dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Copy the CLI into the (world-traversable) test directory and create
    /// a writable HOME for the unprivileged client.
    fn prepare_client(&self) -> PathBuf {
        let cli = self.dir.path().join("zeroshield");
        std::fs::copy(cli_binary().expect("CLI present"), &cli).unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = self.dir.path().join("client-home");
        for sub in ["", "run", ".cache", ".config", ".local/share"] {
            let p = home.join(sub);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o777)).unwrap();
        }
        home
    }

    /// Run the real CLI as `nobody` against this daemon.
    fn cli_as_nobody(&self, cli: &Path, home: &Path, args: &[&str]) -> Output {
        let out = Command::new("timeout")
            .arg("30")
            .arg("setpriv")
            .arg(format!("--reuid={NOBODY}"))
            .arg(format!("--regid={NOBODY}"))
            .arg("--clear-groups")
            .arg("env")
            .arg(format!("HOME={}", home.display()))
            .arg(format!("XDG_RUNTIME_DIR={}/run", home.display()))
            .arg(format!("XDG_CACHE_HOME={}/.cache", home.display()))
            .arg(format!("XDG_CONFIG_HOME={}/.config", home.display()))
            .arg(format!("XDG_DATA_HOME={}/.local/share", home.display()))
            .arg(format!("ZS_SOCKET={}", self.sock.display()))
            .arg(cli)
            .args(args)
            .output()
            .expect("run CLI as nobody");
        if out.stdout.is_empty() && out.stderr.is_empty() {
            let log = std::fs::read_to_string(&self.log).unwrap_or_default();
            panic!(
                "client produced nothing (status {:?})\ndaemon log:\n{log}",
                out.status
            );
        }
        out
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn unprivileged_client_authorization_end_to_end() {
    if let Some(reason) = skip_reason() {
        eprintln!("skipping auth E2E: {reason}");
        return;
    }

    // 1. Untrusted uid, polkit disabled: denied, message points at the list
    //    and the daemon logs the denial with uid + method.
    let d = Daemon::start("client_uids = []\npolkit_enabled = false");
    let cli = d.prepare_client();
    let home = d.dir.path().join("client-home");
    let out = d.cli_as_nobody(&cli, &home, &["--json", "status"]);
    assert!(!out.status.success(), "untrusted client must fail");
    let err = stderr(&out);
    assert!(err.contains("denied"), "{err}");
    assert!(err.contains(&NOBODY.to_string()), "{err}");
    assert!(err.contains("polkit is disabled"), "{err}");
    let log = d.log();
    assert!(log.contains("request denied"), "{log}");
    assert!(log.contains("uid=65534"), "{log}");
    drop(d);

    // 2. Same client listed in client_uids: authorized (the kernel uid
    //    decides, no client-supplied identity involved).
    let d = Daemon::start("client_uids = [65534]\npolkit_enabled = false");
    let cli = d.prepare_client();
    let out = d.cli_as_nobody(
        &cli,
        &d.dir.path().join("client-home"),
        &["--json", "status"],
    );
    assert!(
        out.status.success(),
        "listed uid must be authorized: {}",
        stderr(&out)
    );
    assert!(stdout(&out).contains("version"), "{}", stdout(&out));
    drop(d);

    // 3. Polkit path (fake allow helper): the /proc identity check passes
    //    and the helper authorizes the request.
    let d = Daemon::start(
        "client_uids = []\npolkit_enabled = true\npolkit_helper = \"$DIR/fake-pkcheck\"",
    );
    d.helper("fake-pkcheck", "#!/bin/sh\nexit 0\n");
    let cli = d.prepare_client();
    let out = d.cli_as_nobody(
        &cli,
        &d.dir.path().join("client-home"),
        &["--json", "status"],
    );
    assert!(
        out.status.success(),
        "polkit allow must authorize: {}",
        stderr(&out)
    );
    assert!(d.log().contains("polkit authorized"), "{}", d.log());
    drop(d);

    // 4. Polkit path (fake deny helper): refused with the polkit reason.
    let d = Daemon::start(
        "client_uids = []\npolkit_enabled = true\npolkit_helper = \"$DIR/fake-pkcheck\"",
    );
    d.helper("fake-pkcheck", "#!/bin/sh\nexit 1\n");
    let cli = d.prepare_client();
    let out = d.cli_as_nobody(
        &cli,
        &d.dir.path().join("client-home"),
        &["--json", "status"],
    );
    assert!(!out.status.success(), "polkit deny must refuse");
    assert!(
        stderr(&out).contains("did not authorize"),
        "{}",
        stderr(&out)
    );
}
