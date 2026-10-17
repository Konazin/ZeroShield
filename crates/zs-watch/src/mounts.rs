//! Detection of newly mounted removable media.
//!
//! Rather than depending on udev/udisks, the daemon polls `/proc/mounts` and
//! compares the set of interesting mount points between polls. A mount is
//! interesting when it sits below one of the configured roots (usually
//! `/media`, `/run/media` and `/mnt`), is backed by a block device
//! (`/dev/...`) and is not one of the kernel's virtual filesystems.

use std::collections::HashSet;
use std::path::PathBuf;

/// One interesting mount entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub device: String,
    pub mountpoint: PathBuf,
    pub fstype: String,
}

/// Filesystems that never carry removable user data worth scanning.
const IGNORED_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "pstore",
    "securityfs",
    "debugfs",
    "tracefs",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "binfmt_misc",
    "autofs",
    "ramfs",
    "efivarfs",
    "bpf",
    "nsfs",
    "squashfs",
    "overlay",
    "fuse.portal",
];

/// Decode the octal escapes used in `/proc/mounts` fields
/// (`\040` space, `\011` tab, `\012` newline, `\134` backslash).
pub fn unescape_field(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            if let Ok(octal) = std::str::from_utf8(&bytes[i + 1..i + 4]) {
                if let Ok(v) = u8::from_str_radix(octal, 8) {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse the content of `/proc/mounts` and return the interesting mounts.
pub fn parse_mounts(text: &str, roots: &[PathBuf]) -> Vec<MountInfo> {
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(device), Some(mountpoint), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if IGNORED_FS.contains(&fstype) {
            continue;
        }
        if !device.starts_with("/dev/") {
            continue;
        }
        let mountpoint = PathBuf::from(unescape_field(mountpoint));
        if !roots.iter().any(|root| mountpoint.starts_with(root)) {
            continue;
        }
        if !seen.insert(mountpoint.clone()) {
            continue;
        }
        out.push(MountInfo {
            device: unescape_field(device),
            mountpoint,
            fstype: fstype.to_string(),
        });
    }
    out
}

/// Tracks which interesting mounts are currently visible, so callers can act
/// on mounts that appear between polls.
pub struct MountWatcher {
    roots: Vec<PathBuf>,
    seen: HashSet<PathBuf>,
}

impl MountWatcher {
    pub fn new(roots: Vec<PathBuf>) -> Self {
        Self {
            roots,
            seen: HashSet::new(),
        }
    }

    /// Read `/proc/mounts` and return mounts that were not visible before.
    pub fn poll(&mut self) -> Vec<MountInfo> {
        match std::fs::read_to_string("/proc/mounts") {
            Ok(text) => self.poll_text(&text),
            Err(e) => {
                tracing::debug!("cannot read /proc/mounts: {e}");
                Vec::new()
            }
        }
    }

    /// Testable core of [`MountWatcher::poll`].
    pub fn poll_text(&mut self, text: &str) -> Vec<MountInfo> {
        let visible = parse_mounts(text, &self.roots);
        let current: HashSet<PathBuf> = visible.iter().map(|m| m.mountpoint.clone()).collect();
        let new: Vec<MountInfo> = visible
            .into_iter()
            .filter(|m| !self.seen.contains(&m.mountpoint))
            .collect();
        self.seen = current;
        new
    }

    /// Mark everything currently mounted as seen (no events on first call);
    /// returns the number of interesting mounts visible right now.
    pub fn prime(&mut self) -> usize {
        self.poll();
        self.seen.len()
    }

    /// Currently visible mounts (after the last poll).
    pub fn visible_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/media"),
            PathBuf::from("/run/media"),
            PathBuf::from("/mnt"),
        ]
    }

    #[test]
    fn parses_interesting_mounts_only() {
        let text = r#"
sysfs /sys sysfs rw,nosuid 0 0
tmpfs /media tmpfs rw 0 0
/dev/sda2 / ext4 rw 0 0
/dev/sdb1 /media/My\040USB vfat rw,nosuid 0 0
server:/export /mnt/nfs nfs4 rw 0 0
/dev/sdc1 /run/media/user/backup ext4 rw 0 0
/dev/sdd1 /mnt/cam exfat rw 0 0
/dev/loop0 /media/snap squashfs ro 0 0
"#;
        let mounts = parse_mounts(text, &roots());
        let points: Vec<String> = mounts
            .iter()
            .map(|m| m.mountpoint.display().to_string())
            .collect();
        assert_eq!(
            points,
            vec!["/media/My USB", "/run/media/user/backup", "/mnt/cam",]
        );
        // /mounts under "/" is not interesting.
        assert!(!points.contains(&"/".to_string()));
        // tmpfs on /media is filtered by filesystem type.
        assert_eq!(mounts[0].device, "/dev/sdb1");
        assert_eq!(mounts[0].fstype, "vfat");
    }

    #[test]
    fn unescapes_octal_fields() {
        assert_eq!(unescape_field("My\\040USB"), "My USB");
        assert_eq!(unescape_field("a\\134b"), "a\\b");
        assert_eq!(unescape_field("plain"), "plain");
        // Truncated escape stays as-is.
        assert_eq!(unescape_field("x\\04"), "x\\04");
    }

    #[test]
    fn watcher_reports_only_new_mounts() {
        let a = "/dev/sdb1 /media/usb vfat rw 0 0\n";
        let ab = "/dev/sdb1 /media/usb vfat rw 0 0\n/dev/sdc1 /mnt/disk ext4 rw 0 0\n";
        let b = "/dev/sdc1 /mnt/disk ext4 rw 0 0\n";

        let mut watcher = MountWatcher::new(roots());
        assert_eq!(watcher.poll_text(a).len(), 1); // first poll sees A
        assert_eq!(watcher.poll_text(ab).len(), 1); // B appears
        assert!(watcher.poll_text(ab).is_empty()); // nothing new
        assert!(watcher.poll_text(b).is_empty()); // A removed, B known
        assert_eq!(watcher.poll_text(ab).len(), 1); // A replugged
        assert_eq!(watcher.visible_count(), 2);
    }

    #[test]
    fn prime_marks_current_mounts_as_seen() {
        let mut watcher = MountWatcher::new(roots());
        assert_eq!(
            watcher
                .poll_text("/dev/sdb1 /media/usb vfat rw 0 0\n")
                .len(),
            1
        );
        assert_eq!(watcher.visible_count(), 1);
        assert!(watcher
            .poll_text("/dev/sdb1 /media/usb vfat rw 0 0\n")
            .is_empty());
    }
}
