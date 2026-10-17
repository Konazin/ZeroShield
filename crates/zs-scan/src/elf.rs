//! ELF heuristics: static analysis of Linux binaries.
//!
//! These checks intentionally favour *explanations* over magic: every
//! detection carries a name, a description and a score so the user can judge
//! false positives.

use std::path::Path;

use goblin::elf::Elf;
use zs_core::model::Detection;

// Program header types / flags (defined locally to avoid version churn).
const PT_LOAD: u32 = 0x1;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;
const SHT_PROGBITS: u32 = 0x1;

/// Strings that, found inside a binary, deserve attention (low score each,
/// capped, so a single match never triggers a verdict by itself).
const SUSPICIOUS_MARKERS: &[&str] = &[
    "/dev/shm/",
    "memfd_create",
    "ptrace",
    "LD_PRELOAD",
    "/etc/ld.so.preload",
    "base64 -d",
    "wget http",
    "curl http",
    "nc -e ",
    "bash -i",
    "/dev/tcp/",
    ".onion",
    "crontab -",
    "history -c",
];

const MINING_MARKERS: &[&str] = &["xmrig", "stratum+tcp://", "stratum+ssl://"];

/// True when the buffer starts with the ELF magic.
pub fn is_elf(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] == 0x7f && &buf[1..4] == b"ELF"
}

fn det(name: &str, description: impl Into<String>, score: u32, tags: &[&str]) -> Detection {
    let mut d = Detection::new("elf-heuristic", format!("elf/{name}"), description, score);
    d.tags = tags.iter().map(|s| s.to_string()).collect();
    d
}

/// Shannon entropy (bits per byte) of a buffer.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Analyse an ELF buffer. Not an ELF (or unparsable) yields an empty vec.
pub fn analyze(buf: &[u8], path: &Path) -> Vec<Detection> {
    let elf = match Elf::parse(buf) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!("cannot parse ELF {}: {e}", path.display());
            return Vec::new();
        }
    };
    let mut out = Vec::new();

    // 1. Entrypoint outside any executable load segment.
    let entry = elf.entry;
    let entry_mapped = elf.program_headers.iter().any(|ph| {
        ph.p_type == PT_LOAD
            && ph.p_flags & PF_X != 0
            && entry >= ph.p_vaddr
            && entry < ph.p_vaddr.saturating_add(ph.p_filesz.max(1))
    });
    if !entry_mapped && entry != 0 {
        out.push(det(
            "entrypoint_unmapped",
            format!("entrypoint {entry:#x} is outside every executable segment"),
            55,
            &["elf", "packing"],
        ));
    }

    // 2. Writable + executable load segment (classic self-modifying/packed).
    let has_rwx = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_LOAD && ph.p_flags & PF_W != 0 && ph.p_flags & PF_X != 0);
    if has_rwx {
        out.push(det(
            "rwx_segment",
            "has a writable+executable LOAD segment (self-modifying code or packer)",
            70,
            &["elf", "packing", "memory"],
        ));
    }

    // 3. Executable stack.
    let exec_stack = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_STACK && ph.p_flags & PF_X != 0 && ph.p_flags & PF_R != 0);
    if exec_stack {
        out.push(det(
            "exec_stack",
            "requests an executable stack (PT_GNU_STACK with X)",
            45,
            &["elf", "memory"],
        ));
    }

    // 4. High entropy sections (packing/encryption).
    let mut packed_section: Option<(&str, f64)> = None;
    for sh in &elf.section_headers {
        if sh.sh_type != SHT_PROGBITS || sh.sh_size < 64 * 1024 {
            continue;
        }
        let start = sh.sh_offset as usize;
        // Hostile ELF headers can carry offsets/sizes that overflow on
        // addition; saturate so a crafted file can never panic the scanner.
        let end = start.saturating_add(sh.sh_size as usize).min(buf.len());
        if end <= start {
            continue;
        }
        let e = entropy(&buf[start..end]);
        if e > 7.2 {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
            if packed_section.map(|(_, prev)| e > prev).unwrap_or(true) {
                packed_section = Some((name, e));
            }
        }
    }
    if let Some((name, e)) = packed_section {
        out.push(det(
            "high_entropy_section",
            format!("section '{name}' has entropy {e:.2}/8.00 (packed or encrypted content)"),
            45,
            &["elf", "packing"],
        ));
    }

    // 5. UPX packing.
    let upx_name = elf
        .section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name))
        .any(|n| n.contains("UPX"));
    if upx_name || contains(buf, b"UPX!") {
        out.push(det(
            "upx_packed",
            "binary looks UPX-packed",
            55,
            &["elf", "packing"],
        ));
    }

    // 6. Suspicious interpreter path (very rare outside /lib, /usr).
    if let Some(interp) = elf.interpreter {
        if !interp.starts_with("/lib") && !interp.starts_with("/usr") {
            out.push(det(
                "unusual_interpreter",
                format!("unusual ELF interpreter '{interp}'"),
                40,
                &["elf"],
            ));
        }
    }

    // 7. Suspicious RUNPATH/RPATH locations.
    for rp in elf.runpaths.iter().chain(elf.rpaths.iter()) {
        if rp.contains("/tmp/") || rp.contains("/dev/shm") {
            out.push(det(
                "suspicious_runpath",
                format!("library search path points at a world-writable place: {rp}"),
                35,
                &["elf", "hijack"],
            ));
            break;
        }
    }

    // 8. Suspicious strings (capped).
    let mut hits: Vec<&str> = Vec::new();
    for marker in SUSPICIOUS_MARKERS {
        if contains(buf, marker.as_bytes()) {
            hits.push(marker);
        }
    }
    if !hits.is_empty() {
        let shown: Vec<&str> = hits.iter().take(6).copied().collect();
        let score = ((hits.len() as u32) * 6).min(40);
        out.push(det(
            "suspicious_strings",
            format!("suspicious strings found: {}", shown.join(", ")),
            score,
            &["elf", "strings"],
        ));
    }

    // 9. Mining markers are strong on their own.
    let mining: Vec<&str> = MINING_MARKERS
        .iter()
        .copied()
        .filter(|m| contains(buf, m.as_bytes()))
        .collect();
    if !mining.is_empty() {
        out.push(det(
            "mining_markers",
            format!("cryptomining markers found: {}", mining.join(", ")),
            80,
            &["elf", "miner"],
        ));
    }

    out
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

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> &'static Path {
        Path::new("test")
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[0; 1024]), 0.0);
        let random: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!((entropy(&random) - 8.0).abs() < 0.001);
    }

    #[test]
    fn detects_non_elf() {
        assert!(!is_elf(b"hello"));
        assert!(analyze(b"not an elf", p()).is_empty());
    }

    #[test]
    fn analyzes_host_binary() {
        // Use a stock system binary: the cargo test harness itself embeds the
        // marker strings defined in this very file, which causes false positives.
        let candidate = ["/bin/ls", "/usr/bin/env", "/bin/sh"]
            .iter()
            .map(Path::new)
            .find(|p| p.exists());
        let Some(exe) = candidate else {
            eprintln!("skipping: no host ELF binary found");
            return;
        };
        let buf = std::fs::read(exe).unwrap();
        assert!(is_elf(&buf));
        let dets = analyze(&buf, exe);
        // Heuristics should not declare a stock system binary malicious:
        // no mining markers and no RWX segments.
        assert!(!dets.iter().any(|d| d.name == "elf/mining_markers"));
        assert!(!dets.iter().any(|d| d.name == "elf/rwx_segment"));
    }

    #[test]
    fn flags_rwx_and_mining_in_fake_elf() {
        // Build a minimal but valid ELF64 header with one RWX PT_LOAD.
        let mut buf = vec![0u8; 0x40 + 0x38];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little endian
        buf[6] = 1; // version
        buf[16] = 2; // e_type = ET_EXEC
        buf[18] = 0x3e; // x86-64
        buf[20] = 1; // e_version
        buf[24] = 0x40; // e_entry
        buf[32] = 0x40; // e_phoff
        buf[54] = 0x38; // e_phentsize
        buf[56] = 1; // e_phnum
                     // program header at 0x40: PT_LOAD, RWX, vaddr 0x400000 filesz 0x100
        buf[0x40] = 1; // p_type
        buf[0x44] = PF_R as u8 | PF_W as u8 | PF_X as u8; // p_flags
        buf[0x48] = 0; // p_offset
        buf[0x50] = 0x00; // p_vaddr
        buf[0x58] = 0x00; // p_paddr
        buf[0x60] = 0x00;
        // memsz/filesz bytes: 0x100 at offsets 0x68/0x68
        buf[0x68] = 0x00;
        buf[0x6a] = 0x01;
        let dets = analyze(&buf, p());
        assert!(dets.iter().any(|d| d.name == "elf/rwx_segment"), "{dets:?}");
    }

    #[test]
    fn section_headers_with_wild_offsets_do_not_panic() {
        // Sections whose offset+size overflow `usize` must be skipped, not
        // crash the scanner (debug builds panic on overflow).
        let mut buf = vec![0u8; 0x200];
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little endian
        buf[6] = 1; // version
        buf[16] = 2; // e_type = ET_EXEC
        buf[18] = 0x3e; // x86-64
        buf[20] = 1; // e_version
        buf[24] = 0x40; // e_entry
        buf[41] = 0x01; // e_shoff = 0x100
        buf[52] = 0x40; // e_ehsize = 64
        buf[58] = 0x40; // e_shentsize = 64
        buf[60] = 2; // e_shnum = 2 (null + one PROGBITS)
                     // Section header at 0x100 with a hostile offset.
        buf[0x104] = 1; // sh_type = SHT_PROGBITS
        buf[0x118..0x120].fill(0xff); // sh_offset = u64::MAX
        buf[0x122] = 0x01; // sh_size = 0x10000 (>= 64 KiB)
        let dets = analyze(&buf, p());
        assert!(!dets.iter().any(|d| d.name == "elf/high_entropy_section"));
    }
}
