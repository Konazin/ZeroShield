//! Deterministic mini-fuzzer (stable Rust).
//!
//! A cheap regression net for parser robustness: rules, signature imports and
//! ELF heuristics must never panic on random or mutated input. Deep,
//! coverage-guided runs live in `fuzz/` (cargo-fuzz, scheduled CI job).

use std::path::Path;

use zs_core::storage::Storage;
use zs_scan::elf;
use zs_scan::rules::RuleSet;
use zs_scan::signatures::{import_text, SigFormat};

/// Tiny xorshift64 PRNG so runs are reproducible.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn random_bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.below(max_len + 1);
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }

    fn random_text(&mut self, max_len: usize) -> String {
        String::from_utf8_lossy(&self.random_bytes(max_len)).into_owned()
    }
}

fn mutate_bytes(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let ops = 1 + rng.below(8);
    for _ in 0..ops {
        if bytes.is_empty() {
            bytes.push(b'x');
            continue;
        }
        let i = rng.below(bytes.len());
        match rng.below(4) {
            0 => bytes[i] = (rng.next() & 0xff) as u8,
            1 => {
                bytes.remove(i);
            }
            2 => bytes.insert(i, (rng.next() & 0xff) as u8),
            _ => bytes.truncate(i),
        }
    }
    bytes
}

const RULE_CORPUS: &[&str] = &[
    r#"
[[rule]]
name = "test/text"
description = "text rule"
severity = "high"
score = 70
pattern = "/dev/tcp/"
pattern_kind = "text"
"#,
    r#"
[[rule]]
name = "test/hex"
description = "hex rule"
severity = "medium"
score = 50
pattern = "48 31 ?? c3"
pattern_kind = "hex"
"#,
    r#"
[[rule]]
name = "test/all"
description = "all_of rule"
severity = "low"
score = 30
pattern = ["a", "b"]
pattern_kind = "all_of"
"#,
];

const SIG_CORPUS: &[&str] = &[
    "44d88612fea8a8f36de82e1278abb02f:68:Test.Sig\n",
    "3395856ce81f2b7382dee72602f798b642f14140 sha1-demo\n",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,demo,high,demo sig\n",
];

#[test]
fn rule_parsing_never_panics() {
    let mut rng = Rng::new(0xdead_beef_cafe_1234);
    for i in 0..2000 {
        let input = match i % 3 {
            0 => rng.random_text(1024),
            1 => String::from_utf8_lossy(&mutate_bytes(
                RULE_CORPUS[rng.below(RULE_CORPUS.len())].as_bytes(),
                &mut rng,
            ))
            .into_owned(),
            _ => "[".repeat(rng.below(256)),
        };
        let mut set = RuleSet::new();
        let _ = set.load_toml(&input, "fuzz");
    }
}

#[test]
fn signature_import_never_panics() {
    let storage = Storage::open_in_memory().unwrap();
    let mut rng = Rng::new(0x0dd1_5eed_0001_0002);
    for i in 0..2000 {
        let input = match i % 3 {
            0 => rng.random_text(512),
            1 => String::from_utf8_lossy(&mutate_bytes(
                SIG_CORPUS[rng.below(SIG_CORPUS.len())].as_bytes(),
                &mut rng,
            ))
            .into_owned(),
            _ => format!("{}\n", "f".repeat(rng.below(256))),
        };
        let _ = import_text(&storage, &input, "fuzz", SigFormat::PlainHashes);
        let _ = import_text(&storage, &input, "fuzz", SigFormat::ClamHdb);
        let _ = import_text(&storage, &input, "fuzz", SigFormat::ZeroShieldCsv);
    }
}

#[test]
fn elf_analysis_never_panics() {
    // Seed: minimal ELF64 header (magic + identity + a few header fields).
    let mut seed = vec![0u8; 0x80];
    seed[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    seed[4] = 2; // 64-bit
    seed[5] = 1; // little endian
    seed[6] = 1; // version
    seed[16] = 2; // ET_EXEC
    seed[18] = 0x3e; // x86-64
    seed[20] = 1; // e_version
    seed[24] = 0x40; // e_entry
    seed[32] = 0x40; // e_phoff
    seed[40] = 0x40; // e_shoff
    seed[52] = 0x40; // e_ehsize
    seed[54] = 0x38; // e_phentsize
    seed[56] = 1; // e_phnum
    seed[58] = 0x40; // e_shentsize
    seed[60] = 1; // e_shnum

    let mut rng = Rng::new(0x3f1f_0000_0000_0001);
    for i in 0..2000 {
        let bytes = if i % 3 == 0 {
            rng.random_bytes(2048)
        } else {
            mutate_bytes(&seed, &mut rng)
        };
        let _ = elf::analyze(&bytes, Path::new("fuzz"));
    }
}
