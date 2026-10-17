//! Deterministic mini-fuzzer (stable Rust).
//!
//! A cheap regression net for config parsing: random and mutated TOML must
//! never panic. Deep, coverage-guided runs live in `fuzz/` (cargo-fuzz,
//! scheduled CI job).

use zs_core::config::Config;

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
}

fn mutate(s: &str, rng: &mut Rng) -> String {
    let mut bytes = s.as_bytes().to_vec();
    let ops = 1 + rng.below(8);
    for _ in 0..ops {
        if bytes.is_empty() {
            bytes.push(b'x');
            continue;
        }
        let i = rng.below(bytes.len());
        match rng.below(4) {
            0 => bytes[i] = (rng.next() & 0x7f) as u8,
            1 => {
                bytes.remove(i);
            }
            2 => bytes.insert(i, b"[]\"=.#\n "[rng.below(8)]),
            _ => bytes.truncate(i),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn config_parsing_never_panics() {
    const CORPUS: &[&str] = &[
        "scanner = { max_file_size = 1024, min_report_score = 30 }\n",
        "[netguard]\nenabled = true\nmode = \"audit\"\nfeed_urls = [\"https://a/b\"]\n",
        "[procmon]\ninterval_ms = 1000\nalert_score = 60\n",
        "[storage]\npath = \"/tmp/x.db\"\n",
        "unknown_key = 1\n",
    ];

    let mut rng = Rng::new(0xc0ff_ee00_1234_5678);
    for i in 0..3000 {
        let input = match i % 3 {
            0 => String::from_utf8_lossy(&rng.random_bytes(1024)).into_owned(),
            1 => mutate(CORPUS[rng.below(CORPUS.len())], &mut rng),
            _ => format!("[{}]\n", "a.".repeat(rng.below(128))),
        };
        let _ = Config::parse_toml(&input);
    }
}
