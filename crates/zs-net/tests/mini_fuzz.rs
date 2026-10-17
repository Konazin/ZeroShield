//! Deterministic mini-fuzzer (stable Rust).
//!
//! A cheap regression net for parser robustness: random and mutated inputs
//! must never panic and must only produce well-formed entries. Deep,
//! coverage-guided runs live in `fuzz/` (cargo-fuzz, scheduled CI job).

use zs_net::feeds::parse_feed;

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
    const CHARSET: &[u8] = b"0123456789.:/#-a ";
    let mut bytes = s.as_bytes().to_vec();
    let ops = 1 + rng.below(8);
    for _ in 0..ops {
        if bytes.is_empty() {
            bytes.push(b'x');
            continue;
        }
        let i = rng.below(bytes.len());
        match rng.below(4) {
            0 => bytes[i] = CHARSET[rng.below(CHARSET.len())],
            1 => {
                bytes.remove(i);
            }
            2 => bytes.insert(i, b'0' + (rng.next() % 10) as u8),
            _ => bytes.truncate(i),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn feed_parsing_never_panics() {
    const CORPUS: &[&str] = &[
        "1.2.3.4\n5.6.7.0/24\nevil.example.com\n",
        "https://bad.domain/path/payload.exe # comment\n",
        "102.33.55.1\n# abuse.ch style header\n",
        "not_a_target\nuser@example.com\n",
    ];

    let mut rng = Rng::new(0xfeed_beef_1234_5678);
    for i in 0..3000 {
        let input = match i % 3 {
            0 => String::from_utf8_lossy(&rng.random_bytes(1024)).into_owned(),
            1 => mutate(CORPUS[rng.below(CORPUS.len())], &mut rng),
            _ => ".".repeat(rng.below(4096)),
        };
        let entries = parse_feed(&input, "fuzz");
        // Invariant: every extracted entry is well-formed.
        for e in &entries {
            assert!(
                matches!(e.kind.as_str(), "ip" | "cidr" | "domain"),
                "unexpected kind {}",
                e.kind
            );
            assert!(!e.value.is_empty());
        }
    }
}
