//! Deterministic mini-fuzzer (stable Rust).
//!
//! A cheap regression net for parser robustness: random and mutated inputs
//! must never panic. Deep, coverage-guided runs live in `fuzz/` (cargo-fuzz,
//! executed by the scheduled CI job).

use zs_ipc::{Frame, Request};

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
            2 => bytes.insert(i, b' ' + (rng.next() % 95) as u8),
            _ => bytes.truncate(i),
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn frame_and_request_parsing_never_panics() {
    const CORPUS: &[&str] = &[
        r#"{"id":1,"method":"status","params":{}}"#,
        r#"{"event":{"type":"scan_progress","done":1,"total":2}}"#,
        r#"{"id":0,"ok":false,"error":"boom"}"#,
        "{}",
        "null",
        r#"[{"nested":[{"deeply":["x"]}]}]"#,
    ];

    let mut rng = Rng::new(0x5eed_1234_5678_9abc);
    for i in 0..3000 {
        let input = match i % 3 {
            0 => String::from_utf8_lossy(&rng.random_bytes(512)).into_owned(),
            1 => mutate(CORPUS[rng.below(CORPUS.len())], &mut rng),
            // Pathological nesting must be rejected, not overflow the stack.
            _ => format!("{}{}", "[".repeat(500), "]".repeat(500)),
        };
        let _ = Frame::parse(&input);
        let _ = serde_json::from_str::<Request>(&input);
    }
}
