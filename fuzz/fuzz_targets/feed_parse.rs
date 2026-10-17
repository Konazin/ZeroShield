#![no_main]

use libfuzzer_sys::fuzz_target;

// Threat feeds are downloaded from third parties; the parser must never
// panic and must only ever emit well-formed entries.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let entries = zs_net::feeds::parse_feed(text, "fuzz");
    for e in &entries {
        assert!(
            matches!(e.kind.as_str(), "ip" | "cidr" | "domain"),
            "unexpected kind {:?}",
            e.kind
        );
        assert!(!e.value.is_empty());
    }
});
