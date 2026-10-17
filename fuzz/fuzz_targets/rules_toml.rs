#![no_main]

use libfuzzer_sys::fuzz_target;

// Rule packs can be imported by privileged operators; a panic here would
// take down the whole scan pipeline.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut set = zs_scan::rules::RuleSet::new();
    let _ = set.load_toml(text, "fuzz");
});
