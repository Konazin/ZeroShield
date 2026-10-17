#![no_main]

use libfuzzer_sys::fuzz_target;

// The daemon parses its TOML config at startup; hostile configs must produce
// clean errors, never panics.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = zs_core::config::Config::parse_toml(text);
});
