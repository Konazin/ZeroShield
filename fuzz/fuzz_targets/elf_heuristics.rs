#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

// Every scanned file that starts with the ELF magic reaches these heuristics.
fuzz_target!(|data: &[u8]| {
    // Bound memory when run with a larger `-max_len`: the scanner never
    // passes arbitrary-length buffers here.
    if data.len() > 512 * 1024 {
        return;
    }
    let _ = zs_scan::elf::analyze(data, Path::new("fuzz"));
});
