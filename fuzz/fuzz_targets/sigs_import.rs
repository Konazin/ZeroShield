#![no_main]

use libfuzzer_sys::fuzz_target;
use zs_scan::signatures::{import_text, SigFormat};

// Signature imports (.hdb, CSV, plain lists) are semi-trusted input.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(storage) = zs_core::storage::Storage::open_in_memory() else {
        return;
    };
    let _ = import_text(&storage, text, "fuzz", SigFormat::PlainHashes);
    let _ = import_text(&storage, text, "fuzz", SigFormat::ClamHdb);
    let _ = import_text(&storage, text, "fuzz", SigFormat::ZeroShieldCsv);
});
