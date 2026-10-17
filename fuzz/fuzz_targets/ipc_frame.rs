#![no_main]

use libfuzzer_sys::fuzz_target;
use zs_ipc::{Frame, Request};

// IPC frames are attacker-controlled: any local client can send garbage.
fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Frame::parse(text);
    let _ = serde_json::from_str::<Request>(text);
});
