#![no_main]

use libfuzzer_sys::fuzz_target;
use oct_security::{ClientPrelude, HostPrelude, Invite};

fuzz_target!(|bytes: &[u8]| {
    let _ = ClientPrelude::decode(bytes);
    let _ = HostPrelude::decode(bytes);
    if let Ok(value) = std::str::from_utf8(bytes) {
        let _ = Invite::decode(value);
    }
});
