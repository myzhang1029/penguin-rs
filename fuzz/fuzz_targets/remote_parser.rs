#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let string = String::from_utf8_lossy(data);
    let _: Option<rusty_penguin_lib::arg::Remote> = string.parse().ok();
});
