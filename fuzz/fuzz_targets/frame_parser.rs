#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = bytes::Bytes::from(data.to_vec());
    let _ = penguin_mux::frame::Frame::try_from(bytes);

});
