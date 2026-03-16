#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed raw bytes as a complete Ethernet frame through the full
    // dissector chain. We only care that it doesn't panic — errors are fine.
    let _ = fireshark_dissectors::decode_packet(data);
});
