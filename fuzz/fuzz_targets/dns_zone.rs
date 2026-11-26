//! Arbitrary-byte canonical DNS zone parser invariant campaign (D-091, W638 / M-06).
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::dns_zone(input);
});
