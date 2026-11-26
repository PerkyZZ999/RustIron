//! Arbitrary-byte canonical object invariant campaign.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::canonical_object(input);
});
