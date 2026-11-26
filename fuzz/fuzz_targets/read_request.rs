//! Pure read_request properties, without socket or executor effects.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::read_request(input);
});
