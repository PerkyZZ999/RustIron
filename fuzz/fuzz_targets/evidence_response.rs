//! Pure evidence_response codec properties, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::evidence_response(input);
});
