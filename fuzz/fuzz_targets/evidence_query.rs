//! Pure evidence_query properties, without socket or executor effects.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::evidence_query(input);
});
