//! Pure status_query properties, without socket or executor effects.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::status_query(input);
});
