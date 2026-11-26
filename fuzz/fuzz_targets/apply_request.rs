//! Pure raw apply_request codec invariants, without authority or I/O.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::apply_request(input);
});
