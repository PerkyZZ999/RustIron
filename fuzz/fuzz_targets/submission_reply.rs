//! Pure submission_reply codec properties, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::submission_reply(input);
});
