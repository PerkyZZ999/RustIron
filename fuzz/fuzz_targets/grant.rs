//! All five catalogue grant decoders, without signatures or admission.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::grant(input);
});
