//! Semantic pair binding with independent synthetic facts and asserted time.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::plan_grant_binding(input);
});
