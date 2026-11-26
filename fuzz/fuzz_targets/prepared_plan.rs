//! Arbitrary-byte five-kind plan invariant campaign, without authority or effects.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::prepared_plan(input);
});
