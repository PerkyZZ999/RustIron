//! Capture-manifest tar walk and canonical builder invariants, without I/O.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::capture_manifest(input);
});
