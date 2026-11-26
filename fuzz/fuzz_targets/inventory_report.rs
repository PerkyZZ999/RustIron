//! Pure restore inventory report decoder properties, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::inventory_report(input);
});
