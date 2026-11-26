//! The executor's admin-helper probe reply payload reader, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::admin_probe_payload(input);
});
