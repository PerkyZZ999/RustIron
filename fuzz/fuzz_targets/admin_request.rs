//! Pure admin-helper request line properties, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::admin_request(input);
});
