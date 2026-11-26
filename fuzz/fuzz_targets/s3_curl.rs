//! The curl argv, config and S3 URL builders, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::s3_curl(input);
});
