//! The S3 ListObjectsV2 page reader, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::s3_list(input);
});
