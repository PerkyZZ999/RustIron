//! The S3 GetObjectLockConfiguration reader, without I/O or authority.
#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    rustiron_fuzz::s3_object_lock(input);
});
