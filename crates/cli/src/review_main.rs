//! Unprivileged offline grant review and SSHSIG verification.
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "W672: production code returns errors; tests may unwrap (clippy.toml)"
)]

mod review;

fn main() -> std::process::ExitCode {
    review::main()
}
