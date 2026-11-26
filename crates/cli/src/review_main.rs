//! Unprivileged offline grant review and SSHSIG verification.

mod review;

fn main() -> std::process::ExitCode {
    review::main()
}
