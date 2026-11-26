//! Secret-shape detection for output checks (W185).
//!
//! The executor redacts by construction: step outcomes are dropped to `()`,
//! errors are fixed codes, and stderr reasons are `&'static str`. This module
//! names the shapes a leaked secret would have, so tests and lab checks can
//! show that log, receipt, export and error output carry none of them,
//! without ever comparing against a real secret value.

/// Length in hex digits of every generated lab secret (24 random bytes).
pub const GENERATED_SECRET_HEX: usize = 48;

/// Markers that only appear next to a secret value.
const MARKERS: [(&str, &str); 7] = [
    ("password=", "password_assignment"),
    ("\npassword ", "password_line"),
    ("IDENTIFIED BY", "sql_identified_by"),
    ("RESTIC_PASSWORD=", "restic_password_env"),
    ("AWS_SECRET_ACCESS_KEY=", "aws_secret_env"),
    ("-----BEGIN", "pem_block"),
    ("PRIVATE KEY", "private_key"),
];

/// The secret shapes found in `text`, by name; empty means none. Never
/// returns the matched text.
pub fn secret_shapes(text: &str) -> Vec<&'static str> {
    let mut found: Vec<&'static str> = MARKERS
        .iter()
        .filter(|(marker, _)| text.contains(marker))
        .map(|&(_, name)| name)
        .collect();
    if hex_run(text, GENERATED_SECRET_HEX) {
        found.push("generated_secret_hex48");
    }
    if aws_access_key(text) {
        found.push("aws_access_key_id");
    }
    found
}

/// A maximal run of exactly `length` lowercase hex digits. Digests (64) and
/// shorter ids do not match.
fn hex_run(text: &str, length: usize) -> bool {
    let mut run = 0;
    for byte in text.bytes().chain(std::iter::once(b' ')) {
        if byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte) {
            run += 1;
        } else {
            if run == length {
                return true;
            }
            run = 0;
        }
    }
    false
}

fn aws_access_key(text: &str) -> bool {
    text.match_indices("AKIA").any(|(at, _)| {
        let rest = &text.as_bytes()[at + 4..];
        rest.len() >= 16
            && rest[..16]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::secret_shapes;
    use crate::{ExecutorError, provision};

    #[test]
    fn every_generated_secret_and_its_written_forms_are_detected() {
        for _ in 0..64 {
            let secret = provision::random_secret().unwrap();
            assert_eq!(secret_shapes(&secret), ["generated_secret_hex48"]);
            assert!(!secret_shapes(&format!("x {secret} y")).is_empty());
            let cnf = provision::credentials_text("rs_blog13", &secret);
            assert!(secret_shapes(&cnf).contains(&"password_assignment"));
            let host =
                rustiron_contracts::approval::Hostname::try_from("blog13.lab".to_owned()).unwrap();
            let handover = provision::handover_text(&host, &secret);
            assert!(secret_shapes(&handover).contains(&"password_line"));
        }
        assert!(!secret_shapes("CREATE USER 'a'@'localhost' IDENTIFIED BY 'x'").is_empty());
        assert!(!secret_shapes("key AKIAABCDEFGHIJKLMNOP").is_empty());
        assert!(!secret_shapes("-----BEGIN OPENSSH PRIVATE KEY-----").is_empty());
    }

    #[test]
    fn digests_ids_and_credential_paths_are_not_secret_shaped() {
        for text in [
            "ab".repeat(32).as_str(),
            "c6c1960147290e1cf6f04d0f81563a9542f7e59a231b91ac5cb8bc1c8649891a",
            "rp_abcdef cap_w050 operation_1",
            "LoadCredential=password:/etc/rustiron-s07-lab/sites/rs_blog13/repo.password",
            "RESTIC_PASSWORD_FILE=/run/credentials/x.service/password",
            "--defaults-file=/srv/sites/rs_blog13/private/db.cnf",
        ] {
            assert!(secret_shapes(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn every_error_code_and_reply_is_fixed_text() {
        use ExecutorError::*;
        for error in [
            AccessDenied,
            Unavailable,
            PeerDenied,
            InvalidRequest,
            BindingDenied,
            TimeDenied,
            SignatureDenied,
            RegistryUnavailable,
            PreconditionChanged,
            ReplayDenied,
            Busy,
            ClockRollback,
            Capacity,
            StateExists,
            IdentityMismatch,
            NotAdmitted,
            CompensationDenied,
            Collision,
            StepFailed,
            Drift,
            ArtifactUnavailable,
            ProbeFailed,
            JournalRollback,
            HelperUnreachable,
            RetentionUnverified,
            GenerationCurrent,
            QuotaUnavailable,
            NotEnrolled,
            ReadoptMismatch,
            WindowClosed,
            RunMismatch,
        ] {
            // A new variant must be added here: fails to compile otherwise.
            match error {
                AccessDenied | Unavailable | PeerDenied | InvalidRequest | BindingDenied
                | TimeDenied | SignatureDenied | RegistryUnavailable | PreconditionChanged
                | ReplayDenied | Busy | ClockRollback | Capacity | StateExists
                | IdentityMismatch | NotAdmitted | CompensationDenied | Collision | StepFailed
                | Drift | ArtifactUnavailable | ProbeFailed | JournalRollback
                | HelperUnreachable | RetentionUnverified | GenerationCurrent
                | QuotaUnavailable | NotEnrolled | ReadoptMismatch | WindowClosed | RunMismatch => {
                }
            }
            let reply = serde_json::to_string(&crate::serve::error_reply(None, error)).unwrap();
            assert!(secret_shapes(error.code()).is_empty());
            assert!(secret_shapes(&reply).is_empty(), "{reply}");
        }
    }
}
