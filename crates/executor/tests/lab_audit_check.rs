//! W237: lab post-state checks run as `ssh 'bash -s' < script`, so stdin is a
//! pipe and `ausearch` reads it instead of the audit logs, returning
//! `<no matches>`. Every ausearch must force the logs with `--input-logs`.
const CHECK: &str = include_str!("../../../lab/s10/w215_check.sh");

#[test]
fn ausearch_reads_the_audit_logs_not_stdin() {
    let calls: Vec<&str> = CHECK.lines().filter(|l| l.contains("ausearch")).collect();
    assert!(!calls.is_empty());
    for line in calls {
        assert!(
            line.contains("--input-logs"),
            "ausearch without --input-logs: {line}"
        );
    }
}
