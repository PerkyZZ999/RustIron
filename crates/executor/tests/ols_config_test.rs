//! W238: `openlitespeed -t` must run where the server runs (a transient
//! systemd unit, like lshttpd.service), not inside the admin helper's
//! `rustiron_admin_t`, where SELinux denied its shm/tmp/socket setup.
use rustiron_executor::ols::CONFIG_TEST_ARGV;

#[test]
fn config_test_runs_as_a_waited_transient_unit() {
    assert_eq!(CONFIG_TEST_ARGV[0], "/usr/bin/systemd-run");
    for flag in ["--wait", "--pipe", "--quiet", "--collect"] {
        assert!(CONFIG_TEST_ARGV.contains(&flag), "missing {flag}");
    }
    assert_eq!(
        &CONFIG_TEST_ARGV[CONFIG_TEST_ARGV.len() - 2..],
        ["/usr/local/lsws/bin/openlitespeed", "-t"]
    );
}

#[test]
fn no_call_site_runs_openlitespeed_directly() {
    for (name, src) in [
        ("admin_helper.rs", include_str!("../src/admin_helper.rs")),
        ("durable.rs", include_str!("../src/durable.rs")),
    ] {
        assert!(
            !src.contains("run(\"/usr/local/lsws/bin/openlitespeed\""),
            "{name} runs openlitespeed -t directly"
        );
    }
}
