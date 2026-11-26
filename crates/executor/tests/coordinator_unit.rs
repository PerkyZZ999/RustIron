//! W234 (B05): the product coordinator unit keeps the W191 lab unit's
//! confinement and adds only product identity and paths.
const PRODUCT: &str = include_str!("../../../packaging/systemd/rustiron-coordinator.service");
const LAB: &str = include_str!("../../../lab/s10/rustiron-s10-lab-coordinator.service");
const SYSUSERS: &str = include_str!("../../../packaging/sysusers.d/rustiron-coordinator.conf");

fn settings(unit: &str) -> Vec<&str> {
    unit.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with('['))
        .collect()
}

fn value<'a>(unit: &'a str, key: &str) -> Option<&'a str> {
    settings(unit)
        .into_iter()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
}

#[test]
fn every_lab_hardening_setting_is_kept() {
    let product = settings(PRODUCT);
    let identity = [
        "Description=",
        "User=",
        "Group=",
        "ExecStart=",
        "Restart=",
        "After=",
    ];
    for line in settings(LAB) {
        if identity.iter().any(|k| line.starts_with(k)) {
            continue;
        }
        assert!(product.contains(&line), "missing from product unit: {line}");
    }
}

#[test]
fn product_identity_is_dedicated_and_unprivileged() {
    assert_eq!(value(PRODUCT, "User"), Some("rustiron-coordinator"));
    assert_eq!(
        value(PRODUCT, "SupplementaryGroups"),
        Some("rustiron-requesters")
    );
    assert_eq!(value(PRODUCT, "CapabilityBoundingSet"), Some(""));
    assert_eq!(value(PRODUCT, "PrivateNetwork"), Some("yes"));
    let exec = value(PRODUCT, "ExecStart").unwrap();
    assert!(exec.starts_with("/usr/libexec/rustiron/rustiron-control "));
    assert!(!exec.contains("lab") && !PRODUCT.contains("rustiron-build"));
    assert!(SYSUSERS.contains("u rustiron-coordinator - "));
    assert!(SYSUSERS.contains("m rustiron-coordinator rustiron-requesters"));
    assert!(SYSUSERS.contains("/usr/sbin/nologin"));
}

#[test]
fn start_limits_are_in_the_unit_section() {
    // `systemd-analyze verify` ignores StartLimit* under [Service] (W234).
    let unit: Vec<&str> = PRODUCT
        .lines()
        .skip_while(|l| l.trim() != "[Unit]")
        .take_while(|l| l.trim() != "[Service]")
        .collect();
    assert!(unit.contains(&"StartLimitIntervalSec=60s"));
    assert!(unit.contains(&"StartLimitBurst=5"));
}

const FC: &str = include_str!("../../../policy/selinux/rustiron_coordinator.fc");
const TE: &str = include_str!("../../../policy/selinux/rustiron_coordinator.te");

/// W236: the domain labels exactly the unit's binary, state and runtime dirs.
#[test]
fn selinux_file_contexts_cover_the_unit_paths() {
    let exec = value(PRODUCT, "ExecStart")
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let state = format!(
        "/var/lib/{}(/.*)?",
        value(PRODUCT, "StateDirectory").unwrap()
    );
    let run = format!("/run/{}(/.*)?", value(PRODUCT, "RuntimeDirectory").unwrap());
    let fc: Vec<(&str, &str)> = FC
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some((f.next()?, f.last()?))
        })
        .collect();
    for (path, ty) in [
        (exec, "rustiron_coordinator_exec_t"),
        (state.as_str(), "rustiron_coordinator_var_lib_t"),
        (run.as_str(), "rustiron_coordinator_run_t"),
    ] {
        assert!(
            fc.iter().any(|(p, c)| *p == path && c.contains(ty)),
            "{path} not labelled {ty}"
        );
    }
    // NoNewPrivileges=yes needs the nnp transition; no exec of other programs.
    assert_eq!(value(PRODUCT, "NoNewPrivileges"), Some("yes"));
    assert!(TE.contains("init_nnp_daemon_domain(rustiron_coordinator_t)"));
    assert!(!TE.contains("can_exec") && !TE.contains("corecmd_exec"));
}
