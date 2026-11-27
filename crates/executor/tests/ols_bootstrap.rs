//! W355: the bootstrap state of a fresh product host and the decisions of
//! its first activation, without a host. Each bootstrap fact is required;
//! a running host keeps refusing a stopped OLS as drift.

use std::os::fd::OwnedFd;

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustiron_executor::{
    ExecutorError,
    admin_helper::AdminStep,
    ols::{
        ActivationMode, BootstrapFacts, BootstrapStage, ServerChecks, activation_mode,
        bootstrap_generation, bootstrap_restored, clear_current, digest, generation_checks,
        generation_id, is_bootstrap_predecessor, kill_mode_shipped, observe_current, ports_closed,
        render, unit_stopped,
    },
};
use rustiron_journal::ResourceHistory;

const LISTENER: u16 = 8090;
const WEBADMIN: u16 = 7080;
const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

fn table(rows: &[(u16, &str)]) -> String {
    let mut text = HEADER.to_owned();
    for (index, (port, state)) in rows.iter().enumerate() {
        text.push_str(&format!(
            "   {index}: 0100007F:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0\n"
        ));
    }
    text
}

fn real_generation() -> (Id, Sha256Digest) {
    let generation = render("lab", "127.0.0.1:8090", &[], &[]);
    let digest = digest(&generation);
    (generation_id(&digest), digest)
}

fn fresh() -> BootstrapFacts {
    BootstrapFacts {
        history: ResourceHistory::Empty,
        current: None,
        unit_state: Some("inactive".to_owned()),
        kill_mode: Some("mixed".to_owned()),
        parent_reviewed: true,
        ports_closed: true,
        adopted_vhosts_pinned: true,
        php_capacity: true,
    }
}

#[test]
fn the_bootstrap_predecessor_is_the_content_addressed_empty_generation() {
    let (id, empty) = bootstrap_generation();
    assert_eq!(id, generation_id(&empty));
    assert_eq!(empty, digest(&Default::default()));
    assert!(id.as_str().starts_with('r'));
    assert!(is_bootstrap_predecessor(&id, &empty));
    let (real, real_digest) = real_generation();
    assert!(!is_bootstrap_predecessor(&real, &real_digest));
    assert!(!is_bootstrap_predecessor(&id, &real_digest));
    assert_eq!(
        generation_checks(&bootstrap_generation(), None),
        (true, None),
        "the drift checks read the bootstrap predecessor as content-addressed"
    );
}

#[test]
fn a_fresh_host_is_in_the_bootstrap_state() {
    assert!(fresh().hold(BootstrapStage::BeforeSwitch));
    let failed = BootstrapFacts {
        unit_state: Some("failed".to_owned()),
        ..fresh()
    };
    assert!(
        failed.hold(BootstrapStage::BeforeSwitch),
        "a boot with no generation leaves the package unit failed (W348)"
    );
    let compensated = BootstrapFacts {
        history: ResourceHistory::Established(bootstrap_generation().0, bootstrap_generation().1),
        ..fresh()
    };
    assert!(
        compensated.hold(BootstrapStage::BeforeSwitch),
        "a failed and compensated bootstrap re-establishes no generation"
    );
}

#[test]
fn each_missing_fact_is_not_bootstrap() {
    let (real, real_digest) = real_generation();
    let cases: Vec<(&str, BootstrapFacts)> = vec![
        (
            "a generation the journal established",
            BootstrapFacts {
                history: ResourceHistory::Established(real.clone(), real_digest.clone()),
                ..fresh()
            },
        ),
        (
            "an unresolved earlier operation",
            BootstrapFacts {
                history: ResourceHistory::Unresolved,
                ..fresh()
            },
        ),
        (
            "an include target",
            BootstrapFacts {
                current: Some((real, real_digest)),
                ..fresh()
            },
        ),
        (
            "OLS active",
            BootstrapFacts {
                unit_state: Some("active".to_owned()),
                ..fresh()
            },
        ),
        (
            "OLS restarting",
            BootstrapFacts {
                unit_state: Some("activating".to_owned()),
                ..fresh()
            },
        ),
        (
            "OLS stopping",
            BootstrapFacts {
                unit_state: Some("deactivating".to_owned()),
                ..fresh()
            },
        ),
        (
            "an unknown unit state",
            BootstrapFacts {
                unit_state: None,
                ..fresh()
            },
        ),
        (
            "the package KillMode, which leaves workers after a stop (W361)",
            BootstrapFacts {
                kill_mode: Some("none".to_owned()),
                ..fresh()
            },
        ),
        (
            "an unknown KillMode",
            BootstrapFacts {
                kill_mode: None,
                ..fresh()
            },
        ),
        (
            "a parent that is not reviewed",
            BootstrapFacts {
                parent_reviewed: false,
                ..fresh()
            },
        ),
        (
            "a listening port",
            BootstrapFacts {
                ports_closed: false,
                ..fresh()
            },
        ),
        (
            "an adopted vhost that is not pinned",
            BootstrapFacts {
                adopted_vhosts_pinned: false,
                ..fresh()
            },
        ),
        (
            "PHP capacity below the workers",
            BootstrapFacts {
                php_capacity: false,
                ..fresh()
            },
        ),
    ];
    for (name, facts) in cases {
        assert!(!facts.hold(BootstrapStage::BeforeSwitch), "{name}");
        let target = real_generation();
        let started = BootstrapFacts {
            current: Some(target.clone()),
            ..facts.clone()
        };
        if name != "an include target" {
            assert!(!started.hold(BootstrapStage::Start(&target)), "{name}");
        }
    }
}

/// W382 (D-033): the facts the helper confirms before `reconcile` records
/// the bootstrap predecessor of an interrupted bootstrap activation. Only
/// the facts that make the host the predecessor count: the history before
/// the operation, no `current`, OLS stopped, both ports closed, and the
/// reviewed parent. The start-only facts (`KillMode`, adopted vhosts, PHP
/// capacity) do not decide whether OLS serves anything.
#[test]
fn the_reconcile_confirms_the_predecessor_only_when_every_fact_holds() {
    assert!(fresh().predecessor_confirmed());
    let failed = BootstrapFacts {
        unit_state: Some("failed".to_owned()),
        ..fresh()
    };
    assert!(failed.predecessor_confirmed(), "a failed unit is stopped");
    let compensated = BootstrapFacts {
        history: ResourceHistory::Established(bootstrap_generation().0, bootstrap_generation().1),
        ..fresh()
    };
    assert!(compensated.predecessor_confirmed());
    for start_only in [
        BootstrapFacts {
            kill_mode: Some("none".to_owned()),
            ..fresh()
        },
        BootstrapFacts {
            adopted_vhosts_pinned: false,
            ..fresh()
        },
        BootstrapFacts {
            php_capacity: false,
            ..fresh()
        },
    ] {
        assert!(start_only.predecessor_confirmed(), "{start_only:?}");
    }
    let (real, real_digest) = real_generation();
    let refused: Vec<(&str, BootstrapFacts)> = vec![
        (
            "a generation the journal established before the operation",
            BootstrapFacts {
                history: ResourceHistory::Established(real.clone(), real_digest.clone()),
                ..fresh()
            },
        ),
        (
            "an unresolved earlier operation",
            BootstrapFacts {
                history: ResourceHistory::Unresolved,
                ..fresh()
            },
        ),
        (
            "`current` names the journaled target",
            BootstrapFacts {
                current: Some((real, real_digest)),
                ..fresh()
            },
        ),
        (
            "OLS active",
            BootstrapFacts {
                unit_state: Some("active".to_owned()),
                ..fresh()
            },
        ),
        (
            "OLS restarting",
            BootstrapFacts {
                unit_state: Some("activating".to_owned()),
                ..fresh()
            },
        ),
        (
            "OLS stopping",
            BootstrapFacts {
                unit_state: Some("deactivating".to_owned()),
                ..fresh()
            },
        ),
        (
            "an unknown unit state",
            BootstrapFacts {
                unit_state: None,
                ..fresh()
            },
        ),
        (
            "a listening port",
            BootstrapFacts {
                ports_closed: false,
                ..fresh()
            },
        ),
        (
            "a parent that is not reviewed",
            BootstrapFacts {
                parent_reviewed: false,
                ..fresh()
            },
        ),
    ];
    for (name, facts) in refused {
        assert!(!facts.predecessor_confirmed(), "{name}");
    }
}

#[test]
fn the_start_step_needs_exactly_the_journaled_target() {
    let target = real_generation();
    let switched = BootstrapFacts {
        current: Some(target.clone()),
        ..fresh()
    };
    assert!(switched.hold(BootstrapStage::Start(&target)));
    assert!(
        !switched.hold(BootstrapStage::BeforeSwitch),
        "after the switch the host is no longer before the switch"
    );
    assert!(
        !fresh().hold(BootstrapStage::Start(&target)),
        "no current at the start step"
    );
    let other = (
        generation_id(&digest(&render("lab", "127.0.0.1:8091", &[], &[]))),
        digest(&render("lab", "127.0.0.1:8091", &[], &[])),
    );
    let elsewhere = BootstrapFacts {
        current: Some(other),
        ..fresh()
    };
    assert!(!elsewhere.hold(BootstrapStage::Start(&target)));
}

#[test]
fn only_inactive_and_failed_are_stopped() {
    assert!(unit_stopped(Some("inactive")));
    assert!(unit_stopped(Some("failed")));
    for state in [
        "active",
        "activating",
        "deactivating",
        "reloading",
        "maintenance",
        "refreshing",
        "",
        "inactive\n",
    ] {
        assert!(!unit_stopped(Some(state)), "{state:?}");
    }
    assert!(!unit_stopped(None));
}

/// W364: the shipped drop-in sets `KillMode=mixed` (W245). Only then does a
/// stop end every package worker, so only then may the bootstrap start OLS
/// and its compensation report the host stopped.
#[test]
fn only_the_shipped_kill_mode_ends_every_worker() {
    assert!(kill_mode_shipped(Some("mixed")));
    for mode in ["none", "control-group", "process", "", "mixed\n", "Mixed"] {
        assert!(!kill_mode_shipped(Some(mode)), "{mode:?}");
    }
    assert!(!kill_mode_shipped(None));
}

#[test]
fn ports_are_closed_only_when_both_tables_show_neither_port_listening() {
    let ports = [LISTENER, WEBADMIN];
    let quiet = table(&[(22, "0A"), (LISTENER, "06")]);
    assert!(ports_closed(
        &[Some(quiet.clone()), Some(table(&[]))],
        &ports
    ));
    assert!(!ports_closed(&[None, Some(quiet.clone())], &ports));
    assert!(!ports_closed(&[Some(quiet.clone()), None], &ports));
    for port in ports {
        let open = table(&[(port, "0A")]);
        assert!(!ports_closed(
            &[Some(open.clone()), Some(quiet.clone())],
            &ports
        ));
        assert!(!ports_closed(&[Some(quiet.clone()), Some(open)], &ports));
    }
}

#[test]
fn a_running_host_still_refuses_a_stopped_ols_as_drift() {
    let parent = b"disableWebAdmin 1\ninclude /etc/rustiron-ols/current/*.conf\n";
    let reviewed = Sha256Digest::from_bytes(<sha2::Sha256 as sha2::Digest>::digest(parent).into());
    let stopped = [Some(table(&[(22, "0A")])), Some(table(&[]))];
    let checks = ServerChecks::from_reads(
        Some(parent),
        &reviewed,
        stopped,
        (WEBADMIN, LISTENER),
        true,
        true,
    );
    assert!(
        !checks.webadmin_closed,
        "a stopped listener is not the running state"
    );
    let report = checks.report(generation_checks(
        &real_generation(),
        Some(&real_generation()),
    ));
    assert!(!report.clean(), "a stopped OLS on a running host is drift");
}

#[test]
fn the_mode_follows_the_live_current_and_the_plan_predecessor() {
    let real = real_generation();
    let empty = bootstrap_generation();
    assert_eq!(activation_mode(None, &empty), Ok(ActivationMode::Bootstrap));
    assert_eq!(
        activation_mode(Some(&real), &real),
        Ok(ActivationMode::Running)
    );
    assert_eq!(
        activation_mode(None, &real),
        Err(ExecutorError::RegistryUnavailable),
        "a missing current on a host the plan saw running is not bootstrap"
    );
    assert_eq!(
        activation_mode(Some(&real), &empty),
        Err(ExecutorError::PreconditionChanged),
        "a running host cannot be bootstrapped"
    );
    let other = (
        generation_id(&digest(&render("lab", "127.0.0.1:8091", &[], &[]))),
        digest(&render("lab", "127.0.0.1:8091", &[], &[])),
    );
    assert_eq!(
        activation_mode(Some(&other), &real),
        Err(ExecutorError::PreconditionChanged)
    );
}

#[test]
fn bootstrap_starts_and_running_reloads() {
    assert_eq!(
        ActivationMode::Bootstrap.serving_step(),
        AdminStep::OlsStart
    );
    assert_eq!(ActivationMode::Bootstrap.systemctl_verb(), "start");
    assert_eq!(ActivationMode::Running.serving_step(), AdminStep::OlsReload);
    assert_eq!(ActivationMode::Running.systemctl_verb(), "reload");
}

#[test]
fn the_compensation_records_the_bootstrap_state_only_when_restored() {
    let real = real_generation();
    assert_eq!(
        bootstrap_restored(&Ok(()), &Ok(None)),
        Some(bootstrap_generation())
    );
    for (stopped, current) in [
        (Err(ExecutorError::StepFailed), Ok(None)),
        (Ok(()), Ok(Some(real.clone()))),
        (Ok(()), Err(ExecutorError::RegistryUnavailable)),
        (Err(ExecutorError::HelperUnreachable), Ok(Some(real))),
    ] {
        assert_eq!(
            bootstrap_restored(&stopped, &current),
            None,
            "{stopped:?} {current:?}"
        );
    }
}

fn scratch(name: &str) -> (std::path::PathBuf, OwnedFd) {
    let path = std::env::temp_dir().join(format!("ri-w355-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir(&path).unwrap();
    let directory = std::fs::File::open(&path).unwrap();
    (path, directory.into())
}

#[test]
fn a_missing_current_is_observed_as_absent_and_nothing_else_is() {
    let (path, include) = scratch("observe");
    assert_eq!(observe_current(&include), Ok(None));
    std::fs::write(path.join("current"), b"not a link").unwrap();
    assert!(
        observe_current(&include).is_err(),
        "a regular file named current is not absence"
    );
    std::os::unix::fs::symlink("generations/rmissing", path.join("dangling")).unwrap();
    std::fs::remove_file(path.join("current")).unwrap();
    std::fs::rename(path.join("dangling"), path.join("current")).unwrap();
    assert!(
        observe_current(&include).is_err(),
        "a dangling current is not absence"
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn the_compensation_removes_only_a_current_symlink() {
    let (path, include) = scratch("clear");
    assert_eq!(
        clear_current(&include),
        Ok(()),
        "absent is already restored"
    );
    std::os::unix::fs::symlink("generations/rtarget", path.join("current")).unwrap();
    assert_eq!(clear_current(&include), Ok(()));
    assert!(std::fs::symlink_metadata(path.join("current")).is_err());
    std::fs::write(path.join("current"), b"foreign").unwrap();
    assert_eq!(clear_current(&include), Err(ExecutorError::Drift));
    assert_eq!(std::fs::read(path.join("current")).unwrap(), b"foreign");
    std::fs::remove_dir_all(path).unwrap();
}
