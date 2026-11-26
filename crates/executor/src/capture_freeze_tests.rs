//! W258 (D-021 option A, A3): the frozen capture sequence over fake units and
//! a fake freeze; no systemd.
use super::*;
use std::{cell::RefCell, rc::Rc};

const MARKER: &str = "wp_posts\t1234\n";
const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn summary() -> String {
    format!(
        "{{\"message_type\":\"summary\",\"snapshot_id\":\"{ID}\",\"total_files_processed\":3,\"total_bytes_processed\":9}}\n"
    )
}

struct Fake {
    log: Rc<RefCell<Vec<String>>>,
    arm: Result<(), ExecutorError>,
    stop: Result<(), ExecutorError>,
    held: bool,
}

impl Freeze for Fake {
    fn arm(&mut self) -> Result<(), ExecutorError> {
        self.log.borrow_mut().push("arm".into());
        self.arm
    }
    fn stop(&mut self) -> Result<(), ExecutorError> {
        self.log.borrow_mut().push("stop".into());
        self.stop
    }
    fn held(&mut self) -> bool {
        self.log.borrow_mut().push("held".into());
        self.held
    }
    fn thaw(&mut self) {
        self.log.borrow_mut().push("thaw".into());
    }
}

/// Runs a frozen capture; `answer(step, n)` gets the n-th call of that step.
fn frozen(
    arm: Result<(), ExecutorError>,
    stop: Result<(), ExecutorError>,
    held: bool,
    answer: impl Fn(&str, usize) -> Result<String, ExecutorError>,
) -> (CaptureOutcome, Vec<String>) {
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut fake = Fake {
        log: log.clone(),
        arm,
        stop,
        held,
    };
    let mut counts = std::collections::HashMap::<String, usize>::new();
    let outcome = capture_steps_with(
        "/srv/sites/blog",
        "rs_blog",
        "op_test",
        |phase, _| {
            let step = phase.name();
            log.borrow_mut().push(step.to_owned());
            let n = counts.entry(step.to_owned()).or_default();
            *n += 1;
            match step {
                "lock" => Ok(format!("{}\n", crate::manifest::lock::pass_line(30))),
                _ => answer(step, *n),
            }
        },
        || Ok(()),
        Some(&mut fake),
    );
    let steps = log.borrow().clone();
    (outcome, steps)
}

fn quiet(step: &str, _: usize) -> Result<String, ExecutorError> {
    match step {
        "snapshot" => Ok(summary()),
        "marker" => Ok(MARKER.to_owned()),
        _ => Ok(String::new()),
    }
}

fn label(outcome: &CaptureOutcome) -> CaptureConsistency {
    match outcome {
        CaptureOutcome::Succeeded(snapshot) => snapshot.consistency,
        other => panic!("expected success, got {other:?}"),
    }
}

fn position(steps: &[String], step: &str, nth: usize) -> usize {
    steps
        .iter()
        .enumerate()
        .filter(|(_, s)| *s == step)
        .nth(nth)
        .unwrap_or_else(|| panic!("{step} #{nth} missing in {steps:?}"))
        .0
}

#[test]
fn the_timer_is_armed_first_and_the_pool_is_back_right_after_the_second_marker() {
    let (outcome, steps) = frozen(Ok(()), Ok(()), true, quiet);
    assert_eq!(label(&outcome), CaptureConsistency::Matched);
    let at = |s, n| position(&steps, s, n);
    assert!(at("lock", 0) < at("arm", 0), "{steps:?}");
    assert!(at("arm", 0) < at("stop", 0));
    assert!(at("stop", 0) < at("marker", 0));
    assert!(at("marker", 0) < at("dump", 0));
    assert!(at("dump", 0) < at("snapshot", 0));
    assert!(at("snapshot", 0) < at("marker", 1));
    assert!(at("marker", 1) < at("held", 0));
    assert!(at("held", 0) < at("thaw", 0));
    assert!(at("thaw", 0) < at("check", 0));
    assert_eq!(steps.iter().filter(|s| *s == "thaw").count(), 1);
}

#[test]
fn a_freeze_that_did_not_hold_is_freeze_not_held_even_with_equal_markers() {
    let (outcome, steps) = frozen(Ok(()), Ok(()), false, quiet);
    assert_eq!(
        label(&outcome),
        CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld)
    );
    assert!(steps.contains(&"thaw".to_owned()));
}

#[test]
fn a_held_freeze_still_reports_a_database_change() {
    let (outcome, _) = frozen(Ok(()), Ok(()), true, |step, n| match (step, n) {
        ("marker", 2) => Ok("wp_posts\t1235\n".to_owned()),
        _ => quiet(step, n),
    });
    assert_eq!(
        label(&outcome),
        CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged)
    );
}

#[test]
fn no_freeze_without_an_armed_timer_and_nothing_runs() {
    let (outcome, steps) = frozen(Err(ExecutorError::StepFailed), Ok(()), true, quiet);
    assert_eq!(
        outcome,
        CaptureOutcome::NotStarted(ExecutorError::StepFailed)
    );
    assert_eq!(steps, ["lock", "arm", "thaw"]);
}

#[test]
fn a_failed_stop_thaws_and_refuses_before_the_dump() {
    let (outcome, steps) = frozen(Ok(()), Err(ExecutorError::StepFailed), true, quiet);
    assert_eq!(
        outcome,
        CaptureOutcome::NotStarted(ExecutorError::StepFailed)
    );
    assert_eq!(steps, ["lock", "arm", "stop", "thaw"]);
}

#[test]
fn every_failure_after_the_stop_thaws_exactly_once() {
    for failing in ["dump", "snapshot"] {
        let (outcome, steps) = frozen(Ok(()), Ok(()), true, |step, n| {
            if step == failing {
                Err(ExecutorError::StepFailed)
            } else {
                quiet(step, n)
            }
        });
        assert!(
            !matches!(outcome, CaptureOutcome::Succeeded(_)),
            "{failing}: {outcome:?}"
        );
        assert_eq!(
            steps.iter().filter(|s| *s == "thaw").count(),
            1,
            "{failing}: {steps:?}"
        );
        assert!(!steps.contains(&"held".to_owned()) || failing == "snapshot");
    }
}

#[test]
fn an_unfrozen_capture_never_touches_a_freeze() {
    let (outcome, steps) = {
        let mut steps = Vec::new();
        let outcome = capture_steps_with(
            "/srv/sites/blog",
            "rs_blog",
            "op_test",
            |phase, _| {
                steps.push(phase.name().to_owned());
                match phase.name() {
                    "lock" => Ok(format!("{}\n", crate::manifest::lock::pass_line(30))),
                    s => quiet(s, 1),
                }
            },
            || Ok(()),
            None,
        );
        (outcome, steps)
    };
    assert_eq!(label(&outcome), CaptureConsistency::Matched);
    assert!(
        !steps
            .iter()
            .any(|s| ["arm", "stop", "held", "thaw"].contains(&s.as_str()))
    );
}

#[test]
fn the_freeze_commands_are_fixed_for_the_site_and_capped_at_ten_seconds() {
    let unit = "rustiron-unfreeze-rs_blog13-00ff";
    assert_eq!(
        arm_command("rs_blog13", unit),
        [
            "--unit",
            unit,
            "--on-active=10",
            "--timer-property=AccuracySec=100ms",
            "--quiet",
            "--collect",
            "/usr/bin/systemctl",
            "start",
            "rustiron-site-php@rs_blog13.socket",
        ]
    );
    assert_eq!(
        pool_units("rs_blog13"),
        [
            "rustiron-site-php@rs_blog13.socket",
            "rustiron-site-php@rs_blog13.service",
        ]
    );
    assert_eq!(FREEZE_CAP_SECS, 10);
    for bad in ["", "blog13", "rs_blog13.socket", "rs_../x", "rs_a b"] {
        assert!(SystemdFreeze::new(bad).is_err(), "{bad}");
    }
    assert!(SystemdFreeze::new("rs_blog13").is_ok());
}
