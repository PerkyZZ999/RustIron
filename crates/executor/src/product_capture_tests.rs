//! W356: the product capture sequence over a recording store, fake units and
//! a fake freeze; no systemd, store or secret.
use std::{cell::RefCell, rc::Rc};

use super::*;
use crate::{durable::repository_preflight::StoreIdentity, store_network::WorkerAction};

const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const MARKER: &str = "wp_posts\t1234\n";
const ROOT: &str = "/srv/sites/rs_blog";

fn operation() -> Id {
    Id::try_from("op_w356".to_owned()).unwrap()
}

/// One store phase as the worker action the real store runs for it, so the
/// key pair comes from the launcher's own [`WorkerAction::identity`].
fn identity(phase: &str) -> StoreIdentity {
    let operation = operation();
    let indexes = WrittenIndexes::parse("-").unwrap();
    match phase {
        "repo-id" => WorkerAction::RepositoryId,
        "lock" => WorkerAction::Lock {
            written: None,
            output: "o",
        },
        "lock-op" => WorkerAction::Lock {
            written: Some((&operation, &indexes)),
            output: "o",
        },
        "backup" => WorkerAction::Backup {
            operation: &operation,
            output: "o",
        },
        "check" => WorkerAction::Check,
        "snapshot-tag" => WorkerAction::SnapshotTag {
            operation: &operation,
            output: "o",
        },
        "manifest" => WorkerAction::Manifest {
            snapshot: ID,
            output: "o",
        },
        other => panic!("not a store phase: {other}"),
    }
    .identity()
}

/// The answer of each plain store phase, by phase name.
type Answer = Box<dyn Fn(&str) -> Result<(), ExecutorError>>;
/// One failure case: its name, the store change, and the outcome.
type Case = (
    &'static str,
    Box<dyn FnOnce(&mut Recording)>,
    CaptureOutcome,
);

/// Answers each store phase from a table and logs it.
struct Recording {
    log: Rc<RefCell<Vec<String>>>,
    answer: Answer,
    write: Result<WrittenSnapshot, WriteFailure>,
    found: Result<Option<String>, ExecutorError>,
    manifest: Result<Vec<u8>, ExecutorError>,
    /// W391: the snapshot object the postcheck reads back.
    lock_object: String,
}

impl Recording {
    fn new(log: Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            log,
            answer: Box::new(|_| Ok(())),
            write: Ok(WrittenSnapshot {
                id: ID.to_owned(),
                files: 3,
                bytes: 9,
                indexes: WrittenIndexes::parse("-").unwrap(),
            }),
            found: Ok(Some(ID.to_owned())),
            manifest: Ok(worker_lines().into_bytes()),
            lock_object: ID.to_owned(),
        }
    }

    fn step(&self, phase: &str) -> Result<(), ExecutorError> {
        self.log.borrow_mut().push(phase.to_owned());
        (self.answer)(phase)
    }
}

impl Store for Recording {
    fn repository(&mut self) -> Result<(), ExecutorError> {
        self.step("repo-id")
    }
    fn lock(
        &mut self,
        written: Option<(&Id, &WrittenIndexes)>,
    ) -> Result<LockReading, ExecutorError> {
        if let Some((operation, indexes)) = written {
            assert_eq!(operation.as_str(), "op_w356");
            assert_eq!(indexes, &self.write.as_ref().unwrap().indexes);
        }
        self.step(if written.is_some() { "lock-op" } else { "lock" })?;
        // W391: the postcheck reads back the written snapshot's version.
        Ok(LockReading {
            days: 30,
            objects: written
                .map(|_| rustiron_journal::ObjectRetention {
                    kind: rustiron_journal::RetainedObjectKind::Snapshot,
                    object_id: self.lock_object.clone(),
                    version_id: "v1".to_owned(),
                    retain_until: 1_797_183_776,
                })
                .into_iter()
                .collect(),
        })
    }
    fn write(&mut self, operation: &Id) -> Result<WrittenSnapshot, WriteFailure> {
        assert_eq!(operation.as_str(), "op_w356");
        self.step("backup")
            .map_err(WriteFailure::NotLaunched)
            .and(self.write.clone())
    }
    fn check(&mut self) -> Result<(), ExecutorError> {
        self.step("check")
    }
    fn find(&mut self, operation: &Id) -> Result<Option<String>, ExecutorError> {
        assert_eq!(operation.as_str(), "op_w356");
        self.step("snapshot-tag").and(self.found.clone())
    }
    fn manifest(&mut self, snapshot: &str) -> Result<Vec<u8>, ExecutorError> {
        assert_eq!(snapshot, ID);
        self.step("manifest").and(self.manifest.clone())
    }
}

fn worker_lines() -> String {
    let digest = crate::manifest::format::digest_hex(b"x");
    format!(
        "{{\"path\":\"srv/sites/rs_blog/html/index.php\",\"kind\":\"file\",\"size\":1,\"sha256\":\"{digest}\",\"mode\":420}}\n{{\"end\":{{\"entries\":1,\"regular_bytes\":1,\"truncated\":false}}}}\n"
    )
}

/// Runs the product sequence; `local(step, n)` answers the n-th dump or
/// marker unit. Returns the outcome and the whole phase log.
fn run_with(
    configure: impl FnOnce(&mut Recording),
    local: impl Fn(&str, usize) -> Result<String, ExecutorError>,
    removed: Result<(), ExecutorError>,
    freeze: Option<&mut dyn Freeze>,
) -> (CaptureOutcome, Vec<String>) {
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut store = Recording::new(log.clone());
    configure(&mut store);
    let mut counts = std::collections::HashMap::<String, usize>::new();
    let outcome = capture_steps(
        ROOT,
        "rs_blog",
        &operation(),
        &mut store,
        |phase, command| {
            // Only the dump and the marker run as local units.
            assert!(matches!(phase, Phase::Dump | Phase::Marker), "{phase:?}");
            let expected = match phase {
                Phase::Dump => capture::dump_command(ROOT, "rs_blog"),
                _ => capture::marker_command(ROOT, "rs_blog"),
            };
            assert_eq!(
                command,
                expected.iter().map(String::as_str).collect::<Vec<_>>()
            );
            let step = phase.name();
            log.borrow_mut().push(step.to_owned());
            let n = counts.entry(step.to_owned()).or_default();
            *n += 1;
            local(step, *n)
        },
        || {
            log.borrow_mut().push("remove".to_owned());
            removed
        },
        freeze,
    );
    let steps = log.borrow().clone();
    (outcome, steps)
}

fn quiet(step: &str, _: usize) -> Result<String, ExecutorError> {
    Ok(if step == "marker" {
        MARKER.to_owned()
    } else {
        String::new()
    })
}

fn run(configure: impl FnOnce(&mut Recording)) -> (CaptureOutcome, Vec<String>) {
    run_with(configure, quiet, Ok(()), None)
}

const FULL: [&str; 11] = [
    "repo-id",
    "lock",
    "marker",
    "dump",
    "backup",
    "marker",
    "check",
    "snapshot-tag",
    "lock-op",
    "manifest",
    "remove",
];

#[test]
fn a_full_capture_runs_the_design_order_with_the_design_key_pairs() {
    let (outcome, steps) = run(|_| {});
    assert_eq!(steps, FULL);
    let CaptureOutcome::Succeeded(snapshot) = outcome else {
        panic!("capture must succeed: {outcome:?}");
    };
    assert_eq!(snapshot.id, ID);
    assert_eq!(snapshot.extent(), Some((3, 9)));
    assert_eq!(snapshot.consistency, CaptureConsistency::Matched);
    let manifest = snapshot.manifest.expect("manifest");
    assert_eq!((manifest.entries, manifest.regular_bytes), (1, 1));
    // W391: the postcheck's versions are the capture's retention evidence.
    let evidence = snapshot.retention.expect("retention evidence");
    assert_eq!((evidence.before_days, evidence.after_days), (30, 30));
    assert_eq!(evidence.objects.len(), 1);
    assert_eq!(evidence.objects[0].object_id, ID);
    assert_eq!(evidence.objects[0].version_id, "v1");

    // The design table's credential column: the capture key pair only for
    // steps 3, 6 and 9; the fetch key pair for 2, 7, 8 and 10; the dump and
    // marker units get none (they never reach the store runner).
    let store_steps: Vec<(&str, StoreIdentity)> = steps
        .iter()
        .filter(|step| !matches!(step.as_str(), "dump" | "marker" | "remove"))
        .map(|step| (step.as_str(), identity(step)))
        .collect();
    assert_eq!(
        store_steps,
        [
            ("repo-id", StoreIdentity::Fetch),
            ("lock", StoreIdentity::Capture),
            ("backup", StoreIdentity::Capture),
            ("check", StoreIdentity::Fetch),
            ("snapshot-tag", StoreIdentity::Fetch),
            ("lock-op", StoreIdentity::Capture),
            ("manifest", StoreIdentity::Fetch),
        ]
    );
}

#[test]
fn the_dump_and_marker_units_have_no_store_destination() {
    let site = rustiron_contracts::approval::SiteId::try_from("blog13".to_owned()).unwrap();
    let layout = SiteLayout::derive(&site);
    // A product local unit refuses every repository phase before launch.
    for phase in [
        Phase::Snapshot,
        Phase::Check,
        Phase::Find,
        Phase::Manifest,
        Phase::Lock,
    ] {
        assert_eq!(
            capture::run_local_unit(&layout, "s0:c201", phase, &["x"]),
            Err(ExecutorError::InvalidRequest),
            "{phase:?}"
        );
    }
}

#[test]
fn a_refusal_before_the_write_is_a_known_failure_without_a_dump() {
    for (refused, expected, steps) in [
        ("repo-id", ExecutorError::StepFailed, &["repo-id"][..]),
        (
            "lock",
            ExecutorError::RetentionUnverified,
            &["repo-id", "lock"][..],
        ),
    ] {
        let (outcome, log) = run(|store| {
            store.answer = Box::new(move |phase| {
                if phase == refused {
                    Err(ExecutorError::StepFailed)
                } else {
                    Ok(())
                }
            });
        });
        assert_eq!(outcome, CaptureOutcome::NotStarted(expected), "{refused}");
        assert_eq!(log, steps, "{refused}");
    }
}

#[test]
fn a_failed_dump_is_a_known_failure_and_the_dump_is_removed() {
    let (outcome, steps) = run_with(
        |_| {},
        |step, _| match step {
            "dump" => Err(ExecutorError::StepFailed),
            _ => quiet(step, 1),
        },
        Ok(()),
        None,
    );
    assert_eq!(
        outcome,
        CaptureOutcome::NotStarted(ExecutorError::StepFailed)
    );
    assert_eq!(steps, ["repo-id", "lock", "marker", "dump", "remove"]);
}

#[test]
fn store_checks_refused_at_the_write_start_nothing() {
    // The namespace changed between steps 3 and 6: no worker started.
    let (outcome, steps) = run(|store| {
        store.write = Err(WriteFailure::NotLaunched(
            ExecutorError::PreconditionChanged,
        ));
    });
    assert_eq!(
        outcome,
        CaptureOutcome::NotStarted(ExecutorError::PreconditionChanged)
    );
    assert_eq!(steps[steps.len() - 2..], ["backup", "remove"]);
}

#[test]
fn every_failure_from_the_write_on_is_uncertain() {
    let id = || Some(ID.to_owned());
    let cases: Vec<Case> = vec![
        (
            "write unit failed",
            Box::new(|store| {
                store.write = Err(WriteFailure::Launched {
                    error: ExecutorError::StepFailed,
                    snapshot: None,
                });
            }),
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: None,
            },
        ),
        (
            "partial write",
            Box::new(|store| {
                store.write = Err(WriteFailure::Launched {
                    error: ExecutorError::StepFailed,
                    snapshot: Some(ID.to_owned()),
                });
            }),
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: id(),
            },
        ),
        (
            "postcheck reads another snapshot",
            Box::new(|store| store.lock_object = "e".repeat(64)),
            CaptureOutcome::Uncertain {
                error: ExecutorError::RetentionUnverified,
                snapshot: id(),
            },
        ),
        (
            "postcheck omits a written index",
            Box::new(|store| {
                store.write.as_mut().unwrap().indexes =
                    WrittenIndexes::parse(&"e".repeat(64)).unwrap();
            }),
            CaptureOutcome::Uncertain {
                error: ExecutorError::RetentionUnverified,
                snapshot: id(),
            },
        ),
        (
            "check failed",
            Box::new(|store| {
                store.answer = Box::new(|phase| {
                    if phase == "check" {
                        Err(ExecutorError::StepFailed)
                    } else {
                        Ok(())
                    }
                });
            }),
            CaptureOutcome::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: id(),
            },
        ),
        (
            "tag lists another snapshot",
            Box::new(|store| store.found = Ok(Some("f".repeat(64)))),
            CaptureOutcome::Uncertain {
                error: ExecutorError::PreconditionChanged,
                snapshot: id(),
            },
        ),
        (
            "tag lists nothing",
            Box::new(|store| store.found = Ok(None)),
            CaptureOutcome::Uncertain {
                error: ExecutorError::PreconditionChanged,
                snapshot: id(),
            },
        ),
        (
            "tag listing refused",
            Box::new(|store| store.found = Err(ExecutorError::Unavailable)),
            CaptureOutcome::Uncertain {
                error: ExecutorError::Unavailable,
                snapshot: id(),
            },
        ),
        (
            "lock postcheck failed",
            Box::new(|store| {
                store.answer = Box::new(|phase| {
                    if phase == "lock-op" {
                        Err(ExecutorError::StepFailed)
                    } else {
                        Ok(())
                    }
                });
            }),
            CaptureOutcome::Uncertain {
                error: ExecutorError::RetentionUnverified,
                snapshot: id(),
            },
        ),
    ];
    for (name, configure, expected) in cases {
        let (outcome, steps) = run(configure);
        assert_eq!(outcome, expected, "{name}");
        // Nothing after the failing step reaches the store, and the dump is
        // still removed.
        assert_eq!(steps.last().map(String::as_str), Some("remove"), "{name}");
        assert!(!steps.contains(&"manifest".to_owned()), "{name}");
    }
}

#[test]
fn a_failed_or_refused_manifest_leaves_the_capture_succeeded() {
    for manifest in [
        Err(ExecutorError::StepFailed),
        Ok(Vec::new()),
        Ok(b"not a manifest\n".to_vec()),
        // A path outside the two sources is refused by the W203 check.
        Ok(worker_lines()
            .replace("srv/sites/rs_blog/html", "srv/sites/rs_blog/private")
            .into_bytes()),
    ] {
        let (outcome, steps) = run(|store| store.manifest = manifest.clone());
        let CaptureOutcome::Succeeded(snapshot) = outcome else {
            panic!("capture must succeed for {manifest:?}");
        };
        assert!(snapshot.manifest.is_none(), "{manifest:?}");
        assert_eq!(steps, FULL);
    }
}

#[test]
fn a_dump_left_behind_makes_any_outcome_uncertain() {
    let (outcome, _) = run_with(|_| {}, quiet, Err(ExecutorError::StepFailed), None);
    assert_eq!(
        outcome,
        CaptureOutcome::Uncertain {
            error: ExecutorError::StepFailed,
            snapshot: Some(ID.to_owned())
        }
    );
    let (outcome, _) = run_with(
        |store| {
            store.answer = Box::new(|phase| {
                if phase == "lock" {
                    Err(ExecutorError::StepFailed)
                } else {
                    Ok(())
                }
            });
        },
        quiet,
        Err(ExecutorError::StepFailed),
        None,
    );
    // Refused before the dump unit: the removal is not even tried.
    assert_eq!(
        outcome,
        CaptureOutcome::NotStarted(ExecutorError::RetentionUnverified)
    );
}

#[test]
fn a_changed_marker_is_labelled_and_never_matched() {
    let (outcome, _) = run_with(
        |_| {},
        |step, n| match (step, n) {
            ("marker", 2) => Ok("wp_posts\t9999\n".to_owned()),
            _ => quiet(step, n),
        },
        Ok(()),
        None,
    );
    let CaptureOutcome::Succeeded(snapshot) = outcome else {
        panic!("capture must succeed");
    };
    assert_eq!(
        snapshot.consistency,
        CaptureConsistency::Unmatched(UnmatchedReason::DatabaseChanged)
    );
}

struct FakeFreeze {
    log: Rc<RefCell<Vec<String>>>,
    held: bool,
}

impl Freeze for FakeFreeze {
    fn arm(&mut self) -> Result<(), ExecutorError> {
        self.log.borrow_mut().push("arm".into());
        Ok(())
    }
    fn stop(&mut self) -> Result<(), ExecutorError> {
        self.log.borrow_mut().push("stop".into());
        Ok(())
    }
    fn held(&mut self) -> bool {
        self.log.borrow_mut().push("held".into());
        self.held
    }
    fn thaw(&mut self) {
        self.log.borrow_mut().push("thaw".into());
    }
}

#[test]
fn a_frozen_capture_thaws_once_right_after_the_second_marker() {
    for held in [true, false] {
        let freeze_log = Rc::new(RefCell::new(Vec::new()));
        let mut freeze = FakeFreeze {
            log: freeze_log.clone(),
            held,
        };
        let (outcome, _) = run_with(|_| {}, quiet, Ok(()), Some(&mut freeze));
        let CaptureOutcome::Succeeded(snapshot) = outcome else {
            panic!("capture must succeed");
        };
        assert_eq!(*freeze_log.borrow(), ["arm", "stop", "held", "thaw"]);
        assert_eq!(
            snapshot.consistency,
            if held {
                CaptureConsistency::Matched
            } else {
                CaptureConsistency::Unmatched(UnmatchedReason::FreezeNotHeld)
            }
        );
    }
    // A failed write still thaws exactly once.
    let freeze_log = Rc::new(RefCell::new(Vec::new()));
    let mut freeze = FakeFreeze {
        log: freeze_log.clone(),
        held: true,
    };
    let (outcome, _) = run_with(
        |store| {
            store.write = Err(WriteFailure::Launched {
                error: ExecutorError::StepFailed,
                snapshot: None,
            });
        },
        quiet,
        Ok(()),
        Some(&mut freeze),
    );
    assert!(matches!(outcome, CaptureOutcome::Uncertain { .. }));
    assert_eq!(*freeze_log.borrow(), ["arm", "stop", "thaw"]);
}
