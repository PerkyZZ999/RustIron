//! W394 (B06): `site_readopt` cases that the W377 matrix does not hold:
//! the signer epoch, the issuer, a cross-site grant scope, a truncated or
//! linked journal, and the exact replay under a journal behind its mark
//! (O1 of W377, as W380 decided it).

use std::os::unix::fs::symlink;

use rustiron_contracts::execution::OutcomeState;

use super::w377::{
    JOURNAL, MARK, current, raise_mark, refused, replay_state, submit, write_policy,
};
use super::*;

#[test]
fn w394_readopt_signer_and_scope_abuse_is_refused_before_any_record() {
    let lab = Lab::new("w394-scope");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let operation = "op_w394b";

    // Another signer epoch, and another issuer, in an otherwise valid grant.
    for (field, value) in [
        ("signer_policy_epoch", "policy_9"),
        ("issuer", "operator_9"),
    ] {
        let signed = lab.signed_with(
            site_plan("blog2", |_| {}),
            "site",
            "w394b",
            json!(["blog2"]),
            "key",
            |grant| grant[field] = json!(value),
        );
        refused(
            &lab,
            &mut executor,
            &signed.request(operation),
            ExecutorError::BindingDenied,
            field,
        );
    }

    // Cross-site scope: a plan for blog2 under a grant for blog3, and a
    // grant that names both sites for a one-site plan.
    for sites in [json!(["blog3"]), json!(["blog2", "blog3"])] {
        let signed = lab.signed_with(
            site_plan("blog2", |_| {}),
            "site",
            "w394b",
            sites.clone(),
            "key",
            |_| {},
        );
        refused(
            &lab,
            &mut executor,
            &signed.request(operation),
            ExecutorError::BindingDenied,
            &format!("grant sites {sites}"),
        );
    }

    // Control: the unmodified request is adopted.
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog2", 3002, 202,
    ))));
    let valid = lab.site("blog2", "w394b", |_| {});
    let ReadoptResult::New(row) = executor.readopt(&valid.request(operation)).unwrap() else {
        panic!("new re-adoption expected");
    };
    assert_eq!(row.state, ReadoptState::Adopted);
}

/// No empty-ledger fallback beyond W377: a truncated journal and a journal
/// name that is a link to a copy of the real journal are refused, and
/// `initialize` creates nothing in their place.
#[test]
fn w394_a_truncated_or_linked_journal_is_refused_never_reinitialized() {
    let lab = Lab::new("w394-ledger");
    let journal = lab.anchor.journal_dir.join(JOURNAL);
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "w394l");
    drop(executor);
    let admitted = fs::read(&journal).unwrap();
    let mark = fs::read(lab.anchor.mark_dir.join(MARK)).unwrap();

    private_file(&journal, &admitted[..admitted.len() / 2]);
    assert!(Executor::open(lab.anchor()).is_err(), "a truncated journal");
    assert!(
        Executor::initialize(lab.anchor()).is_err(),
        "a truncated journal was reinitialized"
    );
    assert_eq!(fs::read(&journal).unwrap(), &admitted[..admitted.len() / 2]);

    let copy = lab.root.join("journal-copy.sqlite");
    private_file(&copy, &admitted);
    fs::remove_file(&journal).unwrap();
    symlink(&copy, &journal).unwrap();
    assert!(Executor::open(lab.anchor()).is_err(), "a linked journal");
    assert!(fs::symlink_metadata(&journal).unwrap().is_symlink());
    assert_eq!(
        fs::read(&copy).unwrap(),
        admitted,
        "the link target was written"
    );
    assert_eq!(fs::read(lab.anchor.mark_dir.join(MARK)).unwrap(), mark);

    fs::remove_file(&journal).unwrap();
    private_file(&journal, &admitted);
    let mut executor = Executor::open(lab.anchor()).unwrap();
    assert!(matches!(
        executor
            .readopt(&lab.site("blog1", "w394l", |_| {}).request("op_w394l"))
            .unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Adopted
    ));
}

/// O1 of W377, as W380 decided it: the exact replay of an admitted
/// re-adoption over the socket, with the journal behind its admission mark,
/// is answered from the journal before the fence (stored status, no write).
/// A new re-adoption under the same fence is refused with
/// `JOURNAL_ROLLBACK`, and a changed key under the admitted ID carries no
/// stored status.
#[test]
fn w394_an_exact_readopt_replay_under_a_fenced_journal_is_status_only() {
    let lab = Lab::new("w394-fence");
    let uid = rustix::process::getuid().as_raw();
    write_policy(&lab, |policy| policy["requester_uid"] = json!(uid));
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let admitted = current(&lab, "blog1", "w394f");
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog1", 3001, 201,
    ))));
    let reply = submit(&mut executor, &admitted, "op_w394f", "key_op_w394f");
    assert_eq!(reply.state, Some(OutcomeState::Succeeded), "{reply:?}");

    let mark = raise_mark(&lab);
    let before = replay_state(&lab);
    let reply = submit(&mut executor, &admitted, "op_w394f", "key_op_w394f");
    assert!(reply.replay, "{reply:?}");
    assert_eq!(reply.state, Some(OutcomeState::Succeeded));
    assert_eq!(reply.error, None);
    let reply = submit(&mut executor, &admitted, "op_w394f", "key_w394_changed");
    assert_eq!(reply.error.as_deref(), Some("REPLAY_DENIED"), "{reply:?}");
    assert_eq!(reply.state, None, "a fenced refusal gave stored status");
    let other = current(&lab, "blog2", "w394g");
    let reply = submit(&mut executor, &other, "op_w394g", "key_op_w394g");
    assert_eq!(
        reply.error.as_deref(),
        Some("JOURNAL_ROLLBACK"),
        "{reply:?}"
    );
    assert_eq!(reply.state, None);
    assert!(replay_state(&lab) == before, "a fenced journal was written");
    private_file(&lab.anchor.mark_dir.join(MARK), &mark);
}
