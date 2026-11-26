//! W315 root lab test: drive `store_network::check_repository` against a
//! fixture prepared by `docs/validation/S10-W315/probe_store.sh`. W345 adds
//! the same for `store_network::check_lock`. Ignored by default; they need
//! root, systemd, the store namespace and a labelled worker.

use std::path::PathBuf;

use rustiron_contracts::{
    Id,
    approval::{ProductBackupPolicy, SiteId},
};
use rustiron_executor::{
    ExecutorError, TrustAnchor, retention_evidence::WrittenIndexes, store_network,
};

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required"))
}

#[test]
#[ignore = "root lab test: run through docs/validation/S10-W315/probe_store.sh"]
fn store_repository_check_as_root() {
    let policy_dir = PathBuf::from(required("W315_POLICY_DIR"));
    let site = SiteId::try_from(required("W315_SITE")).unwrap();
    let level = required("W315_LEVEL");
    let expected = required("W315_EXPECT");
    let projection = std::fs::read(policy_dir.join("backup-destination.json")).unwrap();
    let policy = ProductBackupPolicy::decode(&projection).unwrap();
    let mut anchor = TrustAnchor::host();
    anchor.policy_dir = policy_dir;
    let result = store_network::check_repository(&anchor, &policy, &site, &level);
    assert_expected(result, &expected);
}

/// W345 root lab test: drive `store_network::check_lock` against the HTTPS
/// lab store through the fixture of `docs/validation/S10-W345/probe_lock.sh`.
/// For a write postcheck, set `W345_OPERATION` and the successful write's
/// `W345_WRITTEN_INDEXES`. Without them the test checks the bucket default.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W345/probe_lock.sh"]
fn store_lock_check_as_root() {
    let policy_dir = PathBuf::from(required("W315_POLICY_DIR"));
    let site = SiteId::try_from(required("W315_SITE")).unwrap();
    let level = required("W315_LEVEL");
    let expected = required("W315_EXPECT");
    let operation = std::env::var("W345_OPERATION")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| Id::try_from(value).unwrap());
    let projection = std::fs::read(policy_dir.join("backup-destination.json")).unwrap();
    let policy = ProductBackupPolicy::decode(&projection).unwrap();
    let mut anchor = TrustAnchor::host();
    anchor.policy_dir = policy_dir;
    let indexes = operation.as_ref().map(|_| {
        WrittenIndexes::parse(&required("W345_WRITTEN_INDEXES"))
            .expect("validated write index list")
    });
    let result = store_network::check_lock(
        &anchor,
        &policy,
        &site,
        &level,
        operation.as_ref().zip(indexes.as_ref()),
    )
    .map(|reading| {
        println!(
            "w391_lock_days={} objects={}",
            reading.days,
            reading.objects.len()
        )
    });
    assert_expected(result, &expected);
}

/// W356 root lab test: the admin helper's product capture effects (the
/// write gate, then design steps 2 to 10) for `W315_SITE` and the operation
/// `W356_OPERATION`, through the fixture of
/// `docs/validation/S10-W356/probe_write.sh`. `W315_EXPECT` is `not_admitted`
/// (a shipped build), or the outcome: `succeeded`, `not_started` or
/// `uncertain`. Prints the outcome without the manifest text.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W356/probe_write.sh"]
fn product_capture_effects_as_root() {
    let policy_dir = PathBuf::from(required("W315_POLICY_DIR"));
    let site = SiteId::try_from(required("W315_SITE")).unwrap();
    let expected = required("W315_EXPECT");
    let operation = Id::try_from(required("W356_OPERATION")).unwrap();
    let projection = std::fs::read(policy_dir.join("backup-destination.json")).unwrap();
    let policy = ProductBackupPolicy::decode(&projection).unwrap();
    let mut anchor = TrustAnchor::host();
    anchor.policy_dir = policy_dir;
    let result = rustiron_executor::admin_helper::product_capture_effects(
        &anchor, &policy, &site, &operation, false,
    );
    let outcome = match &result {
        Ok(line) => {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            println!("w356_outcome={}", summary(&value));
            value["outcome"].as_str().unwrap_or("unreadable").to_owned()
        }
        Err(error) => {
            println!("w356_result=Err({error:?})");
            "not_admitted".to_owned()
        }
    };
    if expected == "not_admitted" {
        assert_eq!(result, Err(ExecutorError::NotAdmitted));
    }
    assert_eq!(outcome, expected);
}

/// The outcome line without the manifest text: its digest and counts only.
fn summary(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(manifest) = value.get_mut("manifest").and_then(|m| m.as_object_mut()) {
        let text = manifest.remove("text");
        let lines = text
            .as_ref()
            .and_then(|t| t.as_str())
            .map(|t| t.lines().count());
        manifest.insert("lines".to_owned(), serde_json::json!(lines));
    }
    value
}

/// W356 root lab test: the snapshot write unit alone, as
/// `store_network::write_snapshot` starts it. With a shipped worker the
/// gate refuses inside the unit: `Launched` with no snapshot.
#[test]
#[ignore = "root lab test: run through docs/validation/S10-W356/probe_write.sh"]
fn store_write_as_root() {
    let policy_dir = PathBuf::from(required("W315_POLICY_DIR"));
    let site = SiteId::try_from(required("W315_SITE")).unwrap();
    let level = required("W315_LEVEL");
    let operation = Id::try_from(required("W356_OPERATION")).unwrap();
    let projection = std::fs::read(policy_dir.join("backup-destination.json")).unwrap();
    let policy = ProductBackupPolicy::decode(&projection).unwrap();
    let mut anchor = TrustAnchor::host();
    anchor.policy_dir = policy_dir;
    let result = store_network::write_snapshot(&anchor, &policy, &site, &level, &operation);
    println!("w356_write={result:?}");
    match required("W315_EXPECT").as_str() {
        "gate_refused" => assert_eq!(
            result,
            Err(store_network::WriteFailure::Launched {
                error: ExecutorError::StepFailed,
                snapshot: None
            })
        ),
        other => panic!("unknown expectation {other}"),
    }
}

fn assert_expected(result: Result<(), ExecutorError>, expected: &str) {
    println!("w315_result={result:?}");
    match expected {
        "ok" => assert_eq!(result, Ok(())),
        "precondition" => assert_eq!(result, Err(ExecutorError::PreconditionChanged)),
        "access_denied" => assert_eq!(result, Err(ExecutorError::AccessDenied)),
        "step_failed" => assert_eq!(result, Err(ExecutorError::StepFailed)),
        other => panic!("unknown expectation {other}"),
    }
}
