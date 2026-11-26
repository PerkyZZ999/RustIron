//! W287 (B01): what a build with `--cfg rustiron_profile="product"` compiles
//! in. The default (lab) build compiles nothing from this file; `rust-tc
//! quick` runs it in a second, product-profile build.
#![cfg(rustiron_profile = "product")]

#[path = "product_profile/backup.rs"]
mod backup;
// W362: also its own test target; this runs its product cases in the
// maintained product-profile suite.
#[path = "ols_empty_history.rs"]
mod ols_empty_history;
// W372: the generation adoption and the W359 to W362 rules around it.
#[path = "ols_adoption.rs"]
mod ols_adoption;
#[path = "product_profile/store_launch.rs"]
mod store_launch;
mod support;

use std::path::Path;

use rustiron_contracts::Timestamp;
use rustiron_executor::{AdmissionRequest, ExecutorError, TrustAnchor, admit, layout};

#[test]
fn the_selected_profile_is_the_product_one() {
    assert_eq!(layout::ALL, layout::product::ALL);
    assert_eq!(layout::POLICY_DIR, "/etc/rustiron");
    assert_eq!(layout::JOURNAL_DIR, "/var/lib/rustiron/executor");
    assert_eq!(layout::MARK_DIR, "/var/lib/rustiron/admission");
    assert_eq!(layout::EXECUTOR_SOCKET, "/run/rustiron/executor.sock");
    assert_eq!(layout::JOB_BIN_DIR, "/usr/libexec/rustiron/jobs");
    assert_eq!(
        layout::JOB_CREDENTIALS_DIR,
        "/etc/rustiron/credentials/sites"
    );
    assert_eq!(layout::SITES_ROOT, "/srv/sites");
    assert_eq!(layout::FIXTURE_REGISTRY_DIR, None);
}

#[test]
fn generation_readoption_requires_both_shipped_ols_dropins() {
    use rustiron_executor::readopt::dropins_only_rustiron;

    let mut dropins = vec![
        "/etc/systemd/system/lshttpd.service.d/50-rustiron-killmode.conf".to_owned(),
        "/etc/systemd/system/lshttpd.service.d/51-rustiron-boot-guard.conf".to_owned(),
        "/usr/lib/systemd/system/service.d/10-timeout-abort.conf".to_owned(),
    ];
    assert!(dropins_only_rustiron(&dropins));
    assert!(!dropins_only_rustiron(&dropins[..1]));
    assert!(!dropins_only_rustiron(&dropins[1..]));
    dropins.push("/etc/systemd/system/lshttpd.service.d/99-local.conf".to_owned());
    assert!(!dropins_only_rustiron(&dropins));
}

#[test]
fn the_host_anchor_uses_the_product_locations() {
    let anchor = TrustAnchor::host();
    assert_eq!(anchor.owner_uid, 0);
    assert_eq!(anchor.policy_dir, Path::new("/etc/rustiron"));
    assert_eq!(anchor.journal_dir, Path::new("/var/lib/rustiron/executor"));
    assert_eq!(anchor.mark_dir, Path::new("/var/lib/rustiron/admission"));
    assert_eq!(anchor.scratch_dir, Path::new("/var/lib/rustiron/scratch"));
    assert_eq!(anchor.recipes_dir, Path::new("/var/lib/rustiron/recipes"));
    assert_eq!(anchor.registry_dir, Path::new(""));
    assert!(anchor.admin_socket.is_none());
}

#[test]
fn the_fixture_verb_is_refused_before_any_state_is_read() {
    // A real policy directory would make the lab build go on to decode the
    // plan. Here nothing exists, and the refusal is still the verb's own
    // (a lab build answers EXECUTOR_NOT_ENROLLED for the missing policy, W347).
    let root = std::env::temp_dir().join(format!("rustiron-product-{}", std::process::id()));
    let anchor = TrustAnchor {
        owner_uid: 0,
        policy_dir: root.join("policy"),
        registry_dir: root.join("registry"),
        scratch_dir: root.join("scratch"),
        journal_dir: root.join("journal"),
        mark_dir: root.join("mark"),
        recipes_dir: root.join("recipes"),
        admin_socket: None,
    };
    let request = AdmissionRequest {
        peer_uid: 0,
        plan: b"{}",
        grant: b"{}",
        signature: b"",
        operation_id: "op_product_fixture".to_owned().try_into().unwrap(),
        idempotency_key: "key_product_fixture".to_owned().try_into().unwrap(),
        now: Timestamp::try_from(1_800_000_000).ok(),
    };
    assert!(matches!(
        admit(&anchor, &request),
        Err(ExecutorError::InvalidRequest)
    ));
    assert!(!root.exists());
}

fn contexts(file: &str) -> Vec<&str> {
    file.lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect()
}

#[test]
fn committed_file_contexts_cover_the_product_state_locations() {
    let executor = contexts(include_str!("../../../policy/selinux/rustiron_executor.fc"));
    let admin = contexts(include_str!("../../../policy/selinux/rustiron_admin.fc"));
    let covered = |rules: &[&str], path: &str| {
        rules.iter().any(|rule| {
            rule.strip_suffix("(/.*)?")
                .is_some_and(|base| path == base || path.starts_with(&format!("{base}/")))
        })
    };
    for path in [
        layout::POLICY_DIR,
        layout::JOURNAL_DIR,
        layout::MARK_DIR,
        layout::SCRATCH_DIR,
        layout::RECIPES_DIR,
        layout::EXECUTOR_SOCKET,
        layout::OLS_INCLUDE_DIR,
        layout::OLS_EJECTED_DIR,
    ] {
        assert!(
            covered(&executor, path),
            "no executor file context covers {path}"
        );
    }
    assert!(covered(&admin, layout::ADMIN_SOCKET));
    assert!(admin.contains(&layout::RESTORE_PROBES_ROOT));
}

#[test]
fn product_site_root_context_covers_only_the_directory() {
    let source = include_str!("../../../packaging/selinux/rustiron_site_root.fc");
    assert_eq!(
        source.split_whitespace().collect::<Vec<_>>(),
        [
            layout::SITES_ROOT,
            "-d",
            "gen_context(system_u:object_r:httpd_sys_content_t,s0)",
        ]
    );
}

#[test]
fn product_job_credentials_use_a_separate_file_context() {
    let source = include_str!("../../../packaging/selinux/rustiron_job_credential.fc");
    let rule: Vec<_> = source.split_whitespace().collect();
    let path = format!("{}(/.*)?", layout::JOB_CREDENTIALS_DIR);
    assert_eq!(
        rule,
        [
            path.as_str(),
            "gen_context(system_u:object_r:rustiron_job_credential_t,s0)",
        ]
    );
}

#[test]
fn product_jobs_use_the_capture_entry_context() {
    let lab = include_str!("../../../lab/s07/selinux/rustiron_capture.fc");
    let product = include_str!("../../../packaging/selinux/rustiron_capture.fc");
    let expected = lab.replace(layout::lab::JOB_BIN_DIR, layout::JOB_BIN_DIR);
    let rules = |source: &str| {
        source
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
    };
    assert_eq!(rules(product), rules(&expected));
    assert!(contexts(product).contains(&layout::JOB_RESTIC));
}

#[test]
fn the_product_coordinator_unit_names_the_product_socket() {
    let unit = include_str!("../../../packaging/systemd/rustiron-coordinator.service");
    assert!(unit.contains(&format!("--executor-socket {} ", layout::EXECUTOR_SOCKET)));
}
