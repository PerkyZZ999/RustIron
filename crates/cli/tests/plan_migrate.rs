//! W456: `rustiron-plan migrate` runs the P01 planner offline on the worker's
//! report of the real CyberPanel export from W452, an operator declaration,
//! and a stated target.

use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/migration");

fn migrate(observation: &str, declaration: &str, target: &str) -> (Option<i32>, String) {
    let path = |name: &str| format!("{FIXTURES}/{name}");
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .args([
            "migrate".to_owned(),
            path(observation),
            path(declaration),
            path(target),
        ])
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn the_real_export_plans_with_the_signed_facts_of_w452() {
    let (code, text) = migrate(
        "cp02-observation.json",
        "cp02-declaration.json",
        "target-d055.json",
    );
    assert_eq!(code, Some(0), "{text}");
    for line in [
        "Dry run: nothing changes on any host.\n",
        "Site cp02 for cp02.example.test.\n",
        "PHP stays 8.4.\n",
        "Steps, all in one signed site_import plan:\n",
        // W452 signed these facts from the same report.
        "import 4257 entries (110081626 bytes) as the site user; manifest bc8aa3a2ad42634de4325bde0ebfb8760675a677be26da78e7ade7f3d107d440\n",
        "import the 104402-byte dump (utf8mb4, utf8mb4_unicode_520_ci)",
        "Serving the site needs a separate signed config_activate plan.\n",
        "TLS: none on the source.\n",
        "Not imported: 2 database users, 1 panel users, 1 API tokens.",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn the_product_profile_without_d055_refuses_intl_and_mbstring() {
    let (code, text) = migrate(
        "cp02-observation.json",
        "cp02-declaration.json",
        "target-d054.json",
    );
    assert_eq!(code, Some(3));
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"refusals\":[{\"missing_extension\":\"intl\"},{\"missing_extension\":\"mbstring\"}]}\n"
    );
}

#[test]
fn an_existing_site_on_the_target_is_refused() {
    let (code, text) = migrate(
        "cp02-observation.json",
        "cp02-declaration.json",
        "target-taken.json",
    );
    assert_eq!(code, Some(3));
    for refusal in [
        "\"site_exists\"",
        "\"hostname_exists\"",
        "\"account_exists\"",
        "\"database_exists\"",
    ] {
        assert!(text.contains(refusal), "{refusal}: {text}");
    }
}

#[test]
fn a_wrong_or_open_input_is_refused_without_echo() {
    const ERROR: &str = "{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n";
    // The declaration in the observation's place, and a missing target.
    for (observation, declaration, target) in [
        (
            "cp02-declaration.json",
            "cp02-declaration.json",
            "target-d055.json",
        ),
        (
            "cp02-observation.json",
            "cp02-declaration.json",
            "missing.json",
        ),
        (
            "cp02-observation.json",
            "cp02-declaration.json",
            "target-extra.json",
        ),
    ] {
        let (code, text) = migrate(observation, declaration, target);
        assert_eq!((code, text.as_str()), (Some(2), ERROR), "{target}");
    }
}

/// D-066 (W478): a real export's older database and CyberPanel's placeholder
/// `mail.` child domain are listed as left on the source.
#[test]
fn entries_left_on_the_source_are_listed() {
    let (code, text) = migrate(
        "cp02-left-observation.json",
        "cp02-declaration.json",
        "target-d055.json",
    );
    assert_eq!(code, Some(0), "{text}");
    for line in [
        "import the 104402-byte dump (utf8mb4, utf8mb4_unicode_520_ci)",
        "Left on the source: database old_copy_db (137907764 bytes), which the live wp-config.php does not name.\n",
        "Left on the source: child domain mail.cp02.example.test, which holds only the panel's placeholder page.\n",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

fn migrate_args(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .arg("migrate")
        .args(args)
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8(out.stdout).unwrap())
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let mut random = [0u8; 8];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
    let hex: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::path::PathBuf::from(format!("/tmp/rustiron-w591-{tag}-{hex}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn target_observation_json(with_d055: bool, taken_site: bool, adopted_cp02: bool) -> String {
    let mut exts = vec![
        "bcmath",
        "bz2",
        "calendar",
        "ctype",
        "curl",
        "date",
        "dom",
        "exif",
        "fileinfo",
        "filter",
        "ftp",
        "gd",
        "gettext",
        "hash",
        "iconv",
        "json",
        "libxml",
        "mysqli",
        "mysqlnd",
        "openssl",
        "pcntl",
        "pcre",
        "pdo",
        "pdo_mysql",
        "pdo_sqlite",
        "phar",
        "posix",
        "random",
        "readline",
        "reflection",
        "session",
        "shmop",
        "simplexml",
        "sockets",
        "sodium",
        "spl",
        "sqlite3",
        "standard",
        "sysvmsg",
        "sysvsem",
        "sysvshm",
        "tokenizer",
        "xml",
        "xmlreader",
        "xmlwriter",
        "zend_opcache",
        "zip",
        "zlib",
    ];
    if with_d055 {
        exts.push("intl");
        exts.push("mbstring");
    }
    let sites = if taken_site {
        serde_json::json!([
            {
                "site_id": "cp02",
                "hostname": "cp02.example.test",
                "state": "succeeded",
                "alias_hostname": null
            }
        ])
    } else {
        serde_json::json!([
            {
                "site_id": "p01r",
                "hostname": "p01r.example.test",
                "state": "succeeded",
                "alias_hostname": null
            }
        ])
    };
    let adopted = if adopted_cp02 {
        serde_json::json!([{"name": "legacy", "hostname": "cp02.example.test"}])
    } else {
        serde_json::json!([])
    };
    serde_json::json!({
        "schema": "rustiron-lab-observation/1",
        "host": {
            "host_id": "rustiron_w591_target",
            "host_epoch": "epoch_w591_1",
            "migration_php_versions": ["8.4"],
            "adopted_sites": adopted
        },
        "sites": sites,
        "machine": {
            "schema": "rustiron-host-status/1",
            "stack": {
                "openlitespeed": "1.9.4",
                "mariadb": "10.11.18",
                "php": ["8.4.27"],
                "php_extensions": {
                    "8.4": exts
                }
            },
            "site_accounts": if taken_site { vec!["rs_cp02"] } else { vec!["rs_p01r"] },
            "services": []
        }
    })
    .to_string()
}

fn canonical_cp02_declaration() -> Vec<u8> {
    let raw = std::fs::read(format!("{FIXTURES}/cp02-declaration.json")).unwrap();
    rustiron_contracts::CanonicalObject::decode(&raw)
        .unwrap()
        .as_bytes()
        .to_vec()
}

fn make_signed_declaration(
    dir: &std::path::Path,
    principal: &str,
    namespace: &str,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let key = dir.join("operator_key");
    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());

    let decl = dir.join("declaration.json");
    std::fs::write(&decl, canonical_cp02_declaration()).unwrap();

    let status = Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-Y", "sign", "-f"])
        .arg(&key)
        .args(["-n", namespace])
        .arg(&decl)
        .status()
        .unwrap();
    assert!(status.success());
    let sig = dir.join("declaration.json.sig");
    assert!(sig.exists());

    let pub_key = std::fs::read_to_string(dir.join("operator_key.pub")).unwrap();
    let pub_parts: Vec<&str> = pub_key.split_whitespace().collect();
    let allowed = dir.join("allowed_signers");
    std::fs::write(
        &allowed,
        format!(
            "{principal} namespaces=\"{namespace}\" {} {}\n",
            pub_parts[0], pub_parts[1]
        ),
    )
    .unwrap();
    (decl, sig, allowed, dir.join("operator_key.pub"))
}

#[test]
fn w591_target_observation_derives_profile_and_state_and_catches_conflicts() {
    let dir = temp_dir("obs");
    let obs_d055 = dir.join("target-obs-d055.json");
    let obs_d054 = dir.join("target-obs-d054.json");
    let obs_taken = dir.join("target-obs-taken.json");
    let obs_adopted = dir.join("target-obs-adopted.json");
    let req = dir.join("request.json");

    std::fs::write(&obs_d055, target_observation_json(true, false, false)).unwrap();
    std::fs::write(&obs_d054, target_observation_json(false, false, false)).unwrap();
    std::fs::write(&obs_taken, target_observation_json(true, true, false)).unwrap();
    std::fs::write(&obs_adopted, target_observation_json(true, false, true)).unwrap();
    std::fs::write(&req, r#"{"site_id":"cp02","target_php":"8.4"}"#).unwrap();

    let export_obs = format!("{FIXTURES}/cp02-observation.json");
    let decl = format!("{FIXTURES}/cp02-declaration.json");

    let (code, text) = migrate_args(&[
        &export_obs,
        &decl,
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("Site cp02 for cp02.example.test.\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "Target profile and state: derived from target observation (rustiron_w591_target, epoch_w591_1).\n"
        ),
        "{text}"
    );

    // Without D-055 extensions in target observation, intl and mbstring are refused.
    let (code, text) = migrate_args(&[
        &export_obs,
        &decl,
        req.to_str().unwrap(),
        "--target-observation",
        obs_d054.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(3), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"refusals\":[{\"missing_extension\":\"intl\"},{\"missing_extension\":\"mbstring\"}]}\n"
    );

    // Existing site in target observation causes site/hostname/account/database refusals.
    let (code, text) = migrate_args(&[
        &export_obs,
        &decl,
        req.to_str().unwrap(),
        "--target-observation",
        obs_taken.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(3), "{text}");
    for refusal in [
        "\"site_exists\"",
        "\"hostname_exists\"",
        "\"account_exists\"",
        "\"database_exists\"",
    ] {
        assert!(text.contains(refusal), "{refusal}: {text}");
    }

    // Adopted hostname on target is caught as hostname_exists.
    let (code, text) = migrate_args(&[
        &export_obs,
        &decl,
        req.to_str().unwrap(),
        "--target-observation",
        obs_adopted.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(3), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"refusals\":[\"hostname_exists\"]}\n"
    );

    // Passing a hand-written {request, profile, state} file with --target-observation is refused.
    let hand_target = format!("{FIXTURES}/target-d055.json");
    let (code, text) = migrate_args(&[
        &export_obs,
        &decl,
        &hand_target,
        "--target-observation",
        obs_d055.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(2), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn w591_signed_declaration_verifies_and_rejects_tampering_wrong_namespace_and_revocation() {
    let dir = temp_dir("sig");
    let (decl, sig, allowed, pub_key_path) = make_signed_declaration(
        &dir,
        "operator_1",
        rustiron_contracts::migration::DECLARATION_NAMESPACE,
    );
    let obs_d055 = dir.join("target-obs.json");
    let req = dir.join("request.json");
    std::fs::write(&obs_d055, target_observation_json(true, false, false)).unwrap();
    std::fs::write(&req, r#"{"site_id":"cp02","target_php":"8.4"}"#).unwrap();

    let export_obs = format!("{FIXTURES}/cp02-observation.json");

    // 1. Valid signed canonical declaration + target observation succeeds.
    let (code, text) = migrate_args(&[
        &export_obs,
        decl.to_str().unwrap(),
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        sig.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
    ]);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains(
            "Declaration signature: verified (operator_1, namespace rustiron-migration-declaration-v1).\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "Target profile and state: derived from target observation (rustiron_w591_target, epoch_w591_1).\n"
        ),
        "{text}"
    );

    // 2. Tampered declaration is denied with exit 4.
    let tampered = dir.join("tampered.json");
    let mut bytes = std::fs::read(&decl).unwrap();
    let pos = bytes
        .windows(16)
        .position(|w| w == b"\"cron_entries\":0")
        .unwrap();
    bytes[pos + 15] = b'1';
    std::fs::write(&tampered, &bytes).unwrap();
    let (code, text) = migrate_args(&[
        &export_obs,
        tampered.to_str().unwrap(),
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        sig.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
    ]);
    assert_eq!(code, Some(4), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"DECLARATION_SIGNATURE_DENIED\"}\n"
    );

    // 3. Revoked signing key is denied with exit 4.
    let (code, text) = migrate_args(&[
        &export_obs,
        decl.to_str().unwrap(),
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        sig.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
        "--revocations",
        pub_key_path.to_str().unwrap(),
    ]);
    assert_eq!(code, Some(4), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"DECLARATION_SIGNATURE_DENIED\"}\n"
    );

    // 4. Non-canonical declaration file (pretty-printed) is refused with exit 2.
    let pretty = format!("{FIXTURES}/cp02-declaration.json");
    let (code, text) = migrate_args(&[
        &export_obs,
        &pretty,
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        sig.to_str().unwrap(),
        "--allowed-signers",
        allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
    ]);
    assert_eq!(code, Some(2), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n"
    );

    // 5. Plan namespace (`rustiron-plan-v1`) is refused in allowed_signers (domain separation).
    let plan_dir = temp_dir("wrong-ns");
    let (plan_decl, plan_sig, plan_allowed, _) =
        make_signed_declaration(&plan_dir, "operator_1", "rustiron-plan-v1");
    let (code, text) = migrate_args(&[
        &export_obs,
        plan_decl.to_str().unwrap(),
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        plan_sig.to_str().unwrap(),
        "--allowed-signers",
        plan_allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
    ]);
    assert_eq!(code, Some(2), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n"
    );

    // 6. Wildcard principal in allowed_signers is refused with exit 2.
    let wildcard_allowed = dir.join("wildcard_allowed");
    let pub_key = std::fs::read_to_string(&pub_key_path).unwrap();
    let pub_parts: Vec<&str> = pub_key.split_whitespace().collect();
    std::fs::write(
        &wildcard_allowed,
        format!(
            "* namespaces=\"rustiron-migration-declaration-v1\" {} {}\n",
            pub_parts[0], pub_parts[1]
        ),
    )
    .unwrap();
    let (code, text) = migrate_args(&[
        &export_obs,
        decl.to_str().unwrap(),
        req.to_str().unwrap(),
        "--target-observation",
        obs_d055.to_str().unwrap(),
        "--declaration-sig",
        sig.to_str().unwrap(),
        "--allowed-signers",
        wildcard_allowed.to_str().unwrap(),
        "--principal",
        "operator_1",
    ]);
    assert_eq!(code, Some(2), "{text}");
    assert_eq!(
        text,
        "{\"scope\":\"migration_plan\",\"error\":\"INVALID_MIGRATION_INPUT\"}\n"
    );

    std::fs::remove_dir_all(&plan_dir).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}
