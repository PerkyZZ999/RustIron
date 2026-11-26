//! W591 (P01): deriving `TargetProfile` and `TargetState` from a target host's
//! merged read-only observation.

use rustiron_contracts::{
    ProtocolError,
    migration::{PhpExtension, PhpVersion, derive_target_from_observation},
};
use serde_json::{Value, json};

fn sample_observation() -> Value {
    json!({
        "schema": "rustiron-lab-observation/1",
        "host": {
            "host_id": "rustiron_target_1",
            "host_epoch": "epoch_target_1",
            "migration_php_versions": ["8.4"],
            "adopted_sites": [
                {"name": "legacy", "hostname": "legacy.example.test"}
            ]
        },
        "sites": [
            {
                "site_id": "blog1",
                "hostname": "blog1.example.test",
                "state": "succeeded",
                "alias_hostname": null
            },
            {
                "site_id": "docs1",
                "hostname": "docs1.example.test",
                "state": "succeeded",
                "alias_hostname": "www.docs1.example.test"
            },
            {
                "site_id": "gone1",
                "hostname": "gone1.example.test",
                "state": "deleted",
                "alias_hostname": null
            }
        ],
        "machine": {
            "schema": "rustiron-host-status/1",
            "stack": {
                "openlitespeed": "1.9.4",
                "mariadb": "10.11.18",
                "php": ["8.4.27"],
                "php_extensions": {
                    "8.4": ["curl", "dom", "gd", "intl", "mbstring", "mysqli", "simplexml", "zip"]
                }
            },
            "site_accounts": ["rs_blog1", "rs_docs1", "rs_orphan"],
            "services": [
                {"unit": "rustiron-site-php@rs_svc_only.service", "active": "inactive"}
            ]
        }
    })
}

fn derive(value: &Value) -> Result<rustiron_contracts::migration::ObservedTarget, ProtocolError> {
    let bytes = serde_json::to_vec(value).unwrap();
    derive_target_from_observation(&bytes)
}

#[test]
fn derives_profile_and_state_including_aliases_adopted_deleted_and_host_accounts() {
    let target = derive(&sample_observation()).expect("valid merged observation");
    assert_eq!(target.host_id.as_str(), "rustiron_target_1");
    assert_eq!(target.host_epoch.as_str(), "epoch_target_1");
    assert_eq!(
        target.profile.php_versions,
        vec![PhpVersion::try_from("8.4".to_owned()).unwrap()]
    );
    assert!(
        target
            .profile
            .php_extensions
            .contains(&PhpExtension::try_from("simplexml".to_owned()).unwrap())
    );
    assert!(
        target
            .profile
            .php_extensions
            .contains(&PhpExtension::try_from("intl".to_owned()).unwrap())
    );

    let site_ids: Vec<&str> = target.state.site_ids.iter().map(|s| s.as_str()).collect();
    // Deleted site ID stays reserved in the journal (D-085).
    assert_eq!(site_ids, vec!["blog1", "docs1", "gone1"]);

    let hostnames: Vec<&str> = target.state.hostnames.iter().map(|h| h.as_str()).collect();
    assert_eq!(
        hostnames,
        vec![
            "blog1.example.test",
            "docs1.example.test",
            "gone1.example.test",
            "legacy.example.test",
            "www.docs1.example.test",
        ]
    );

    let accounts: Vec<&str> = target.state.accounts.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        accounts,
        vec!["rs_blog1", "rs_docs1", "rs_orphan", "rs_svc_only"]
    );

    let databases: Vec<&str> = target.state.databases.iter().map(|d| d.as_str()).collect();
    // Deleted site's database was removed; non-deleted sites stay reserved.
    assert_eq!(databases, vec!["rs_blog1", "rs_docs1"]);
}

#[test]
fn multiple_enrolled_php_versions_intersect_their_observed_extensions() {
    let mut obs = sample_observation();
    obs["host"]["migration_php_versions"] = json!(["8.3", "8.4"]);
    obs["machine"]["stack"]["php_extensions"] = json!({
        "8.3": ["curl", "mysqli", "zip"],
        "8.4": ["curl", "intl", "mysqli", "simplexml"]
    });
    let target = derive(&obs).expect("multi-version intersection");
    let exts: Vec<&str> = target
        .profile
        .php_extensions
        .iter()
        .map(PhpExtension::as_str)
        .collect();
    assert_eq!(exts, vec!["curl", "mysqli"]);
}

#[test]
fn fails_closed_when_migration_policy_or_extensions_are_missing() {
    let mut no_migration = sample_observation();
    no_migration["host"]["migration_php_versions"] = Value::Null;
    assert_eq!(derive(&no_migration), Err(ProtocolError::InvalidMessage));

    let mut missing_version_exts = sample_observation();
    missing_version_exts["host"]["migration_php_versions"] = json!(["8.3", "8.4"]);
    assert_eq!(
        derive(&missing_version_exts),
        Err(ProtocolError::InvalidMessage)
    );

    let mut disjoint_exts = sample_observation();
    disjoint_exts["host"]["migration_php_versions"] = json!(["8.3", "8.4"]);
    disjoint_exts["machine"]["stack"]["php_extensions"] = json!({
        "8.3": ["curl"],
        "8.4": ["mysqli"]
    });
    assert_eq!(derive(&disjoint_exts), Err(ProtocolError::InvalidMessage));

    let mut unmerged = sample_observation();
    unmerged.as_object_mut().unwrap().remove("machine");
    assert_eq!(derive(&unmerged), Err(ProtocolError::InvalidMessage));

    let mut bad_schema = sample_observation();
    bad_schema["schema"] = json!("rustiron-lab-observation/99");
    assert_eq!(derive(&bad_schema), Err(ProtocolError::InvalidMessage));
}
