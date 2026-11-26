//! P01 slice 1: the closed migration inventory and the dry-run planner.

use rustiron_contracts::migration::{
    Field, MigrationRequest, Refusal, Step, TargetProfile, TargetState, decode_migration_inventory,
    plan_migration, render_dry_run,
};
use serde_json::{Value, json};

const DIGEST: &str = "4b3e1d0c9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a2918070605";

fn inventory() -> Value {
    json!({
        "schema_version": 1,
        "source_profile": {"declared": {"os": "AlmaLinux 9.6", "panel": "CyberPanel 2.4", "web_server": "OpenLiteSpeed 1.8"}},
        "hostname": {"observed": "blog.example.test"},
        "declared_hostname": {"declared": "blog.example.test"},
        "aliases": {"observed": []},
        "child_domains": {"observed": 0},
        "files": {"observed": {"entries": 4200, "bytes": 90_000_000, "manifest_sha256": DIGEST, "unsafe_entries": 0}},
        "uploads": {"observed": {"files": 800, "bytes": 60_000_000}},
        "databases": {"observed": [{"bytes": 12_000_000, "charset": "utf8mb4", "collation": "utf8mb4_unicode_ci"}]},
        "php_version": {"observed": "8.2"},
        "php_extensions": {"declared": ["curl", "gd", "mysqli", "zip"]},
        "site_url": {"observed": "https://blog.example.test"},
        "home_url": {"observed": "https://blog.example.test/"},
        "cron_entries": {"declared": 1},
        "tls": {"observed": {"subject": "blog.example.test", "issuer": "R11", "not_after": 1_800_000_000}},
        "credentials": {"observed": {"database_users": 1, "panel_users": 1, "api_tokens": 1}},
        "dns": {"declared": {"authority": "registrar DNS", "addresses": ["192.0.2.10"]}},
        "dns_records": {"observed": 6},
        "mail": {"declared": {"mx": 1, "spf": true, "dkim": true, "dmarc": false, "outbound": "provider relay"}},
        "mail_accounts": {"observed": 2},
        "api_consumers": {"declared": 0}
    })
}

fn request(php: &str) -> MigrationRequest {
    serde_json::from_value(json!({"site_id": "blog", "target_php": php})).unwrap()
}

fn profile() -> TargetProfile {
    serde_json::from_value(json!({
        "php_versions": ["8.2", "8.3"],
        "php_extensions": ["curl", "gd", "intl", "mysqli", "zip"]
    }))
    .unwrap()
}

fn empty_state() -> TargetState {
    serde_json::from_value(
        json!({"site_ids": [], "hostnames": [], "accounts": [], "databases": []}),
    )
    .unwrap()
}

fn plan(value: &Value, php: &str, state: &TargetState) -> Result<String, Vec<Refusal>> {
    let inventory = decode_migration_inventory(&serde_json::to_vec(value).unwrap()).unwrap();
    plan_migration(&inventory, &request(php), &profile(), state).map(|plan| render_dry_run(&plan))
}

fn refusals(value: &Value, php: &str, state: &TargetState) -> Vec<Refusal> {
    plan(value, php, state).expect_err("the planner must refuse")
}

#[test]
fn complete_inventory_plans_the_five_steps_in_order() {
    let inventory = decode_migration_inventory(&serde_json::to_vec(&inventory()).unwrap()).unwrap();
    let plan = plan_migration(&inventory, &request("8.2"), &profile(), &empty_state()).unwrap();
    let kinds: Vec<&str> = plan
        .steps()
        .iter()
        .map(|step| match step {
            Step::Provision { .. } => "provision",
            Step::ImportFiles { .. } => "files",
            Step::ImportDatabase { .. } => "database",
            Step::RotateDatabaseCredentials => "credentials",
            Step::ChangeHostname { .. } => "rename",
            Step::SandboxCheckAndProbe => "probe",
        })
        .collect();
    assert_eq!(
        kinds,
        ["provision", "files", "database", "credentials", "probe"]
    );
    assert_eq!(plan.php_change(), None);
    let text = render_dry_run(&plan);
    for wanted in [
        "Dry run: nothing changes",
        "blog.example.test",
        "import_v1",
        "4200 entries",
        DIGEST,
        "No DNS record changes",
        "No mail setting changes",
        "2 mail accounts stay on the incumbent",
        "1 cron entries",
    ] {
        assert!(text.contains(wanted), "{wanted} absent from:\n{text}");
    }
}

/// D-070: a requested hostname other than the source's adds the rename step
/// before the probe; the target hostname, not the source's, must be free;
/// the source URLs still must be the source hostname at the root.
#[test]
fn a_requested_hostname_renames_the_site() {
    let inventory = decode_migration_inventory(&serde_json::to_vec(&inventory()).unwrap()).unwrap();
    let renamed: MigrationRequest = serde_json::from_value(
        json!({"site_id": "blog", "target_php": "8.2", "hostname": "copy.example.net"}),
    )
    .unwrap();
    let plan = plan_migration(&inventory, &renamed, &profile(), &empty_state()).unwrap();
    assert_eq!(plan.hostname().as_str(), "copy.example.net");
    assert_eq!(
        plan.source_hostname().map(|h| h.as_str()),
        Some("blog.example.test")
    );
    let tail: Vec<_> = plan.steps().iter().rev().take(2).collect();
    assert!(matches!(tail[0], Step::SandboxCheckAndProbe));
    assert!(matches!(tail[1], Step::ChangeHostname { from, to }
        if from.as_str() == "blog.example.test" && to.as_str() == "copy.example.net"));
    let text = render_dry_run(&plan);
    for wanted in [
        "Site blog for copy.example.net.\n",
        "Hostname changes from blog.example.test to copy.example.net: sign a site_import plan of schema 2 with source_hostname blog.example.test.\n",
        "replace //blog.example.test with //copy.example.net in the site's database",
    ] {
        assert!(text.contains(wanted), "{wanted} absent from:\n{text}");
    }
    // The same hostname is no rename.
    let same: MigrationRequest = serde_json::from_value(
        json!({"site_id": "blog", "target_php": "8.2", "hostname": "blog.example.test"}),
    )
    .unwrap();
    let plan = plan_migration(&inventory, &same, &profile(), &empty_state()).unwrap();
    assert_eq!(plan.source_hostname(), None);
    assert!(!render_dry_run(&plan).contains("Hostname changes"));
    // Only the served hostname must be free on the target.
    let state = |host: &str| -> TargetState {
        serde_json::from_value(
            json!({"site_ids": [], "hostnames": [host], "accounts": [], "databases": []}),
        )
        .unwrap()
    };
    assert!(
        plan_migration(
            &inventory,
            &renamed,
            &profile(),
            &state("blog.example.test")
        )
        .is_ok()
    );
    assert_eq!(
        plan_migration(&inventory, &renamed, &profile(), &state("copy.example.net")).err(),
        Some(vec![Refusal::HostnameExists])
    );
}

#[test]
fn every_unknown_required_field_refuses_as_incomplete() {
    let fields = [
        ("source_profile", Field::SourceProfile),
        ("hostname", Field::Hostname),
        ("declared_hostname", Field::DeclaredHostname),
        ("aliases", Field::Aliases),
        ("child_domains", Field::ChildDomains),
        ("files", Field::Files),
        ("uploads", Field::Uploads),
        ("databases", Field::Databases),
        ("php_version", Field::PhpVersion),
        ("php_extensions", Field::PhpExtensions),
        ("site_url", Field::SiteUrl),
        ("home_url", Field::HomeUrl),
        ("cron_entries", Field::CronEntries),
        ("tls", Field::Tls),
        ("credentials", Field::Credentials),
        ("dns", Field::Dns),
        ("dns_records", Field::DnsRecords),
        ("mail", Field::Mail),
        ("mail_accounts", Field::MailAccounts),
        ("api_consumers", Field::ApiConsumers),
    ];
    for (name, field) in fields {
        let mut value = inventory();
        value[name] = json!("unknown");
        let found = refusals(&value, "8.2", &empty_state());
        assert!(
            found.contains(&Refusal::Unknown(field)),
            "{name}: {found:?}"
        );
    }
}

#[test]
fn a_field_from_the_wrong_source_refuses() {
    let mut value = inventory();
    value["files"] = json!({"declared": value["files"]["observed"].clone()});
    value["php_extensions"] = json!({"observed": ["curl"]});
    let found = refusals(&value, "8.2", &empty_state());
    assert!(found.contains(&Refusal::WrongSource(Field::Files)));
    assert!(found.contains(&Refusal::WrongSource(Field::PhpExtensions)));
}

#[test]
fn contradictions_between_facts_refuse() {
    let mut value = inventory();
    value["declared_hostname"] = json!({"declared": "shop.example.test"});
    value["uploads"] = json!({"observed": {"files": 5000, "bytes": 60_000_000}});
    let found = refusals(&value, "8.2", &empty_state());
    assert!(found.contains(&Refusal::HostnameContradiction));
    assert!(found.contains(&Refusal::UploadsExceedFiles));
}

#[test]
fn every_target_conflict_is_reported_together() {
    let state: TargetState = serde_json::from_value(json!({
        "site_ids": ["blog"],
        "hostnames": ["blog.example.test"],
        "accounts": ["rs_blog"],
        "databases": ["rs_blog"]
    }))
    .unwrap();
    let found = refusals(&inventory(), "8.2", &state);
    for refusal in [
        Refusal::SiteExists,
        Refusal::HostnameExists,
        Refusal::AccountExists,
        Refusal::DatabaseExists,
    ] {
        assert!(found.contains(&refusal), "{refusal:?} absent: {found:?}");
    }
}

#[test]
fn unsafe_archive_entries_refuse() {
    let mut value = inventory();
    value["files"]["observed"]["unsafe_entries"] = json!(1);
    assert!(refusals(&value, "8.2", &empty_state()).contains(&Refusal::UnsafeEntries));
}

#[test]
fn the_first_slice_refuses_aliases_child_domains_and_more_databases() {
    let mut value = inventory();
    value["aliases"] = json!({"observed": ["www.blog.example.test"]});
    value["child_domains"] = json!({"observed": 1});
    let dump = value["databases"]["observed"][0].clone();
    value["databases"] = json!({"observed": [dump.clone(), dump]});
    let found = refusals(&value, "8.2", &empty_state());
    assert!(found.contains(&Refusal::AliasesUnsupported));
    assert!(found.contains(&Refusal::ChildDomainsUnsupported));
    assert!(found.contains(&Refusal::DatabaseCount));
}

/// D-074: an export with no database is a static site: no URLs are needed,
/// the plan has no database steps, and it keeps its hostname.
#[test]
fn a_static_site_plans_without_database_steps() {
    let mut value = inventory();
    value["databases"] = json!({"observed": []});
    value["site_url"] = json!("unknown");
    value["home_url"] = json!("unknown");
    let inventory = decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).unwrap();
    let plan = plan_migration(&inventory, &request("8.2"), &profile(), &empty_state()).unwrap();
    assert!(matches!(
        plan.steps(),
        [
            Step::Provision { .. },
            Step::ImportFiles { .. },
            Step::SandboxCheckAndProbe
        ]
    ));
    let text = render_dry_run(&plan);
    assert!(text.contains("import_static_v1"), "{text}");
    assert!(!text.contains("dump"), "{text}");
    let renamed: MigrationRequest = serde_json::from_value(
        json!({"site_id": "blog", "target_php": "8.2", "hostname": "copy.example.net"}),
    )
    .unwrap();
    assert_eq!(
        plan_migration(&inventory, &renamed, &profile(), &empty_state()).unwrap_err(),
        [Refusal::StaticHostnameChange]
    );
    // An unknown database list is still incomplete, never static.
    value["databases"] = json!("unknown");
    assert!(refusals(&value, "8.2", &empty_state()).contains(&Refusal::Unknown(Field::Databases)));
}

#[test]
fn a_url_change_or_a_path_install_refuses() {
    for (field, name, url) in [
        (Field::SiteUrl, "site_url", "https://other.example.test"),
        (Field::HomeUrl, "home_url", "https://blog.example.test/blog"),
        (Field::SiteUrl, "site_url", "ftp://blog.example.test"),
        (
            Field::HomeUrl,
            "home_url",
            "https://blog.example.test.evil.test",
        ),
    ] {
        let mut value = inventory();
        value[name] = json!({ "observed": url });
        let found = refusals(&value, "8.2", &empty_state());
        assert!(
            found.contains(&Refusal::UrlChange(field)),
            "{url}: {found:?}"
        );
    }
}

#[test]
fn php_is_checked_against_the_target_profile() {
    let mut value = inventory();
    value["php_extensions"] = json!({"declared": ["curl", "imagick"]});
    let found = refusals(&value, "8.2", &empty_state());
    assert!(found.iter().any(
        |refusal| matches!(refusal, Refusal::MissingExtension(name) if name.as_str() == "imagick")
    ));

    assert!(
        refusals(&inventory(), "7.4", &empty_state()).contains(&Refusal::PhpVersionUnavailable)
    );

    let inventory = decode_migration_inventory(&serde_json::to_vec(&inventory()).unwrap()).unwrap();
    let plan = plan_migration(&inventory, &request("8.3"), &profile(), &empty_state()).unwrap();
    let change = plan.php_change().expect("a version change is stated");
    assert_eq!((change.0.as_str(), change.1.as_str()), ("8.2", "8.3"));
    assert!(render_dry_run(&plan).contains("PHP changes from 8.2 to 8.3"));
}

#[test]
fn decoding_refuses_open_shapes_and_oversized_input() {
    let mut value = inventory();
    value["user_password"] = json!("x");
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = inventory();
    value["credentials"]["observed"]["password_hash"] = json!("x");
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = inventory();
    value["schema_version"] = json!(2);
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = inventory();
    value["php_version"] = json!({"observed": "8.2; rm"});
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut value = inventory();
    value["aliases"] = json!({"observed": vec!["a.example.test"; 65]});
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut big = serde_json::to_vec(&inventory()).unwrap();
    big.resize(70 * 1024, b' ');
    assert!(decode_migration_inventory(&big).is_err());
}

#[test]
fn the_render_escapes_operator_text() {
    let mut value = inventory();
    value["dns"]["declared"]["authority"] = json!("registrar\u{202e}txet\u{1b}[2J");
    let text = plan(&value, "8.2", &empty_state()).unwrap();
    assert!(
        !text.contains('\u{202e}') && !text.contains('\u{1b}'),
        "{text}"
    );
    assert!(text.contains("\\u{202e}"));
}

#[test]
fn a_fact_holds_exactly_one_source() {
    let mut value = inventory();
    value["php_version"] = json!({"observed": "8.2", "declared": "8.3"});
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());
    value["php_version"] = json!({});
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());
    value["php_version"] = json!(null);
    assert!(decode_migration_inventory(&serde_json::to_vec(&value).unwrap()).is_err());
}
