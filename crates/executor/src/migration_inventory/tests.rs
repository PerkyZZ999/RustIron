//! Local export fixtures only: no archive extraction, no SQL or PHP execution,
//! and no network. The secret strings below must never reach a report.
use super::*;
use rustiron_contracts::migration::{TlsObservation, decode_export_observation};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

const PANEL_HASH: &str = "SECRET-PANEL-HASH-6d1f";
const TOKEN: &str = "SECRET-API-TOKEN-91ab";
const DB_HASH: &str = "SECRET-DB-HASH-03c2";
const MAIL_HASH: &str = "SECRET-MAIL-HASH-77e0";

fn meta_xml(extra: &str) -> String {
    format!(
        "<?xml version=\"1.0\" ?>\n<metaFile>\n  <VERSION>2.4</VERSION>\n  <masterDomain>blog.example.test</masterDomain>\n  \
         <phpSelection>PHP 8.2</phpSelection>\n  <userName>admin</userName>\n  <userPassword>{PANEL_HASH}</userPassword>\n  \
         <token>{TOKEN}</token>\n  <ChildDomains/>\n  <Databases>\n    <database>\n      <dbName>blog_wp</dbName>\n      \
         <databaseUsers><dbUser>blog_u</dbUser><dbHost>localhost</dbHost><password>{DB_HASH}</password></databaseUsers>\n    \
         </database>\n  </Databases>\n  <Aliases/>\n  <dnsrecords>\n    <dnsrecord><type>A</type><name>blog.example.test</name>\
         <content>192.0.2.10</content><priority>0</priority></dnsrecord>\n    <dnsrecord><type>MX</type><name>blog.example.test</name>\
         <content>mail.example.test</content><priority>10</priority></dnsrecord>\n  </dnsrecords>\n  <emails>\n    \
         <emailAccount><email>a@blog.example.test</email><password>{MAIL_HASH}</password></emailAccount>\n  </emails>\n{extra}</metaFile>\n"
    )
}

const DUMP: &str = "-- MySQL dump 10.13\n/*!40101 SET NAMES utf8mb4 */;\n\
    CREATE TABLE `wp_options` (\n  `option_id` bigint unsigned NOT NULL AUTO_INCREMENT,\n  PRIMARY KEY (`option_id`)\n) \
    ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_520_ci;\n\
    INSERT INTO `wp_options` VALUES (1,'siteurl','https://blog.example.test','yes'),(2,'home','https://blog.example.test','yes');\n";

/// `<base>/export/{meta.xml,blog_wp.sql,public_html/...}`.
struct Export(PathBuf, PathBuf);

impl Export {
    fn new() -> Self {
        assert_ne!(rustix::process::geteuid().as_raw(), 0);
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!(
            "ri-migration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&base)
            .unwrap();
        let root = base.join("export");
        let uploads = root.join("public_html/public_html/wp-content/uploads/2026");
        std::fs::create_dir_all(&uploads).unwrap();
        std::fs::write(
            root.join("public_html/public_html/index.php"),
            b"<?php // fixture\n",
        )
        .unwrap();
        std::fs::write(uploads.join("a.jpg"), b"0123456789").unwrap();
        std::fs::create_dir(root.join("vmail")).unwrap();
        std::fs::write(root.join("vmail/mailbox"), b"never read").unwrap();
        let export = Self(root, base);
        export.write("meta.xml", &meta_xml(""));
        export.write("blog_wp.sql", DUMP);
        export
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.0.join(name), text).unwrap();
    }

    fn run(&self) -> ExportObservation {
        self.run_with(&Limits::default())
    }

    fn run_with(&self, limits: &Limits) -> ExportObservation {
        observe(&self.0, limits, identity())
    }
}

impl Drop for Export {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.1).unwrap();
    }
}

fn stopped(observation: &ExportObservation) -> Option<ExportReason> {
    assert_eq!(
        *observation,
        ExportObservation::stopped(observation.status, observation.reason.unwrap())
    );
    observation.reason
}

#[test]
fn a_complete_export_is_observed_without_its_secrets() {
    let export = Export::new();
    let observation = export.run();
    assert_eq!(
        observation.status,
        ExportStatus::Complete,
        "{observation:?}"
    );
    assert_eq!(
        observation.hostname.as_ref().unwrap().as_str(),
        "blog.example.test"
    );
    assert_eq!(observation.php_version.as_ref().unwrap().as_str(), "8.2");
    assert_eq!(observation.aliases, Some(vec![]));
    assert_eq!(observation.child_domains, Some(0));
    let files = observation.files.as_ref().unwrap();
    // public_html, wp-content, uploads, 2026, index.php, a.jpg
    assert_eq!((files.entries, files.unsafe_entries), (6, 0));
    assert_eq!(files.bytes, 17 + 10);
    let uploads = observation.uploads.as_ref().unwrap();
    assert_eq!((uploads.files, uploads.bytes), (1, 10));
    let dump = &observation.databases.as_ref().unwrap()[0];
    assert_eq!(dump.bytes, DUMP.len() as u64);
    assert_eq!(dump.charset.as_str(), "utf8mb4");
    assert_eq!(dump.collation.as_str(), "utf8mb4_unicode_520_ci");
    assert_eq!(
        observation.site_url.as_ref().unwrap().as_str(),
        "https://blog.example.test"
    );
    assert_eq!(
        observation.home_url.as_ref().unwrap().as_str(),
        "https://blog.example.test"
    );
    let credentials = observation.credentials.as_ref().unwrap();
    assert_eq!(
        (
            credentials.database_users,
            credentials.panel_users,
            credentials.api_tokens
        ),
        (1, 1, 1)
    );
    assert_eq!(observation.dns_records, Some(2));
    assert_eq!(observation.mail_accounts, Some(1));
    assert_eq!(
        observation.tls,
        Some(TlsObservation::None),
        "no certificate files"
    );

    let bytes = serde_json::to_vec(&observation).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    for secret in [PANEL_HASH, TOKEN, DB_HASH, MAIL_HASH, "never read"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
    assert_eq!(decode_export_observation(&bytes).unwrap(), observation);
}

#[test]
fn the_manifest_follows_content_and_paths() {
    let export = Export::new();
    let first = export.run().files.unwrap().manifest_sha256;
    assert_eq!(export.run().files.unwrap().manifest_sha256, first, "stable");
    std::fs::write(
        export.0.join("public_html/public_html/index.php"),
        b"<?php // fixturE\n",
    )
    .unwrap();
    let changed = export.run().files.unwrap().manifest_sha256;
    assert_ne!(changed, first, "one content byte");
    std::fs::rename(
        export.0.join("public_html/public_html/index.php"),
        export.0.join("public_html/public_html/index2.php"),
    )
    .unwrap();
    assert_ne!(
        export.run().files.unwrap().manifest_sha256,
        changed,
        "one path"
    );
}

#[test]
fn links_special_and_privileged_entries_are_counted_not_followed() {
    let export = Export::new();
    let site = export.0.join("public_html/public_html");
    std::os::unix::fs::symlink("/etc/shadow", site.join("link")).unwrap();
    std::fs::write(site.join("one"), b"x").unwrap();
    std::fs::hard_link(site.join("one"), site.join("two")).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        site.join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    std::fs::write(site.join("suid"), b"x").unwrap();
    std::fs::set_permissions(site.join("suid"), std::fs::Permissions::from_mode(0o4755)).unwrap();
    std::fs::create_dir(site.join("sgid")).unwrap();
    std::fs::write(site.join("sgid/inside"), b"x").unwrap();
    std::fs::set_permissions(site.join("sgid"), std::fs::Permissions::from_mode(0o2755)).unwrap();
    let observation = export.run();
    let files = observation.files.unwrap();
    // link, one, two (two links), fifo, suid, sgid; `inside` is never seen.
    assert_eq!(files.unsafe_entries, 6, "{files:?}");
    assert_eq!(files.entries, 6 + 6);
}

#[test]
fn a_missing_meta_or_tree_is_unsupported() {
    let export = Export::new();
    std::fs::remove_file(export.0.join("meta.xml")).unwrap();
    assert_eq!(stopped(&export.run()), Some(ExportReason::Unsupported));

    let export = Export::new();
    std::fs::remove_dir_all(export.0.join("public_html")).unwrap();
    assert_eq!(stopped(&export.run()), Some(ExportReason::Unsupported));

    let export = Export::new();
    std::fs::remove_file(export.0.join("meta.xml")).unwrap();
    std::os::unix::fs::symlink(export.1.join("elsewhere.xml"), export.0.join("meta.xml")).unwrap();
    assert_eq!(stopped(&export.run()), Some(ExportReason::Unsupported));
}

#[test]
fn hostile_metadata_stops_the_worker() {
    for meta in [
        "<!DOCTYPE metaFile [<!ENTITY x \"y\">]>".to_owned() + &meta_xml(""),
        meta_xml("<masterDomain>second.example.test</masterDomain>"),
        meta_xml("").replace("blog_wp</dbName>", "blog/../x</dbName>"),
        meta_xml("").replace(
            "<masterDomain>blog.example.test",
            "<masterDomain>blog&#46;example.test",
        ),
        meta_xml("")
            .replace("<metaFile>", "<other>")
            .replace("</metaFile>", "</other>"),
        meta_xml("").replace("</metaFile>\n", ""),
        meta_xml("<Aliases><alias>Not A Host</alias></Aliases>"),
        meta_xml("").replace("<phpSelection>PHP 8.2</phpSelection>", ""),
        "x".repeat(meta::MAX_META_BYTES + 1),
    ] {
        let export = Export::new();
        export.write("meta.xml", &meta);
        assert_eq!(
            stopped(&export.run()),
            Some(ExportReason::Metadata),
            "{}",
            &meta[..meta.len().min(120)]
        );
    }
}

/// D-074: no database and no wp-config.php is a static site (no dumps);
/// a wp-config.php without a database leaves the databases unknown.
#[test]
fn an_export_without_a_database_is_static_only_without_wp_config() {
    let export = Export::new();
    let meta = meta_xml("");
    let start = meta.find("<Databases>").unwrap();
    let end = meta.find("</Databases>").unwrap() + "</Databases>".len();
    export.write(
        "meta.xml",
        &format!("{}<Databases/>{}", &meta[..start], &meta[end..]),
    );
    std::fs::remove_file(export.0.join("blog_wp.sql")).unwrap();
    let observation = export.run();
    assert_eq!(observation.status, ExportStatus::Complete);
    assert_eq!(observation.databases, Some(Vec::new()));
    assert_eq!(observation.site_url, None);
    export.write(
        "public_html/public_html/wp-config.php",
        "<?php // fixture\n",
    );
    assert_eq!(export.run().databases, None);
}

#[test]
fn unreadable_facts_stay_unknown() {
    let export = Export::new();
    std::fs::remove_file(export.0.join("blog_wp.sql")).unwrap();
    std::fs::write(export.0.join("blog_wp.sql.gz"), b"compressed").unwrap();
    let observation = export.run();
    assert_eq!(observation.status, ExportStatus::Complete);
    assert_eq!(observation.databases, None);
    assert_eq!(observation.site_url, None);

    let export = Export::new();
    export.write(
        "blog_wp.sql",
        &format!(
            "{DUMP}INSERT INTO `wp_posts` VALUES (9,'siteurl','https://other.example.test');\n"
        ),
    );
    export.write("meta.xml", &meta_xml("").replace("PHP 8.2", "PHP eight"));
    let observation = export.run();
    assert_eq!(observation.site_url, None, "two different values");
    assert!(observation.home_url.is_some());
    assert_eq!(observation.php_version, None);
    assert!(observation.databases.is_some());
}

#[test]
fn a_url_across_a_read_chunk_edge_is_found() {
    // The dump without its URL row, then a row whose marker starts four bytes
    // before the first 256 KiB read ends, and a value that ends after it.
    let header = &DUMP[..DUMP.find("INSERT").unwrap()];
    let row = "(3,'siteurl','https://blog.example.test','yes');\n";
    let marker = row.find("'siteurl'").unwrap();
    for edge_offset in [4, 11, 20] {
        let padding = 256 * 1024 - edge_offset - header.len() - marker - 1;
        let text = format!("{header}{}\n{row}", "-".repeat(padding));
        assert_eq!(text.find("'siteurl'").unwrap(), 256 * 1024 - edge_offset);
        let export = Export::new();
        export.write("blog_wp.sql", &text);
        let observation = export.run();
        assert_eq!(
            observation
                .site_url
                .map(|url| url.as_str().to_owned())
                .as_deref(),
            Some("https://blog.example.test"),
            "marker {edge_offset} bytes before the edge"
        );
        assert_eq!(observation.home_url, None);
    }
}

#[test]
fn limits_and_identity_stop_the_worker() {
    let export = Export::new();
    let few = Limits {
        entries: 3,
        ..Limits::default()
    };
    let observation = export.run_with(&few);
    assert_eq!(
        (observation.status, stopped(&observation)),
        (ExportStatus::Limit, Some(ExportReason::Entries))
    );
    let shallow = Limits {
        depth: 1,
        ..Limits::default()
    };
    assert_eq!(
        stopped(&export.run_with(&shallow)),
        Some(ExportReason::Depth)
    );
    let none = Limits {
        time: Duration::ZERO,
        ..Limits::default()
    };
    assert_eq!(stopped(&export.run_with(&none)), Some(ExportReason::Time));

    let observation = observe(&export.0, &Limits::default(), (0, 0));
    assert_eq!(
        (observation.status, stopped(&observation)),
        (ExportStatus::Error, Some(ExportReason::Identity))
    );
    let (real, _) = identity();
    assert_eq!(
        stopped(&observe(&export.0, &Limits::default(), (real, real + 1))),
        Some(ExportReason::Identity)
    );
    assert_eq!(
        stopped(&observe(
            Path::new("relative/export"),
            &Limits::default(),
            identity()
        )),
        Some(ExportReason::Unsupported)
    );
}

/// Public test certificates made with OpenSSL 4.1.0 for W436; the keys were
/// deleted. `LEAF_UTC` expires 2027-01-01T00:00:00Z (UTCTime) and its issuer
/// has a common name. `LEAF_GENERALIZED` expires 2051-06-15T12:30:45Z
/// (GeneralizedTime) and its issuer has only an organization.
const LEAF_UTC: &str = "-----BEGIN CERTIFICATE-----\nMIIBmTCCAUCgAwIBAgIUTW8MhOrkPDz2Sskr/jUVFgzCJc4wCgYIKoZIzj0EAwIw\nOjEZMBcGA1UECgwQUnVzdGlyb24gVGVzdCBDQTEdMBsGA1UEAwwUUnVzdGlyb24g\nVGVzdCBJc3N1ZXIwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjAcMRow\nGAYDVQQDDBFibG9nLmV4YW1wbGUudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABALAj/a/Qc+jrRqV4iHunSerQPoFzBN8uAT3UafPi7GfeM+NCDebzpqTd/jo\nESSUGX2rn4/NgXHTPU2NUlC1rwSjQjBAMB0GA1UdDgQWBBSwNNv2kpQy8bMHPfEH\nX1zvHMzwVjAfBgNVHSMEGDAWgBQzsyEgd+oFOmwqY8slx0NhIgUm1TAKBggqhkjO\nPQQDAgNHADBEAiAxLO97Mv1A5rAk2Lw/gT9KXJF83Xf9hoaUahWesgq2HAIgUoAz\nn4FkZs2ihiGz6zaNV9F0/3qiPBsR3Eow6PM4AZc=\n-----END CERTIFICATE-----\n";
const LEAF_GENERALIZED: &str = "-----BEGIN CERTIFICATE-----\nMIIBfzCCASSgAwIBAgIUF6j1pG7WCsbJ4VMjrxs6RXHu10UwCgYIKoZIzj0EAwIw\nHDEaMBgGA1UECgwRUnVzdGlyb24gVGVzdCBPcmcwIBcNMjYwMTAxMDAwMDAwWhgP\nMjA1MTA2MTUxMjMwNDVaMBwxGjAYBgNVBAMMEWJsb2cuZXhhbXBsZS50ZXN0MFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJ2oEuFcsRthEe121HOfbE3cVCBcEpm5\n118QA07ptnreaJCE1Mm0+mvwB5sXxE26p2JbkFSo+edgLICcDnoQRaNCMEAwHQYD\nVR0OBBYEFIf82g1MhBSzhwKqoMHOOG6/hDwXMB8GA1UdIwQYMBaAFBYptHbEUYZN\n1Sw/HZdVggLJLXx0MAoGCCqGSM49BAMCA0kAMEYCIQC7LAAVcvsJl3ECG7y+MC+V\n7tfkDgW5VMvDkNpuUxxilAIhAKwQQ3ra2p/+qMOM40Gn+HCqqnYWBjQaD45b6G7v\nXuG6\n-----END CERTIFICATE-----\n";
const ISSUER_GENERALIZED: &str = "-----BEGIN CERTIFICATE-----\nMIIBbDCCARKgAwIBAgIUBnrKJOxiYaSPqEXBU02vXEvh8PAwCgYIKoZIzj0EAwIw\nHDEaMBgGA1UECgwRUnVzdGlyb24gVGVzdCBPcmcwHhcNMjYxMTE2MTE1NDQ4WhcN\nMzYxMTEzMTE1NDQ4WjAcMRowGAYDVQQKDBFSdXN0aXJvbiBUZXN0IE9yZzBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABC2q0/p2x0if9yyodqu2EqV2q+e5aIdHloQv\nKjKpGzTbne7XF3wrZ/Q6fg4ziRxjFWEAwJC4bSgw/7oTHlDSZpCjMjAwMB0GA1Ud\nDgQWBBQWKbR2xFGGTdUsPx2XVYICyS18dDAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\nSM49BAMCA0gAMEUCICgvEMPkX8F7v/TSE7Byms4D9McyhrXIwF93fxlB6vtLAiEA\n9nlcfEt5+SAWoEHK4o/DVHwHRpkTgz0pSrFgjN26jKw=\n-----END CERTIFICATE-----\n";

fn certificate(observation: &ExportObservation) -> (String, String, u64) {
    match observation.tls.as_ref().expect("a certificate observation") {
        TlsObservation::Certificate(tls) => (
            tls.subject.as_str().to_owned(),
            tls.issuer.as_str().to_owned(),
            tls.not_after.get(),
        ),
        TlsObservation::None => panic!("no certificate observed"),
    }
}

#[test]
fn the_leaf_certificate_is_read_and_the_key_never_opened() {
    let export = Export::new();
    export.write("blog.example.test.cert.pem", LEAF_UTC);
    export.write(
        "blog.example.test.fullchain.pem",
        &format!("{LEAF_GENERALIZED}{ISSUER_GENERALIZED}"),
    );
    export.write("blog.example.test.privkey.pem", "SECRET-PRIVATE-KEY");
    std::fs::set_permissions(
        export.0.join("blog.example.test.privkey.pem"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    let observation = export.run();
    assert_eq!(
        certificate(&observation),
        (
            "blog.example.test".to_owned(),
            "Rustiron Test Issuer".to_owned(),
            1_798_761_600
        )
    );
    let text = serde_json::to_string(&observation).unwrap();
    assert!(!text.contains("SECRET-PRIVATE-KEY"));

    std::fs::remove_file(export.0.join("blog.example.test.cert.pem")).unwrap();
    assert_eq!(
        certificate(&export.run()),
        (
            "blog.example.test".to_owned(),
            "Rustiron Test Org".to_owned(),
            2_570_445_045
        ),
        "the first certificate of the full chain"
    );
}

#[test]
fn an_unreadable_certificate_stays_unknown() {
    let export = Export::new();
    export.write("blog.example.test.privkey.pem", "key");
    assert_eq!(export.run().tls, None, "a key without a certificate");

    let truncated = &LEAF_UTC[..LEAF_UTC.len() / 2];
    for pem in [
        "not a certificate".to_owned(),
        format!("{truncated}\n-----END CERTIFICATE-----\n"),
        LEAF_UTC.replace('A', "*"),
        "x".repeat(64 * 1024 + 1),
    ] {
        let export = Export::new();
        export.write("blog.example.test.cert.pem", &pem);
        let observation = export.run();
        assert_eq!(observation.status, ExportStatus::Complete);
        assert_eq!(observation.tls, None, "{}", &pem[..pem.len().min(40)]);
    }
}

#[test]
fn a_synthetic_export_with_a_certificate_plans_a_move() {
    use rustiron_contracts::migration::{
        MigrationRequest, TargetProfile, TargetState, assemble_inventory,
        decode_operator_declaration, plan_migration, render_dry_run,
    };
    let export = Export::new();
    export.write("blog.example.test.fullchain.pem", LEAF_UTC);
    let observation = export.run();
    let declaration = decode_operator_declaration(
        br#"{"schema_version":1,
        "source_profile":{"os":"AlmaLinux 9.6","panel":"CyberPanel 2.4","web_server":"OpenLiteSpeed 1.8"},
        "hostname":"blog.example.test","php_extensions":["mysqli"],"cron_entries":0,
        "dns":{"authority":"registrar DNS","addresses":["192.0.2.10"]},
        "mail":{"mx":1,"spf":true,"dkim":false,"dmarc":false,"outbound":"provider relay"},
        "api_consumers":0}"#,
    )
    .unwrap();
    let inventory = assemble_inventory(&observation, &declaration).unwrap();
    let request: MigrationRequest =
        serde_json::from_str(r#"{"site_id":"blog","target_php":"8.2"}"#).unwrap();
    let profile: TargetProfile =
        serde_json::from_str(r#"{"php_versions":["8.2"],"php_extensions":["mysqli"]}"#).unwrap();
    let state: TargetState =
        serde_json::from_str(r#"{"site_ids":[],"hostnames":[],"accounts":[],"databases":[]}"#)
            .unwrap();
    let plan = plan_migration(&inventory, &request, &profile, &state).unwrap();
    let text = render_dry_run(&plan);
    assert!(
        text.contains("TLS: blog.example.test from Rustiron Test Issuer, expires at 1798761600"),
        "{text}"
    );
    assert!(
        text.contains("1 mail accounts stay on the incumbent"),
        "{text}"
    );
}

/// W447 (found on the product host): the site root is `drwxr-x--x root`, so
/// the site account may traverse it but not read it. The walk must not need
/// to read an ancestor of the export folder.
#[test]
fn a_traverse_only_ancestor_does_not_stop_the_worker() {
    let export = Export::new();
    std::fs::set_permissions(&export.1, std::fs::Permissions::from_mode(0o100)).unwrap();
    let observation = export.run();
    std::fs::set_permissions(&export.1, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        observation.status,
        ExportStatus::Complete,
        "{observation:?}"
    );
}

/// W448: the tree mode gives the same manifest for the same folder content
/// at two places, and another one after one byte changes.
#[test]
fn the_tree_mode_compares_two_folders_by_content() {
    let export = Export::new();
    let docroot = export.0.join("public_html/public_html");
    let copy = export.1.join("copy");
    std::fs::create_dir_all(copy.join("wp-content/uploads/2026")).unwrap();
    for file in ["index.php", "wp-content/uploads/2026/a.jpg"] {
        std::fs::copy(docroot.join(file), copy.join(file)).unwrap();
    }
    let one = tree_report(&docroot, &Limits::default(), identity());
    let two = tree_report(&copy, &Limits::default(), identity());
    assert_eq!(one.status, ExportStatus::Complete);
    assert_eq!(one.files, two.files);
    std::fs::write(copy.join("index.php"), b"changed").unwrap();
    let three = tree_report(&copy, &Limits::default(), identity());
    assert_ne!(
        one.files.unwrap().manifest_sha256,
        three.files.unwrap().manifest_sha256
    );
    assert_eq!(
        tree_report(&copy, &Limits::default(), (0, 0)).reason,
        Some(ExportReason::Identity)
    );
    assert_eq!(
        tree_report(&export.1.join("missing"), &Limits::default(), identity()).reason,
        Some(ExportReason::Io)
    );
}
