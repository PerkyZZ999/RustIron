//! Lab OLS drift checks that need no host: parent review, WebAdmin listener
//! table parsing and the generation explanation rules.

use rustiron_contracts::{Id, approval::Sha256Digest};
use rustiron_executor::ols::{
    DriftReport, file_is_pinned, generation_id, generation_refusal, listening, ols_workers,
    parent_is_reviewed,
};
use sha2::{Digest, Sha256};

const PARENT: &str = "serverName\nuser nobody\ndisableWebAdmin                  1\nindexFiles index.php\n\ntuning{\n    maxConnections               10000\n    connTimeout                  60\n    maxReqBodySize               64M\n}\n\nperClientConnLimit{\n    softLimit                                15\n    hardLimit                                30\n    gracePeriod                              10\n    banPeriod                                60\n}\n\ninclude /etc/rustiron-ols/current/*.conf\n";

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

#[test]
fn only_the_exact_reviewed_parent_passes() {
    let reviewed = sha(PARENT.as_bytes());
    assert!(parent_is_reviewed(PARENT.as_bytes(), &reviewed));
    let edited = PARENT.replace("indexFiles index.php", "indexFiles index.html");
    assert!(
        !parent_is_reviewed(edited.as_bytes(), &reviewed),
        "any byte change is drift"
    );
    for changed in [
        PARENT.replace("disableWebAdmin                  1", "disableWebAdmin 0"),
        PARENT.replace(
            "include /etc/rustiron-ols/current/*.conf",
            "include /tmp/x/*.conf",
        ),
        format!("{PARENT}include /etc/other/*.conf\n"),
        format!("{PARENT}disableWebAdmin 1\n"),
        PARENT.replace("include /etc/rustiron-ols/current/*.conf\n", ""),
    ] {
        assert!(
            !parent_is_reviewed(changed.as_bytes(), &sha(changed.as_bytes())),
            "even a re-enrolled digest cannot approve: {changed:?}"
        );
    }
}

/// D-028 item 1 (W338): the reviewed parent carries the server limits, each
/// once and in its own block; a re-enrolled digest cannot approve a parent
/// that drops, loosens, duplicates, or moves one.
#[test]
fn the_reviewed_parent_carries_the_d028_limits() {
    for changed in [
        PARENT.replace("    connTimeout                  60\n", ""),
        PARENT.replace("connTimeout                  60", "connTimeout 300"),
        PARENT.replace("maxReqBodySize               64M", "maxReqBodySize 2047M"),
        PARENT.replace(
            "softLimit                                15",
            "softLimit 50",
        ),
        PARENT.replace(
            "hardLimit                                30",
            "hardLimit 100",
        ),
        PARENT.replace(
            "gracePeriod                              10",
            "gracePeriod 15",
        ),
        PARENT.replace(
            "banPeriod                                60",
            "banPeriod 300",
        ),
        format!("{PARENT}tuning{{\n    maxReqBodySize 2047M\n}}\n"),
        PARENT.replace(
            "    maxReqBodySize               64M\n}\n\nperClientConnLimit{\n",
            "}\n\nperClientConnLimit{\n    maxReqBodySize 64M\n",
        ),
        PARENT.replace(
            "perClientConnLimit{\n    softLimit",
            "perClientConnLimit{\n    softLimit 50\n    softLimit",
        ),
    ] {
        assert!(
            !parent_is_reviewed(changed.as_bytes(), &sha(changed.as_bytes())),
            "limits must hold: {changed:?}"
        );
    }
    let spaced = PARENT.replace("tuning{", "tuning {");
    assert!(parent_is_reviewed(
        spaced.as_bytes(),
        &sha(spaced.as_bytes())
    ));
}

/// W348 (B01): the parent the product installer writes.
const SHIPPED_PARENT: &str = include_str!("../../../packaging/ols/httpd_config.conf");

/// W348 (B01, D-028 item 1): the shipped parent passes the review for its
/// own digest and fixes the worker count that the per-worker limits assume.
/// It defines nothing that serves: no listener, virtual host, or server-level
/// PHP application. It registers the cache module with storing off and
/// lookups on (D-028 item 2).
#[test]
fn the_shipped_product_parent_is_reviewed_for_its_own_digest() {
    let bytes = SHIPPED_PARENT.as_bytes();
    assert!(parent_is_reviewed(bytes, &sha(bytes)));
    assert_eq!(ols_workers(bytes, Some(16)), Some(4));
    assert_eq!(ols_workers(bytes, Some(1)), Some(4));
    let lines: Vec<String> = SHIPPED_PARENT
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    for word in [
        "listener",
        "virtualHost",
        "vhTemplate",
        "extprocessor",
        "scripthandler",
    ] {
        assert!(
            lines
                .iter()
                .all(|line| line.split(' ').next() != Some(word)),
            "the parent must not define {word}"
        );
    }
    let module: Vec<&str> = lines
        .iter()
        .skip_while(|line| line.as_str() != "module cache {")
        .skip(1)
        .take_while(|line| line.as_str() != "}")
        .map(String::as_str)
        .collect();
    for wanted in [
        "ls_enabled 1",
        "enableCache 0",
        "enablePrivateCache 0",
        "checkPublicCache 1",
        "checkPrivateCache 1",
    ] {
        assert!(module.contains(&wanted), "the cache module needs {wanted}");
    }
    let modules = lines.iter().filter(|line| line.starts_with("module "));
    assert_eq!(modules.count(), 1);
}

/// The list that OLS 1.9.4 keeps for `sslDefaultCiphers`, or `None` when
/// OLS ignores the value. A model of `SslUtil::setDefaultCipherList` and
/// `buildCipherList` (sslutil.cpp, tag v1.9.4): leading CHACHA20 suites are
/// skipped; if the list then starts with an ECDHE suite whose first
/// non-CHACHA20 entry names GCM, the function returns the input and the
/// stored default is NOT changed. Otherwise OLS stores the list with
/// `ECDHE-ECDSA-AES128-GCM-SHA256` and `ECDHE-RSA-AES128-GCM-SHA256`
/// inserted after the leading CHACHA20 suites. W390 measured the ignored
/// case: a list that starts with an ECDHE GCM suite left static RSA and CBC
/// suites accepted.
fn ols_default_cipher_list(value: &str) -> Option<Vec<String>> {
    let entries: Vec<&str> = value.split(':').collect();
    let lead = entries
        .iter()
        .take(entries.len().saturating_sub(1))
        .take_while(|entry| entry.to_ascii_lowercase().contains("chacha"))
        .count();
    let has_next_separator = lead + 1 < entries.len();
    let ignored = has_next_separator
        && value.len() >= 5
        && value[..5].eq_ignore_ascii_case("ECDHE")
        && entries[..=lead].join(":").contains("GCM");
    if ignored {
        return None;
    }
    let mut stored: Vec<String> = entries[..lead].iter().map(|s| (*s).to_owned()).collect();
    stored.push("ECDHE-ECDSA-AES128-GCM-SHA256".to_owned());
    stored.push("ECDHE-RSA-AES128-GCM-SHA256".to_owned());
    stored.extend(entries[lead..].iter().map(|s| (*s).to_owned()));
    Some(stored)
}

#[test]
fn the_ols_cipher_model_matches_the_w390_measurements() {
    // The first D-039 list: OLS ignored it (T1 rerun after the re-pin).
    assert_eq!(
        ols_default_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305"
        ),
        None
    );
    assert_eq!(
        ols_default_cipher_list("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"),
        Some(
            [
                "ECDHE-ECDSA-CHACHA20-POLY1305",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-CHACHA20-POLY1305",
            ]
            .map(str::to_owned)
            .to_vec()
        )
    );
}

/// W390 (D-039): every TLS listener inherits the server defaults unless it
/// sets its own. OLS 1.9.4 by default accepts TLS 1.2 suites with static RSA
/// key exchange and CBC, and opens an HTTP/3 (QUIC) socket that no campaign
/// has tested. The shipped parent limits the default TLS 1.2 suites to ECDHE
/// with an AEAD cipher and turns QUIC off at server scope.
#[test]
fn the_shipped_parent_sets_safe_tls_defaults_and_no_quic() {
    let lines: Vec<String> = SHIPPED_PARENT
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let tuning: Vec<&str> = lines
        .iter()
        .skip_while(|line| line.as_str() != "tuning {")
        .skip(1)
        .take_while(|line| line.as_str() != "}")
        .map(String::as_str)
        .collect();
    let value = |key: &str| {
        let found: Vec<&str> = tuning
            .iter()
            .filter_map(|line| line.strip_prefix(&format!("{key} ")))
            .collect();
        assert_eq!(found.len(), 1, "{key} once in tuning: {tuning:?}");
        found[0].to_owned()
    };
    assert_eq!(value("quicEnable"), "0");
    let ciphers = value("sslDefaultCiphers");
    let suites = ols_default_cipher_list(&ciphers)
        .expect("OLS 1.9.4 stores the list (W390 T1 rerun: an ignored list kept the OLS defaults)");
    assert!(suites.len() >= 4, "{suites:?}");
    for suite in &suites {
        assert!(suite.starts_with("ECDHE-"), "forward secrecy: {suite}");
        assert!(
            suite.contains("-GCM-") || suite.ends_with("-CHACHA20-POLY1305"),
            "AEAD only: {suite}"
        );
    }
    for scope in ["quicEnable", "sslDefaultCiphers"] {
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.split(' ').next() == Some(scope))
                .count(),
            1,
            "{scope} only in tuning"
        );
    }
}

/// W387 (D-037): OLS starts the PHP of an ejected site through its suEXEC
/// daemon. W387 run 1 found that the daemon refuses every start
/// (`cgidSuEXEC failed`) when the parent has no `CGIRLimit` block. The
/// shipped parent has one, and its floor keeps every system account (UID
/// and GID under 1000) out of a PHP that OLS starts.
#[test]
fn the_shipped_parent_lets_ols_start_php_only_as_unprivileged_accounts() {
    let lines: Vec<String> = SHIPPED_PARENT
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let block: Vec<&str> = lines
        .iter()
        .skip_while(|line| line.as_str() != "CGIRLimit {")
        .skip(1)
        .take_while(|line| line.as_str() != "}")
        .map(String::as_str)
        .collect();
    let floor = |name: &str| {
        block
            .iter()
            .find_map(|line| line.strip_prefix(&format!("{name} ")))
            .and_then(|value| value.parse::<u32>().ok())
    };
    assert!(floor("minUID").is_some_and(|uid| uid >= 1000), "{block:?}");
    assert!(floor("minGID").is_some_and(|gid| gid >= 1000), "{block:?}");
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("CGIRLimit"))
            .count(),
        1
    );
}

#[test]
fn webadmin_listener_is_found_in_ipv4_and_ipv6_tables() {
    let v4 = "  sl  local_address rem_address   st\n   0: 0100007F:1BA8 00000000:0000 0A 0\n   1: BA7AA8C0:1F9A 00000000:0000 0A 0\n";
    assert!(listening(v4, 7080));
    assert!(listening(v4, 8090));
    assert!(!listening(v4, 80));
    let established =
        "  sl  local_address rem_address   st\n   0: 0100007F:1BA8 0100007F:D431 01 0\n";
    assert!(!listening(established, 7080), "only LISTEN counts");
    let v6 = "  sl  local_address remote_address st\n   0: 00000000000000000000000001000000:1BA8 00000000000000000000000000000000:0000 0A 0\n";
    assert!(listening(v6, 7080));
}

#[test]
fn an_lsadm_owned_vhost_is_not_pinned() {
    assert!(!file_is_pinned(997, 0o100640, 1, true, false));
    assert!(!file_is_pinned(0, 0o100644, 1, true, false));
    assert!(!file_is_pinned(0, 0o100444, 2, true, true));
    assert!(!file_is_pinned(0, 0o100444, 1, false, true));
    assert!(file_is_pinned(0, 0o100444, 1, true, true));
}

#[test]
fn a_report_is_clean_only_when_every_check_holds() {
    let clean = DriftReport {
        content_addressed: true,
        explained: Some(true),
        parent_reviewed: true,
        webadmin_closed: true,
        adopted_vhosts_pinned: true,
        php_capacity: true,
        page_cache_ols_tested: true,
    };
    assert!(clean.clean());
    assert!(
        DriftReport {
            explained: None,
            ..clean
        }
        .clean(),
        "no established generation yet is not drift"
    );
    for broken in [
        DriftReport {
            content_addressed: false,
            ..clean
        },
        DriftReport {
            explained: Some(false),
            ..clean
        },
        DriftReport {
            parent_reviewed: false,
            ..clean
        },
        DriftReport {
            webadmin_closed: false,
            ..clean
        },
        DriftReport {
            adopted_vhosts_pinned: false,
            ..clean
        },
        DriftReport {
            php_capacity: false,
            page_cache_ols_tested: true,
            ..clean
        },
    ] {
        assert!(!broken.clean(), "{broken:?}");
    }
}

/// W359: through the helper, a drift refusal after intent records the
/// operation `untouched`, and the journal then establishes its predecessor.
/// So the generation checks must refuse before intent, against the journal
/// as it stands, or a refused activation explains the drift it refused.
#[test]
fn an_unjournaled_generation_is_refused_before_intent() {
    let journaled = sha(b"rs_blog13.vhost\0journaled");
    let planted = sha(b"rs_blog13.vhost\0journaled\n# planted\n");
    let established = (generation_id(&journaled), journaled.clone());
    let live = (generation_id(&planted), planted.clone());
    assert_eq!(
        generation_refusal(&live, Some(&established)),
        Some((true, Some(false))),
        "a valid content address the journal never established is drift"
    );
    assert_eq!(generation_refusal(&established, Some(&established)), None);
    assert_eq!(
        generation_refusal(&live, None),
        None,
        "with nothing established yet, a content-addressed generation passes"
    );
    let forged = (generation_id(&journaled), planted);
    assert_eq!(
        generation_refusal(&forged, Some(&established)),
        Some((false, Some(false))),
        "bytes that no longer hash to the id"
    );
    let adopted = (Id::try_from("g1".to_owned()).unwrap(), journaled);
    assert_eq!(generation_refusal(&adopted, Some(&adopted)), None);
    assert_eq!(
        generation_refusal(&adopted, None),
        Some((false, None)),
        "an adopted id passes only as the established generation"
    );
}

#[test]
fn an_edited_generation_no_longer_matches_its_content_address() {
    let original = sha(b"vhosts.conf\0");
    let id: Id = generation_id(&original);
    assert_eq!(generation_id(&original), id);
    assert_ne!(generation_id(&sha(b"vhosts.conf\0edited")), id);
}

mod helper_checks {
    //! W200: the server-root and listener-table checks the admin helper makes.
    use super::*;
    use rustiron_contracts::approval::{Hostname, SiteId};
    use rustiron_executor::{
        ExecutorError,
        ols::{ServerChecks, served_from},
    };

    const CLOSED: &str =
        "  sl  local_address rem_address   st\n   0: 00000000:1F9A 00000000:0000 0A\n";
    const OPEN: &str =
        "  sl  local_address rem_address   st\n   0: 00000000:1BA8 00000000:0000 0A\n";

    fn tables(first: Option<&str>, second: Option<&str>) -> [Option<String>; 2] {
        [first.map(str::to_owned), second.map(str::to_owned)]
    }

    #[test]
    fn reviewed_parent_and_closed_webadmin_pass() {
        let reviewed = sha(PARENT.as_bytes());
        let checks = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            true,
            true,
        );
        assert!(checks.report((true, Some(true))).clean());
    }

    #[test]
    fn unreadable_config_or_table_is_drift_not_clean() {
        let reviewed = sha(PARENT.as_bytes());
        let unreadable_parent = ServerChecks::from_reads(
            None,
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            true,
            true,
        );
        assert!(!unreadable_parent.parent_reviewed);
        assert!(!unreadable_parent.report((true, Some(true))).clean());
        for missing in [tables(None, Some(CLOSED)), tables(Some(CLOSED), None)] {
            let checks = ServerChecks::from_reads(
                Some(PARENT.as_bytes()),
                &reviewed,
                missing,
                (7080, 8090),
                true,
                true,
            );
            assert!(!checks.webadmin_closed);
        }
    }

    #[test]
    fn a_private_network_namespace_is_not_a_closed_webadmin() {
        // PrivateNetwork=yes shows an empty table: nothing listens, not
        // even the OLS listener, so the webadmin check must not pass.
        let reviewed = sha(PARENT.as_bytes());
        let empty = "  sl  local_address rem_address   st\n";
        let checks = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(empty), Some(empty)),
            (7080, 8090),
            true,
            true,
        );
        assert!(!checks.webadmin_closed);
        assert!(!checks.report((true, Some(true))).clean());
    }

    #[test]
    fn drifted_parent_open_webadmin_or_unpinned_vhost_is_drift() {
        let reviewed = sha(PARENT.as_bytes());
        let drifted = PARENT.replace("disableWebAdmin                  1", "disableWebAdmin 0");
        let parent = ServerChecks::from_reads(
            Some(drifted.as_bytes()),
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            true,
            true,
        );
        assert!(!parent.parent_reviewed);
        let open = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(OPEN), Some(CLOSED)),
            (7080, 8090),
            true,
            true,
        );
        assert!(!open.webadmin_closed);
        let unpinned = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            false,
            true,
        );
        assert!(!unpinned.report((true, Some(true))).clean());
        // The executor's own generation checks still apply.
        let clean = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            true,
            true,
        );
        assert!(!clean.report((false, Some(true))).clean());
        assert!(!clean.report((true, Some(false))).clean());
        // W212: too few PHP children for the OLS workers refuses activation.
        let starved = ServerChecks::from_reads(
            Some(PARENT.as_bytes()),
            &reviewed,
            tables(Some(CLOSED), Some(CLOSED)),
            (7080, 8090),
            true,
            false,
        );
        assert!(!starved.report((true, Some(true))).clean());
    }

    #[test]
    fn helper_reply_decodes_only_the_exact_four_fields() {
        let checks = ServerChecks {
            parent_reviewed: true,
            webadmin_closed: true,
            adopted_vhosts_pinned: true,
            php_capacity: true,
            page_cache_ols_tested: true,
        };
        assert_eq!(ServerChecks::decode(&checks.encode()), Some(checks));
        // W427 (D-052): a reply without the OLS version check is refused.
        let old = r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true,"php_capacity":true}"#;
        assert_eq!(ServerChecks::decode(old), None);
        for hostile in [
            "",
            "{}",
            r#"{"parent_reviewed":true,"webadmin_closed":true}"#,
            r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true,"clean":true}"#,
            r#"{"parent_reviewed":"true","webadmin_closed":true,"adopted_vhosts_pinned":true}"#,
            r#"{"parent_reviewed":true,"webadmin_closed":true,"adopted_vhosts_pinned":true}"#,
            "true",
        ] {
            assert_eq!(ServerChecks::decode(hostile), None, "accepted {hostile}");
        }
        let padded = format!("{}{}", checks.encode(), " ".repeat(300));
        assert_eq!(ServerChecks::decode(&padded), None);
    }

    /// W426-F1 (D-052): the cache-on recipe's post-password bypass works
    /// only on tested OLS versions; anything else, or no version, is untested.
    #[test]
    fn only_a_tested_ols_version_supports_the_cache_on_recipe() {
        use rustiron_executor::ols::{PAGE_CACHE_OLS_VERSIONS, page_cache_ols_tested};
        assert_eq!(PAGE_CACHE_OLS_VERSIONS, ["1.9.4"]);
        for tested in ["1.9.4", "1.9.4\n"] {
            assert!(page_cache_ols_tested(Some(tested)), "{tested:?}");
        }
        for untested in [
            "1.9.3\n",
            "1.9.2",
            "1.9.4.1",
            " 1.9.4",
            "1.9.4\n\n",
            "",
            "1.9.40",
        ] {
            assert!(!page_cache_ols_tested(Some(untested)), "{untested:?}");
        }
        assert!(!page_cache_ols_tested(None));
    }

    /// The version check is reported but does not make a report unclean:
    /// only an activation that serves a cached site requires it.
    #[test]
    fn the_ols_version_check_is_reported_outside_clean() {
        let checks = ServerChecks {
            parent_reviewed: true,
            webadmin_closed: true,
            adopted_vhosts_pinned: true,
            php_capacity: true,
            page_cache_ols_tested: false,
        };
        let report = checks.report((true, Some(true)));
        assert!(report.clean());
        assert!(!report.page_cache_ols_tested);
    }

    fn site(value: &str) -> SiteId {
        SiteId::try_from(value.to_owned()).unwrap()
    }
    fn host(value: &str) -> Hostname {
        Hostname::try_from(value.to_owned()).unwrap()
    }

    #[test]
    fn served_sites_come_from_the_generation_and_the_journal_only() {
        let provisions = [
            (
                site("blog13"),
                host("blog13.example.test"),
                Some(host("alias.example.test")),
            ),
            (site("blog5"), host("blog5.example.test"), None),
        ];
        let sites = served_from(&["rs_blog13".to_owned()], &provisions, &[site("blog5")]).unwrap();
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].hostname.as_str(), "blog13.example.test");
        assert_eq!(sites[0].alias_hostname, Some(host("alias.example.test")));
        assert!(!sites[0].ejected);
        assert!(sites[1].ejected && sites[1].account == "rs_blog5");
        // A vhost the journal does not explain, or a foreign file name, is refused.
        for managed in [["rs_w198z".to_owned()], ["site_a".to_owned()]] {
            assert_eq!(
                served_from(&managed, &provisions, &[]).err(),
                Some(ExecutorError::PreconditionChanged)
            );
        }
        assert_eq!(
            served_from(&[], &provisions, &[site("gone")]).err(),
            Some(ExecutorError::PreconditionChanged)
        );
    }
}
