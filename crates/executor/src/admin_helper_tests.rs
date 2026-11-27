use super::*;

fn request(step: AdminStep) -> AdminRequest {
    AdminRequest {
        operation_id: Id::try_from("op_w171".to_owned()).unwrap(),
        step,
    }
}

#[test]
fn every_step_round_trips() {
    for step in AdminStep::ALL {
        let bytes = request(step).encode();
        assert_eq!(AdminRequest::parse(&bytes), Ok(request(step)));
    }
}

#[test]
fn ols_status_is_one_exact_line_and_not_a_step() {
    assert!(is_ols_status(b"v1 ols_status\n"));
    for bytes in [
        &b"v1 ols_status"[..],
        b"v1 ols_status \n",
        b"V1 ols_status\n",
        b"v1 op_w202 ols_status\n",
        b"v1 ols_status\0\n",
    ] {
        assert!(!is_ols_status(bytes), "{bytes:?}");
    }
    assert!(
        AdminStep::ALL
            .iter()
            .all(|step| step.name() != "ols_status")
    );
    assert_eq!(
        AdminRequest::parse(b"v1 op_w202 ols_status\n"),
        Err(ExecutorError::InvalidRequest)
    );
}

#[test]
fn step_names_are_unique() {
    let mut names: Vec<_> = AdminStep::ALL.iter().map(|s| s.name()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), AdminStep::ALL.len());
}

#[test]
fn rejects_anything_but_the_exact_form() {
    let long_id = format!("v1 {} account_reserve\n", "a".repeat(65));
    let oversized = format!(
        "v1 op_w171 account_reserve\n{}",
        " ".repeat(MAX_ADMIN_REQUEST_BYTES)
    );
    let cases: [&[u8]; 16] = [
        b"",
        b"v1 op_w171 account_reserve",
        b"v1 op_w171 account_reserve\r\n",
        b"v1 op_w171 account_reserve\n\n",
        b"v2 op_w171 account_reserve\n",
        b"v1  op_w171 account_reserve\n",
        b"v1 op_w171 account_reserve /srv/sites/x\n",
        b"v1 op_w171 account_reserve --uid=0\n",
        b"v1 op_w171\n",
        b"v1 op_w171 ACCOUNT_RESERVE\n",
        b"v1 op_w171 useradd\n",
        b"v1 ../etc account_reserve\n",
        b"v1 op_w171 launch_enrolled_job SELinuxContext=unconfined_t\n",
        b"v1 op_w171 account_reserve\xff\n",
        long_id.as_bytes(),
        oversized.as_bytes(),
    ];
    for case in cases {
        assert_eq!(
            AdminRequest::parse(case),
            Err(ExecutorError::InvalidRequest),
            "accepted {:?}",
            String::from_utf8_lossy(case)
        );
    }
}

#[test]
fn verb_step_table_is_closed() {
    use AdminStep as S;
    let allowed = |verb| -> Vec<AdminStep> {
        AdminStep::ALL
            .into_iter()
            .filter(|s| step_allowed(verb, *s))
            .collect()
    };
    // W457: an import's scrub runs under its provision; W501: a clone's;
    // W508: the retirement of a quarantined provision.
    assert_eq!(
        allowed(Verb::SiteProvision),
        [
            S::ProvisionStep,
            S::ImportScrub,
            S::CloneScrub,
            S::SiteRetire,
            S::SiteDelete,
            S::UpdateInventory,
            S::SiteQuotaSet
        ]
    );
    // W462: a certificate issuance asks for its one step; W464: a renewal
    // under its grant asks for the renewal step (the record decides).
    assert_eq!(
        allowed(Verb::CertificateIssue),
        [S::CertificateIssue, S::CertificateRenew]
    );
    assert_eq!(allowed(Verb::RestoreProbe), [S::ProbeRun]);
    // W516: an update asks for its open step or its open rollback.
    assert_eq!(
        allowed(Verb::SiteUpdate),
        [S::UpdateStep, S::UpdateRollback]
    );
    assert_eq!(allowed(Verb::BackupCapture), [S::CaptureRun]);
    // W543: a restore asks only for the open step of its open attempt.
    assert_eq!(allowed(Verb::SiteRestore), [S::RestoreStep]);
    // W563: a zone import asks for its one step; W565: once done, the read
    // of the zone it owns.
    assert_eq!(allowed(Verb::DnsZoneImport), [S::DnsImport, S::DnsZoneRead]);
    assert_eq!(allowed(Verb::DnsChange), [S::DnsChange]);
    assert_eq!(
        allowed(Verb::SiteCredentialRotate),
        [S::SiteCredentialRotate, S::SiteCredentialVerify]
    );
    let ols = [
        S::OlsPreflight,
        S::OlsConfigTest,
        S::OlsReload,
        S::OlsVerify,
        S::OlsStart,
        S::OlsStop,
        S::PageCacheInstall,
        S::PageCacheRemove,
        S::OlsBootstrapConfirm,
    ];
    assert_eq!(allowed(Verb::ConfigActivate), ols);
    // W387: only an ejection stops or restores the site's Rustiron PHP.
    let mut eject = ols.to_vec();
    eject.extend([S::EjectPhpStop, S::EjectPhpRestore]);
    assert_eq!(allowed(Verb::SiteEject), eject);
}

#[test]
fn ols_steps_have_exact_wire_names() {
    for (step, name) in [
        (AdminStep::OlsPreflight, "ols_preflight"),
        (AdminStep::OlsConfigTest, "ols_config_test"),
        (AdminStep::OlsReload, "ols_reload"),
        (AdminStep::OlsVerify, "ols_verify"),
        (AdminStep::OlsStart, "ols_start"),
        (AdminStep::OlsStop, "ols_stop"),
        (AdminStep::PageCacheInstall, "page_cache_install"),
        (AdminStep::PageCacheRemove, "page_cache_remove"),
        (AdminStep::OlsBootstrapConfirm, "ols_bootstrap_confirm"),
        (AdminStep::EjectPhpStop, "eject_php_stop"),
        (AdminStep::EjectPhpRestore, "eject_php_restore"),
    ] {
        let line = format!("v1 op_w200 {name}\n");
        assert_eq!(
            AdminRequest::parse(line.as_bytes()).map(|r| r.step),
            Ok(step)
        );
    }
    for hostile in [
        &b"v1 op_w200 ols_reload lshttpd.service\n"[..],
        b"v1 op_w200 ols_verify --address=10.0.0.1:80\n",
        b"v1 op_w200 ols_config_test;sh\n",
        b"v1 op_w200 OLS_PREFLIGHT\n",
        b"v1 op_w200 ols_restart\n",
        b"v1 op_w355 ols_start lshttpd.service\n",
        b"v1 op_w355 ols_reload_or_restart\n",
        b"v1 op_w355 OLS_START\n",
        b"v1 op_w413 boot-restore-ejected-php\n",
    ] {
        assert_eq!(
            AdminRequest::parse(hostile),
            Err(ExecutorError::InvalidRequest)
        );
    }
}

const ADMIN_TE: &str = include_str!("../../../policy/selinux/rustiron_admin.te");

fn rules(te: &str) -> String {
    te.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_helper_unit_reaches_only_the_ols_listener_address() {
    let unit = include_str!("../../../lab/s10/rustiron-s10-lab-admin-helper.service");
    let lines: Vec<&str> = unit.lines().map(str::trim).collect();
    assert!(!lines.iter().any(|l| l.starts_with("PrivateNetwork=")));
    assert!(lines.contains(&"IPAddressDeny=any"));
    let allow: Vec<_> = lines
        .iter()
        .filter(|l| l.starts_with("IPAddressAllow="))
        .collect();
    assert_eq!(allow, [&"IPAddressAllow=192.168.122.186/32"]);
    assert!(lines.contains(&"RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET"));
}

#[test]
fn only_the_helper_reads_proc_net_and_connects_to_one_ols_port() {
    let admin = rules(ADMIN_TE);
    // W200: exactly one TCP connect grant, to the one lab listener port type.
    assert_eq!(admin.matches("name_connect").count(), 1);
    assert!(admin.contains("allow rustiron_admin_t rustiron_ols_port_t:tcp_socket name_connect;"));
    // The one local port label C07 accepts.
    assert_eq!(
        include_str!("../../../lab/s10/c07_ports.txt").trim(),
        "rustiron_ols_port_t tcp 8090"
    );
    assert!(admin.contains("kernel_read_network_state(rustiron_admin_t)"));
    for broad in [
        "unreserved_port_t",
        "http_port_t",
        "corenet_tcp_connect_all",
        "corenet_tcp_connect_generic",
        "name_bind",
        "node_bind",
        "udp_socket",
        "rawip_socket",
        "kernel_read_system_state",
        "rustiron_ols_generation_t:dir { write",
        "manage_files_pattern(rustiron_admin_t, rustiron_ols_generation_t",
    ] {
        assert!(!admin.contains(broad), "admin policy grants {broad}");
    }
    let executor = rules(EXECUTOR_TE);
    for word in [
        "proc_net",
        "network_state",
        "tcp_socket",
        "name_connect",
        "rustiron_ols_port_t",
    ] {
        assert!(!executor.contains(word), "executor policy grants {word}");
    }
}

/// W358: on a clean AlmaLinux 10.2 host, `quotaon` runs in the base
/// `quota_t` domain and was refused the write to the stdout file that PID 1
/// opened in the helper's runtime directory, so the W335 readiness check
/// always answered `quota_state_unknown`. The helper's metadata check of
/// `quotaon` (`quota_exec_t`) was refused too. The rules stay as narrow as
/// the W318 reader rules: write to that one file type, no open or create.
#[test]
fn quota_tools_can_write_their_unit_output_and_nothing_more() {
    let admin = rules(ADMIN_TE);
    assert!(admin.contains("allow quota_t rustiron_admin_run_t:file { getattr write append };"));
    assert!(admin.contains("dontaudit quota_t rustiron_admin_run_t:file ioctl;"));
    assert!(admin.contains("allow rustiron_admin_t quota_exec_t:file getattr;"));
    // systemd-run's access(X_OK) probe of quotaon: refused and not audited.
    assert!(admin.contains("dontaudit rustiron_admin_t quota_exec_t:file execute;"));
    for broad in [
        "quota_t rustiron_admin_run_t:file { getattr open",
        "quota_t rustiron_admin_run_t:dir",
        "manage_files_pattern(quota_t",
        "domtrans_pattern(rustiron_admin_t, quota_exec_t",
        "quota_exec_t:file { getattr execute",
    ] {
        assert!(!admin.contains(broad), "admin policy grants {broad}");
    }
    // The executor domain keeps no quota authority; the helper runs the tools.
    assert!(!rules(EXECUTOR_TE).contains("quota"));
}

/// W361: `systemctl is-enabled -- mariadb.service` in the provision Verify
/// step (`serving_survives_boot`) stats the vendor unit file
/// (`mysqld_unit_file_t`) before it asks PID 1. PID 1 answers the state over
/// D-Bus, and W358 recorded `enabled` with the stat refused, so the stat
/// result is unused. The helper gets no access to that type; the refusal is
/// kept out of the audit log.
#[test]
fn mariadb_unit_file_stat_is_refused_without_audit() {
    let admin = rules(ADMIN_TE);
    assert!(admin.contains("dontaudit rustiron_admin_t mysqld_unit_file_t:file getattr;"));
    assert!(admin.contains("policy_module(rustiron_admin, 0.5.6)"));
    for broad in [
        "allow rustiron_admin_t mysqld_unit_file_t",
        "mysqld_unit_file_t:service",
        "systemd_read_all_unit_files",
        "systemd_getattr_all_unit_files",
    ] {
        assert!(!admin.contains(broad), "admin policy grants {broad}");
    }
}

/// W566 (W564-F5): the helper may read `pdns_control`'s metadata for
/// systemd-run's check; it never executes it.
#[test]
fn pdns_control_is_checked_by_metadata_only() {
    let admin = rules(ADMIN_TE);
    assert!(admin.contains("allow rustiron_admin_t pdns_control_exec_t:file getattr;"));
    assert!(admin.contains("dontaudit rustiron_admin_t pdns_control_exec_t:file execute;"));
    for broad in [
        "allow rustiron_admin_t pdns_control_exec_t:file { getattr execute",
        "allow rustiron_admin_t pdns_control_exec_t:file execute",
        "pdns_control_t",
        "pdns_var_lib_t",
    ] {
        assert!(!admin.contains(broad), "admin policy grants {broad}");
    }
}

/// W370: the page-cache removal lists the site's cache storage (`usr_t`,
/// created by OLS) before and after the purge job. The base `domain` rules
/// already allow that listing (W370 VM `sesearch`), so the module adds no
/// `usr_t` rule; the job deletes as the OLS account in its own unit.
#[test]
fn cache_storage_is_never_written_by_the_helper() {
    let admin = rules(ADMIN_TE);
    for broad in [
        "files_list_usr",
        "files_manage_usr",
        "files_delete_usr",
        "files_rw_usr",
        "files_manage_generic_usr",
        "usr_t:dir { write",
        "usr_t:file",
    ] {
        assert!(!admin.contains(broad), "admin policy grants {broad}");
    }
}

const EXECUTOR_TE: &str = include_str!("../../../policy/selinux/rustiron_executor.te");

#[test]
fn executor_policy_holds_no_administrative_authority() {
    let forbidden = [
        "seutil_",
        "semanage",
        "usermanage_",
        "useradd",
        "load_policy",
        "setfiles",
        "systemd_config_all_services",
        "systemd_start",
        "init_start",
        "init_stop",
        "unconfined_domain",
        "permissive ",
        "etc_t",
    ];
    let rules = EXECUTOR_TE
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
        // The one SELinux-utility read the executor keeps (W173): the
        // generated local rules file, for category allocation.
        .replace("seutil_read_file_contexts(rustiron_executor_t)", "");
    for word in forbidden {
        assert!(!rules.contains(word), "executor policy grants {word}");
    }
}

mod authorize {
    use rustiron_contracts::{
        Timestamp,
        approval::{Hostname, Sha256Digest, SiteId, SnapshotId},
    };
    use rustiron_journal::{CaptureIntent, ProbeIntent, ProvisionIntent, StepRecord};
    use std::path::PathBuf;

    use super::super::*;

    const EXECUTOR: u32 = 0;

    fn id(value: &str) -> Id {
        Id::try_from(value.to_owned()).unwrap()
    }
    fn digest() -> Sha256Digest {
        Sha256Digest::try_from("a".repeat(64)).unwrap()
    }
    fn time() -> Timestamp {
        Timestamp::try_from(1000).unwrap()
    }
    fn site() -> SiteId {
        SiteId::try_from("blog1".to_owned()).unwrap()
    }
    fn ask(step: AdminStep) -> AdminRequest {
        AdminRequest {
            operation_id: id("op_a"),
            step,
        }
    }

    fn provision(last: ProvisionStep, state: StepState) -> Provision {
        let position = ProvisionStep::ALL.iter().position(|s| *s == last).unwrap();
        let mut steps: Vec<_> = ProvisionStep::ALL[..=position]
            .iter()
            .map(|step| StepRecord {
                step: *step,
                state: StepState::Done,
                resource: "r".to_owned(),
            })
            .collect();
        steps.last_mut().unwrap().state = state;
        Provision {
            intent: ProvisionIntent {
                operation_id: id("op_a"),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest(),
                grant_digest: digest(),
                host_id: id("h"),
                host_epoch: id("e"),
                site_id: site(),
                hostname: Hostname::try_from("blog1.example.test".to_owned()).unwrap(),
                expires_at: time(),
            },
            state: ProvisionState::Running,
            steps,
        }
    }

    fn probe(state: ProbeState) -> Probe {
        Probe {
            backup_policy_digest: None,
            intent: ProbeIntent {
                operation_id: id("op_a"),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest(),
                grant_digest: digest(),
                host_id: id("h"),
                host_epoch: id("e"),
                site_id: site(),
                snapshot_id: SnapshotId::try_from("b".repeat(64)).unwrap(),
                probe_account: "rp_00aa11".to_owned(),
                expires_at: time(),
            },
            started_at: time(),
            state,
            receipt: None,
            finished_at: None,
        }
    }

    fn capture(state: CaptureState) -> Capture {
        Capture {
            backup_policy_digest: None,
            intent: CaptureIntent {
                operation_id: id("op_a"),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest(),
                grant_digest: digest(),
                host_id: id("h"),
                host_epoch: id("e"),
                site_id: site(),
                expires_at: time(),
            },
            started_at: time(),
            state,
            snapshot_id: None,
            finished_at: None,
            method: None,
            retention_days: None,
            files: None,
            bytes: None,
            manifest: None,
            consistency: None,
            unclaimed_snapshot_id: None,
            retention_evidence: None,
            refusal: None,
        }
    }

    #[test]
    fn provision_step_targets_come_from_the_journal() {
        let record = provision(ProvisionStep::Account, StepState::Intent);
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(AdminStep::ProvisionStep),
            Record::Provision(&record),
        );
        assert_eq!(
            action,
            Ok(AdminAction {
                step: AdminStep::ProvisionStep,
                account: "rs_blog1".to_owned(),
                root: PathBuf::from("/srv/sites/rs_blog1"),
            })
        );
    }

    #[test]
    fn wrong_peer_is_refused_first() {
        let record = provision(ProvisionStep::Account, StepState::Intent);
        assert_eq!(
            authorize(
                1000,
                EXECUTOR,
                &ask(AdminStep::ProvisionStep),
                Record::Provision(&record)
            ),
            Err(ExecutorError::PeerDenied)
        );
    }

    #[test]
    fn only_the_current_provision_step_is_authorized() {
        let deny = Err(ExecutorError::BindingDenied);
        let run = AdminStep::ProvisionStep;
        let cases = [
            // Step already done, not in intent.
            (provision(ProvisionStep::Account, StepState::Done), run),
            // Failed step.
            (provision(ProvisionStep::Labels, StepState::Failed), run),
            // Steps of other verbs.
            (
                provision(ProvisionStep::Account, StepState::Intent),
                AdminStep::CaptureRun,
            ),
            (
                provision(ProvisionStep::PhpUnits, StepState::Intent),
                AdminStep::ProbeRun,
            ),
        ];
        for (record, step) in cases {
            assert_eq!(
                authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Provision(&record)),
                deny,
                "{step:?}"
            );
        }
        let mut quarantined = provision(ProvisionStep::Account, StepState::Intent);
        quarantined.state = ProvisionState::Quarantined;
        assert_eq!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(run),
                Record::Provision(&quarantined)
            ),
            deny
        );
        for step in ProvisionStep::ALL {
            let record = provision(step, StepState::Intent);
            assert!(
                authorize(EXECUTOR, EXECUTOR, &ask(run), Record::Provision(&record)).is_ok(),
                "{step:?}"
            );
        }
    }

    /// W530 (D-087): the read-only inventory, and W535 (D-088) the quota
    /// change, are authorized for a site that the journal owns, and for no
    /// other provision state; the open change is checked when the step runs.
    #[test]
    fn the_inventory_is_authorized_only_for_an_owned_site() {
        let mut record = provision(ProvisionStep::PhpUnits, StepState::Done);
        for (state, allowed) in [
            (ProvisionState::Succeeded, true),
            (ProvisionState::Adopted, true),
            (ProvisionState::Running, false),
            (ProvisionState::Quarantined, false),
            (ProvisionState::Deleted, false),
        ] {
            record.state = state;
            for step in [AdminStep::UpdateInventory, AdminStep::SiteQuotaSet] {
                assert_eq!(
                    authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Provision(&record)).is_ok(),
                    allowed,
                    "{step:?} {state:?}"
                );
            }
        }
    }

    /// W543 (D-089): a restore of `blog1` with one attempt.
    fn restore(
        from: rustiron_journal::RestoreFrom,
        attempt: StepState,
        steps: &[(rustiron_journal::RestoreStep, StepState)],
        state: rustiron_journal::RestoreState,
    ) -> rustiron_journal::SiteRestore {
        rustiron_journal::SiteRestore {
            operation_id: id("op_a"),
            site_id: site(),
            scope: rustiron_contracts::approval::RestoreScope::Database,
            capture_operation_id: id("cap_old"),
            snapshot_id: SnapshotId::try_from("b".repeat(64)).unwrap(),
            manifest_sha256: digest(),
            safety_capture_operation_id: id("cap_safe"),
            attempts: vec![rustiron_journal::RestoreAttempt {
                from,
                state: attempt,
                steps: steps
                    .iter()
                    .map(|(step, state)| rustiron_journal::RestoreStepRecord {
                        step: *step,
                        state: *state,
                    })
                    .collect(),
            }],
            state,
        }
    }

    /// W543: only the open step of the open attempt of an open restore is
    /// authorized, and only as `restore_step`; its targets are the site's.
    #[test]
    fn a_restore_step_needs_the_open_step_of_the_open_attempt() {
        use rustiron_journal::{RestoreFrom as F, RestoreState as R, RestoreStep as T};
        let open = restore(
            F::Safety,
            StepState::Intent,
            &[
                (T::Maintenance, StepState::Done),
                (T::Fetch, StepState::Intent),
            ],
            R::Intent,
        );
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(AdminStep::RestoreStep),
            Record::Restore(&open),
        )
        .unwrap();
        assert_eq!(action.account, "rs_blog1");
        assert_eq!(action.root, SiteLayout::derive(&site()).root);
        for step in [
            AdminStep::UpdateStep,
            AdminStep::ProvisionStep,
            AdminStep::SiteDelete,
        ] {
            assert_eq!(
                authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Restore(&open)).err(),
                Some(ExecutorError::BindingDenied),
                "{step:?}"
            );
        }
        for closed in [
            // No step open yet, or the last one finished.
            restore(F::Signed, StepState::Intent, &[], R::Intent),
            restore(
                F::Signed,
                StepState::Intent,
                &[(T::Maintenance, StepState::Done)],
                R::Intent,
            ),
            // A failed attempt, or a finished restore.
            restore(
                F::Signed,
                StepState::Failed,
                &[(T::Fetch, StepState::Failed)],
                R::Intent,
            ),
            restore(
                F::Signed,
                StepState::Done,
                &[(T::Health, StepState::Done)],
                R::Done,
            ),
            restore(
                F::Safety,
                StepState::Done,
                &[(T::Health, StepState::Done)],
                R::Reverted,
            ),
        ] {
            assert_eq!(
                authorize(
                    EXECUTOR,
                    EXECUTOR,
                    &ask(AdminStep::RestoreStep),
                    Record::Restore(&closed)
                )
                .err(),
                Some(ExecutorError::BindingDenied)
            );
        }
        let other = AdminRequest {
            operation_id: id("op_b"),
            step: AdminStep::RestoreStep,
        };
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &other, Record::Restore(&open)).err(),
            Some(ExecutorError::BindingDenied)
        );
        // A restore is one record; with any other it is refused.
        let alone = OperationRecords {
            site_restore: Some(open.clone()),
            ..Default::default()
        };
        assert!(matches!(single_record(&alone), Ok(Record::Restore(_))));
        let mixed = OperationRecords {
            site_restore: Some(open),
            capture: Some(capture(CaptureState::Running)),
            ..Default::default()
        };
        assert_eq!(
            single_record(&mixed).err(),
            Some(ExecutorError::BindingDenied)
        );
    }

    /// W563 (D-091): a zone import runs only its own step while open; its
    /// targets are PowerDNS's, and its operation names no other record.
    #[test]
    fn a_dns_import_runs_once_while_open_and_alone() {
        let import = |state| rustiron_journal::DnsImport {
            operation_id: id("op_a"),
            zone: rustiron_contracts::approval::ZoneName::try_from("example.test".to_owned())
                .unwrap(),
            zone_sha256: rustiron_contracts::approval::Sha256Digest::from_bytes([7; 32]),
            record_sets: 3,
            state,
        };
        let open = import(StepState::Intent);
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(AdminStep::DnsImport),
            Record::DnsImport(&open),
        )
        .unwrap();
        assert_eq!(action.account, "pdns");
        assert_eq!(action.root, PathBuf::from("/var/lib/pdns"));
        for (step, record) in [
            (AdminStep::RestoreStep, open.clone()),
            (AdminStep::DnsImport, import(StepState::Done)),
            (AdminStep::DnsImport, import(StepState::Failed)),
        ] {
            assert_eq!(
                authorize(EXECUTOR, EXECUTOR, &ask(step), Record::DnsImport(&record)),
                Err(ExecutorError::BindingDenied)
            );
        }
        assert_eq!(
            authorize(
                1,
                EXECUTOR,
                &ask(AdminStep::DnsImport),
                Record::DnsImport(&open)
            ),
            Err(ExecutorError::PeerDenied)
        );
        let alone = OperationRecords {
            dns_import: Some(open.clone()),
            ..Default::default()
        };
        assert!(matches!(single_record(&alone), Ok(Record::DnsImport(_))));
        // W565: the zone read runs only under a done import.
        let done = import(StepState::Done);
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::DnsZoneRead),
                Record::DnsImport(&done)
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::DnsZoneRead),
                Record::DnsImport(&open)
            ),
            Err(ExecutorError::BindingDenied)
        );
        let mixed = OperationRecords {
            dns_import: Some(open),
            capture: Some(capture(CaptureState::Running)),
            ..Default::default()
        };
        assert_eq!(
            single_record(&mixed).err(),
            Some(ExecutorError::BindingDenied)
        );
    }

    /// W565 (D-091): a record change runs only its own step while open, and
    /// needs its stored plan bytes and no other record.
    #[test]
    fn a_dns_change_runs_once_while_open_with_its_plan() {
        let change = |state| rustiron_journal::DnsChange {
            operation_id: id("op_a"),
            zone: rustiron_contracts::approval::ZoneName::try_from("example.test".to_owned())
                .unwrap(),
            sets: Vec::new(),
            state,
        };
        let plan: &[u8] = b"{}";
        let open = change(StepState::Intent);
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::DnsChange),
                Record::DnsChange(&open, plan)
            )
            .is_ok()
        );
        for (step, record) in [
            (AdminStep::DnsImport, open.clone()),
            (AdminStep::DnsZoneRead, open.clone()),
            (AdminStep::DnsChange, change(StepState::Done)),
            (AdminStep::DnsChange, change(StepState::Failed)),
        ] {
            assert_eq!(
                authorize(
                    EXECUTOR,
                    EXECUTOR,
                    &ask(step),
                    Record::DnsChange(&record, plan)
                ),
                Err(ExecutorError::BindingDenied)
            );
        }
        let without_plan = OperationRecords {
            dns_change: Some(open.clone()),
            ..Default::default()
        };
        assert_eq!(
            single_record(&without_plan).err(),
            Some(ExecutorError::BindingDenied)
        );
        let alone = OperationRecords {
            dns_change: Some(open.clone()),
            dns_change_plan: Some(plan.to_vec()),
            ..Default::default()
        };
        assert!(matches!(single_record(&alone), Ok(Record::DnsChange(..))));
        let mixed = OperationRecords {
            dns_change: Some(open),
            dns_change_plan: Some(plan.to_vec()),
            capture: Some(capture(CaptureState::Running)),
            ..Default::default()
        };
        assert_eq!(
            single_record(&mixed).err(),
            Some(ExecutorError::BindingDenied)
        );
    }

    /// W501 (D-078): a clone scrub is authorized only on a quarantined
    /// provision, and runs only for the open scrub after a failed clone step.
    #[test]
    fn a_clone_scrub_needs_a_failed_clone_with_an_open_scrub() {
        use rustiron_journal::{CloneFacts, CloneStep, CloneStepRecord, SiteClone};
        let scrub = AdminStep::CloneScrub;
        let running = provision(ProvisionStep::Recipe, StepState::Intent);
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &ask(scrub), Record::Provision(&running)),
            Err(ExecutorError::BindingDenied)
        );
        let mut quarantined = provision(ProvisionStep::Recipe, StepState::Failed);
        quarantined.state = ProvisionState::Quarantined;
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(scrub),
            Record::Provision(&quarantined),
        )
        .unwrap();
        let clone = |last: StepState, scrub: Option<StepState>| SiteClone {
            facts: CloneFacts {
                source_site_id: "blog9".to_owned().try_into().unwrap(),
                source_hostname: "blog9.example.test".to_owned().try_into().unwrap(),
                capture_operation_id: "op_capture".to_owned().try_into().unwrap(),
                snapshot_id: "b".repeat(64).try_into().unwrap(),
                manifest_sha256: "c".repeat(64).try_into().unwrap(),
                destination_policy_digest: "d".repeat(64).try_into().unwrap(),
                repository_id: "e".repeat(64).try_into().unwrap(),
            },
            steps: vec![CloneStepRecord {
                step: CloneStep::Fetch,
                state: last,
            }],
            scrub,
            signed_scrub: None,
        };
        // No clone record, no open scrub, a done scrub, or a step that did
        // not fail without a signed scrub: refused before any effect.
        for refused in [
            None,
            Some(clone(StepState::Failed, None)),
            Some(clone(StepState::Failed, Some(StepState::Done))),
            Some(clone(StepState::Intent, Some(StepState::Intent))),
        ] {
            assert_eq!(
                clone_scrub(&action, &quarantined, refused.as_ref()),
                Err(ExecutorError::BindingDenied)
            );
        }
        // The open scrub of a succeeded provision is refused too.
        let mut succeeded = quarantined.clone();
        succeeded.state = ProvisionState::Succeeded;
        assert_eq!(
            clone_scrub(
                &action,
                &succeeded,
                Some(&clone(StepState::Failed, Some(StepState::Intent)))
            ),
            Err(ExecutorError::BindingDenied)
        );
        // W538: a signed scrub opens an interrupted clone's scrub, but never
        // that of a succeeded provision, and a done or failed signed scrub
        // opens nothing.
        let mut signed = clone(StepState::Intent, Some(StepState::Intent));
        signed.signed_scrub = Some(StepState::Intent);
        assert_eq!(
            clone_scrub(&action, &succeeded, Some(&signed)),
            Err(ExecutorError::BindingDenied)
        );
        for state in [StepState::Done, StepState::Failed] {
            signed.signed_scrub = Some(state);
            assert_eq!(
                clone_scrub(&action, &quarantined, Some(&signed)),
                Err(ExecutorError::BindingDenied),
                "{state:?}"
            );
        }
    }

    /// W457 (D-057): a scrub is authorized only on a quarantined provision,
    /// and runs only for the open automatic scrub that the journal records.
    #[test]
    fn an_import_scrub_needs_an_ended_import_with_an_open_scrub() {
        use rustiron_journal::{Import, ImportFacts, ImportScrub, ScrubOrigin};
        let scrub = AdminStep::ImportScrub;
        let running = provision(ProvisionStep::Recipe, StepState::Intent);
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &ask(scrub), Record::Provision(&running)),
            Err(ExecutorError::BindingDenied)
        );
        let mut quarantined = provision(ProvisionStep::Recipe, StepState::Failed);
        quarantined.state = ProvisionState::Quarantined;
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(scrub),
            Record::Provision(&quarantined),
        )
        .unwrap();
        assert_eq!(action.root, PathBuf::from("/srv/sites/rs_blog1"));
        let import = |scrubs: Vec<ImportScrub>| Import {
            facts: ImportFacts {
                archive_sha256: digest(),
                manifest_sha256: digest(),
                file_entries: 1,
                file_bytes: 1,
                dump_bytes: 1,
                target_php: rustiron_contracts::migration::PhpVersion::try_from("8.4".to_owned())
                    .unwrap(),
                source_hostname: None,
                alias_hostname: None,
            },
            steps: Vec::new(),
            scrubs,
        };
        let row = |origin, state, operation: &str| ImportScrub {
            operation_id: id(operation),
            origin,
            state,
        };
        for refused in [
            None,
            Some(import(Vec::new())),
            Some(import(vec![row(
                ScrubOrigin::FailedStep,
                StepState::Done,
                "op_a",
            )])),
            Some(import(vec![row(
                ScrubOrigin::FailedStep,
                StepState::Failed,
                "op_a",
            )])),
            Some(import(vec![row(
                ScrubOrigin::FailedStep,
                StepState::Intent,
                "op_b",
            )])),
            Some(import(vec![row(
                ScrubOrigin::Signed,
                StepState::Done,
                "op_s",
            )])),
        ] {
            assert_eq!(
                import_scrub(&action, &quarantined, refused.as_ref()),
                Err(ExecutorError::BindingDenied),
                "{refused:?}"
            );
        }
        // W459: a succeeded import has no automatic scrub; only a signed one.
        let mut succeeded = quarantined.clone();
        succeeded.state = ProvisionState::Succeeded;
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(scrub),
                Record::Provision(&succeeded)
            )
            .is_ok()
        );
        let automatic = import(vec![row(
            ScrubOrigin::FailedStep,
            StepState::Intent,
            "op_a",
        )]);
        assert_eq!(
            import_scrub(&action, &succeeded, Some(&automatic)),
            Err(ExecutorError::BindingDenied)
        );
    }

    #[test]
    fn record_of_another_operation_is_refused() {
        let record = provision(ProvisionStep::Account, StepState::Intent);
        let other = AdminRequest {
            operation_id: id("op_b"),
            step: AdminStep::ProvisionStep,
        };
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &other, Record::Provision(&record)),
            Err(ExecutorError::BindingDenied)
        );
    }

    #[test]
    fn probe_runs_only_while_running_and_derives_the_probe_root() {
        let running = probe(ProbeState::Running);
        assert_eq!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::ProbeRun),
                Record::Probe(&running)
            )
            .map(|a| a.root),
            Ok(PathBuf::from("/srv/restore-probes/rp_00aa11"))
        );
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::CaptureRun),
                Record::Probe(&running)
            )
            .is_err()
        );
        // Cleanup of a dirty probe is the operator's `cleanup_probe`, never
        // a helper request.
        for state in [
            ProbeState::CleanupIncomplete,
            ProbeState::Passed,
            ProbeState::Failed,
        ] {
            assert!(
                authorize(
                    EXECUTOR,
                    EXECUTOR,
                    &ask(AdminStep::ProbeRun),
                    Record::Probe(&probe(state))
                )
                .is_err(),
                "{state:?}"
            );
        }
    }

    #[test]
    fn capture_runs_only_while_running() {
        let running = capture(CaptureState::Running);
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::CaptureRun),
                Record::Capture(&running)
            )
            .is_ok()
        );
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::ProbeRun),
                Record::Capture(&running)
            )
            .is_err()
        );
        let done = capture(CaptureState::Succeeded);
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::CaptureRun),
                Record::Capture(&done)
            )
            .is_err()
        );
    }

    pub(super) fn ols(state: RecordedState, effect_attempted: bool) -> Operation {
        Operation {
            intent: rustiron_journal::Intent {
                operation_id: id("op_a"),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest(),
                grant_digest: digest(),
                host_id: id("h"),
                host_epoch: id("e"),
                resource_id: id("ols_lab_listener"),
                predecessor_generation: id("r0000000000000001"),
                predecessor_digest: digest(),
                target_generation: id("r0000000000000002"),
                target_digest: digest(),
                expires_at: time(),
                compensation_valid_until: time(),
            },
            state,
            effect_attempted,
            compensation_attempted: state == RecordedState::Compensating,
        }
    }

    #[test]
    fn ols_steps_follow_the_journal_state() {
        use AdminStep as S;
        use RecordedState as R;
        let cases: [(R, bool, &[S]); 8] = [
            (R::Intent, false, &[S::OlsPreflight]),
            (
                R::Intent,
                true,
                &[
                    S::OlsConfigTest,
                    S::OlsReload,
                    S::OlsVerify,
                    S::PageCacheInstall,
                    S::PageCacheRemove,
                ],
            ),
            // W370: the page-cache removal also runs after the one
            // compensating restore, never in a reconcile.
            (
                R::Compensating,
                true,
                &[S::OlsReload, S::OlsVerify, S::PageCacheRemove],
            ),
            (R::Succeeded, true, &[]),
            (R::Untouched, false, &[]),
            (R::NeedsAttention, true, &[S::OlsReload, S::OlsVerify]),
            (R::NeedsAttention, false, &[]),
            (R::FailedCompensated, true, &[]),
        ];
        for (state, attempted, wanted) in cases {
            let operation = ols(state, attempted);
            for step in AdminStep::ALL {
                let decided = authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Ols(&operation));
                if wanted.contains(&step) {
                    let action = decided.unwrap();
                    assert_eq!(action.root, PathBuf::from(crate::ols::INCLUDE_DIR));
                    assert_eq!(action.account, "ols_lab_listener");
                } else {
                    assert_eq!(
                        decided.err(),
                        Some(ExecutorError::BindingDenied),
                        "{state:?} {attempted} {step:?}"
                    );
                }
            }
        }
    }

    /// W387 (D-037): the eject steps of an ejection follow its journal
    /// state: the stop only after the effect mark of the running ejection,
    /// the restore in the states of the predecessor reload (an attempted
    /// ejection, its one compensation). An activation may ask for neither.
    #[test]
    fn eject_steps_follow_the_journal_state_of_an_ejection_only() {
        use AdminStep as S;
        use RecordedState as R;
        let site = rustiron_contracts::approval::SiteId::try_from("blog9".to_owned()).unwrap();
        let cases: [(R, bool, &[S]); 8] = [
            (R::Intent, false, &[]),
            (R::Intent, true, &[S::EjectPhpStop, S::EjectPhpRestore]),
            (R::Compensating, true, &[S::EjectPhpRestore]),
            (R::Succeeded, true, &[]),
            (R::Untouched, false, &[]),
            (R::NeedsAttention, true, &[S::EjectPhpRestore]),
            (R::NeedsAttention, false, &[]),
            (R::FailedCompensated, true, &[]),
        ];
        for (state, attempted, wanted) in cases {
            let operation = ols(state, attempted);
            for step in [S::EjectPhpStop, S::EjectPhpRestore] {
                let decided = authorize(
                    EXECUTOR,
                    EXECUTOR,
                    &ask(step),
                    Record::Ejection(&operation, &site),
                );
                assert_eq!(
                    decided.is_ok(),
                    wanted.contains(&step),
                    "{state:?} {attempted} {step:?}"
                );
                assert_eq!(
                    authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Ols(&operation)).err(),
                    Some(ExecutorError::BindingDenied),
                    "an activation: {state:?} {attempted} {step:?}"
                );
            }
            // The OLS steps of an ejection are those of an activation.
            for step in AdminStep::ALL {
                if matches!(step, S::EjectPhpStop | S::EjectPhpRestore) {
                    continue;
                }
                assert_eq!(
                    authorize(
                        EXECUTOR,
                        EXECUTOR,
                        &ask(step),
                        Record::Ejection(&operation, &site)
                    )
                    .is_ok(),
                    authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Ols(&operation)).is_ok(),
                    "{state:?} {attempted} {step:?}"
                );
            }
        }
        let bootstrap = bootstrap_ols(R::Compensating, true);
        assert!(
            authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(S::EjectPhpRestore),
                Record::Ejection(&bootstrap, &site)
            )
            .is_err(),
            "never for a bootstrap predecessor"
        );
    }

    /// W355: an activation whose journaled predecessor is the bootstrap
    /// generation.
    pub(super) fn bootstrap_ols(state: RecordedState, effect_attempted: bool) -> Operation {
        let mut operation = ols(state, effect_attempted);
        let (generation, digest) = crate::ols::bootstrap_generation();
        operation.intent.predecessor_generation = generation;
        operation.intent.predecessor_digest = digest;
        operation
    }

    #[test]
    fn bootstrap_ols_steps_start_and_stop_and_never_reload() {
        use AdminStep as S;
        use RecordedState as R;
        // W382 (D-033): the read-only confirmation in every unresolved
        // state, for `reconcile`; never after a settlement.
        let cases: [(R, bool, &[S]); 8] = [
            (R::Intent, false, &[S::OlsPreflight, S::OlsBootstrapConfirm]),
            (
                R::Intent,
                true,
                &[
                    S::OlsConfigTest,
                    S::OlsVerify,
                    S::OlsStart,
                    S::OlsBootstrapConfirm,
                ],
            ),
            (R::Compensating, true, &[S::OlsStop, S::OlsBootstrapConfirm]),
            (R::Succeeded, true, &[]),
            (R::Untouched, false, &[]),
            (R::NeedsAttention, true, &[S::OlsBootstrapConfirm]),
            (R::NeedsAttention, false, &[S::OlsBootstrapConfirm]),
            (R::FailedCompensated, true, &[]),
        ];
        for (state, attempted, wanted) in cases {
            let operation = bootstrap_ols(state, attempted);
            for step in AdminStep::ALL {
                let decided = authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Ols(&operation));
                if wanted.contains(&step) {
                    assert!(decided.is_ok(), "{state:?} {attempted} {step:?}");
                } else {
                    assert_eq!(
                        decided.err(),
                        Some(ExecutorError::BindingDenied),
                        "{state:?} {attempted} {step:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn only_a_bootstrap_operation_may_start_or_stop() {
        use RecordedState as R;
        for (state, attempted) in [
            (R::Intent, false),
            (R::Intent, true),
            (R::Compensating, true),
            (R::NeedsAttention, true),
        ] {
            let running = ols(state, attempted);
            for step in [
                AdminStep::OlsStart,
                AdminStep::OlsStop,
                AdminStep::OlsBootstrapConfirm,
            ] {
                assert!(
                    !ols_step_current(&running, step),
                    "{state:?} {attempted} {step:?}"
                );
            }
        }
        // A predecessor with the bootstrap id but another digest is not one.
        let mut forged = bootstrap_ols(R::Intent, true);
        forged.intent.predecessor_digest = digest();
        assert!(!ols_step_current(&forged, AdminStep::OlsStart));
        // W382: nor may it ask for the bootstrap confirmation.
        assert!(!ols_step_current(&forged, AdminStep::OlsBootstrapConfirm));
        assert!(ols_step_current(&forged, AdminStep::OlsReload));
    }

    #[test]
    fn ols_steps_refuse_a_wrong_peer_another_operation_and_other_records() {
        let operation = ols(RecordedState::Intent, false);
        assert_eq!(
            authorize(
                1000,
                EXECUTOR,
                &ask(AdminStep::OlsPreflight),
                Record::Ols(&operation)
            )
            .err(),
            Some(ExecutorError::PeerDenied)
        );
        let other = AdminRequest {
            operation_id: id("op_b"),
            step: AdminStep::OlsPreflight,
        };
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &other, Record::Ols(&operation)).err(),
            Some(ExecutorError::BindingDenied)
        );
        let running = capture(CaptureState::Running);
        for step in [
            AdminStep::OlsPreflight,
            AdminStep::OlsReload,
            AdminStep::OlsVerify,
            AdminStep::OlsStart,
            AdminStep::OlsStop,
        ] {
            assert_eq!(
                authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Capture(&running)).err(),
                Some(ExecutorError::BindingDenied)
            );
        }
    }

    #[test]
    fn an_ols_step_runs_once_per_journal_state() {
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        let attempted = ols(RecordedState::Intent, true);
        assert_eq!(helper.ols_once(&attempted, AdminStep::OlsReload), Ok(()));
        assert_eq!(
            helper.ols_once(&attempted, AdminStep::OlsReload),
            Err(ExecutorError::ReplayDenied)
        );
        assert_eq!(helper.ols_once(&attempted, AdminStep::OlsVerify), Ok(()));
        // The one compensation gets its own reload and verify, once.
        let compensating = ols(RecordedState::Compensating, true);
        assert_eq!(helper.ols_once(&compensating, AdminStep::OlsReload), Ok(()));
        assert_eq!(
            helper.ols_once(&compensating, AdminStep::OlsReload),
            Err(ExecutorError::ReplayDenied)
        );
        // W355: the bootstrap start and its compensation's stop, once each.
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        let started = bootstrap_ols(RecordedState::Intent, true);
        assert_eq!(helper.ols_once(&started, AdminStep::OlsStart), Ok(()));
        assert_eq!(
            helper.ols_once(&started, AdminStep::OlsStart),
            Err(ExecutorError::ReplayDenied)
        );
        let stopping = bootstrap_ols(RecordedState::Compensating, true);
        assert_eq!(helper.ols_once(&stopping, AdminStep::OlsStop), Ok(()));
        assert_eq!(
            helper.ols_once(&stopping, AdminStep::OlsStop),
            Err(ExecutorError::ReplayDenied)
        );
        // W382 (D-033): the bootstrap confirmation changes nothing, so a
        // second `reconcile` in the same journal state may ask again (for
        // example after the operator stopped OLS).
        for state in [
            RecordedState::Intent,
            RecordedState::NeedsAttention,
            RecordedState::Compensating,
        ] {
            let row = bootstrap_ols(state, true);
            for _ in 0..3 {
                assert_eq!(
                    helper.ols_once(&row, AdminStep::OlsBootstrapConfirm),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn a_capture_or_probe_runs_once_per_helper() {
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        let later = helper.started + 1;
        assert_eq!(helper.once(&id("op_a"), later), Ok(()));
        assert_eq!(helper.once(&id("op_b"), later), Ok(()));
        assert_eq!(
            helper.once(&id("op_a"), later),
            Err(ExecutorError::ReplayDenied)
        );
    }

    #[test]
    fn a_restarted_helper_refuses_operations_journaled_before_it_started() {
        // W176: a new helper process re-ran a capture still `running`.
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        let started = helper.started;
        for journaled_at in [started - 3600, started] {
            assert_eq!(
                helper.once(&id("op_old"), journaled_at),
                Err(ExecutorError::ReplayDenied)
            );
        }
        assert_eq!(helper.once(&id("op_new"), started + 1), Ok(()));
    }

    #[test]
    fn replies_carry_a_payload_or_a_known_code() {
        assert_eq!(parse_reply("ok\n"), Ok(Reply::Done(None)));
        assert_eq!(
            parse_reply("ok {\"a\":1}\n"),
            Ok(Reply::Done(Some("{\"a\":1}".to_owned())))
        );
        assert_eq!(
            parse_reply("REPLAY_DENIED\n"),
            Ok(Reply::Refused(ExecutorError::ReplayDenied))
        );
        for bad in ["ok", "ok\nok\n", "WHATEVER\n", ""] {
            assert_eq!(parse_reply(bad), Err(ExecutorError::Unavailable), "{bad:?}");
        }
        let long = format!("ok {}\n", "x".repeat(MAX_ADMIN_REPLY_BYTES));
        assert_eq!(parse_reply(&long), Err(ExecutorError::Unavailable));
        for error in ExecutorError::ALL {
            assert_eq!(
                parse_reply(&format!("{}\n", error.code())),
                Ok(Reply::Refused(error))
            );
        }
    }

    /// W272: what the helper writes is exactly what the executor reads, for
    /// every reply shape it sends, and the ceiling sits at the full line.
    #[test]
    fn reply_lines_round_trip_through_the_shared_wire() {
        let mut lines = vec![
            ReplyLine::Done(None),
            ReplyLine::Done(Some("")),
            ReplyLine::Done(Some("{\"a\":1}")),
        ];
        let codes: Vec<&str> = ExecutorError::ALL.iter().map(|e| e.code()).collect();
        lines.extend(codes.iter().map(|code| ReplyLine::Code(code)));
        for line in lines {
            assert_eq!(decode_reply(&line.encode()), Some(line), "{line:?}");
        }
        let at_ceiling = "x".repeat(MAX_ADMIN_REPLY_BYTES - 4);
        let encoded = ReplyLine::Done(Some(&at_ceiling)).encode();
        assert_eq!(encoded.len(), MAX_ADMIN_REPLY_BYTES);
        assert!(decode_reply(&encoded).is_some());
        // A newline inside a payload is never readable as a different reply.
        assert_eq!(
            decode_reply(&ReplyLine::Done(Some("a\nREPLAY_DENIED")).encode()),
            None
        );
    }

    const ROOT_FOR_RELAY: &str = "/srv/sites/rs_blog";

    fn relay_snapshot(path: &str) -> crate::capture::CapturedSnapshot {
        let digest = crate::manifest::format::digest_hex(b"x");
        let stream = format!(
            "{{\"path\":\"{path}\",\"kind\":\"file\",\"size\":1,\"sha256\":\"{digest}\",\"mode\":420}}\n{{\"end\":{{\"entries\":1,\"regular_bytes\":1,\"truncated\":false}}}}\n"
        );
        crate::capture::CapturedSnapshot {
            id: "ab".repeat(32),
            files: Some(1),
            bytes: Some(1),
            manifest: crate::manifest::from_worker(
                stream.as_bytes(),
                ROOT_FOR_RELAY,
                &crate::capture::dump_path(ROOT_FOR_RELAY),
            ),
            consistency: rustiron_journal::CaptureConsistency::Matched,
            retention: None,
        }
    }

    /// W391: relayed retention evidence round-trips; evidence that does not
    /// name the snapshot is dropped and the capture stays succeeded.
    #[test]
    fn relayed_retention_evidence_round_trips_and_a_bad_one_is_dropped() {
        use crate::capture::CaptureOutcome as O;
        let mut snapshot = relay_snapshot("srv/sites/rs_blog/html/index.php");
        snapshot.retention = Some(rustiron_journal::RetentionEvidence {
            before_days: 30,
            after_days: 30,
            objects: vec![rustiron_journal::ObjectRetention {
                kind: rustiron_journal::RetainedObjectKind::Snapshot,
                object_id: "ab".repeat(32),
                version_id: "76b01aea-db7c-4b38-b41d-3c031085d108".to_owned(),
                retain_until: 1_797_183_776,
            }],
        });
        let outcome = O::Succeeded(snapshot.clone());
        assert_eq!(
            decode_capture(&encode_capture(&outcome), ROOT_FOR_RELAY),
            outcome
        );
        let changed = encode_capture(&outcome).replace(&"ab".repeat(32), &"cd".repeat(32));
        let O::Succeeded(other) = decode_capture(
            &changed.replacen(&"cd".repeat(32), &"ab".repeat(32), 1),
            ROOT_FOR_RELAY,
        ) else {
            panic!("capture must stay succeeded");
        };
        assert_eq!(other.retention, None);
    }

    #[test]
    fn a_relayed_manifest_round_trips_and_a_bad_one_is_dropped_not_fatal() {
        use crate::capture::CaptureOutcome as O;
        let snapshot = relay_snapshot("srv/sites/rs_blog/html/index.php");
        assert!(snapshot.manifest.is_some());
        let outcome = O::Succeeded(snapshot.clone());
        assert_eq!(
            decode_capture(&encode_capture(&outcome), ROOT_FOR_RELAY),
            outcome
        );
        // Another site's root, or a tampered digest, drops only the manifest.
        let O::Succeeded(other) = decode_capture(&encode_capture(&outcome), "/srv/sites/rs_other")
        else {
            panic!("capture must stay succeeded");
        };
        assert_eq!(other.manifest, None);
        let digest = &snapshot.manifest.as_ref().unwrap().sha256;
        let tampered = encode_capture(&outcome).replace(digest.as_str(), &"0".repeat(64));
        let O::Succeeded(tampered) = decode_capture(&tampered, ROOT_FOR_RELAY) else {
            panic!("capture must stay succeeded");
        };
        assert_eq!(
            (tampered.id, tampered.manifest),
            (snapshot.id.clone(), None)
        );
        // A manifest that would overflow the reply is left out of it.
        let mut huge = snapshot.clone();
        let built = huge.manifest.as_mut().unwrap();
        built.bytes = vec![b'a'; MAX_ADMIN_REPLY_BYTES];
        let line = encode_capture(&O::Succeeded(huge));
        assert!(
            line.len() < 1024 && !line.contains("manifest"),
            "{}",
            line.len()
        );
    }

    #[test]
    fn capture_outcomes_round_trip_and_unknown_is_uncertain() {
        use crate::capture::{CaptureOutcome as O, CapturedSnapshot};
        let snap = "ab".repeat(32);
        for outcome in [
            O::Succeeded(CapturedSnapshot {
                id: snap.clone(),
                files: Some(3),
                bytes: None,
                manifest: None,
                consistency: rustiron_journal::CaptureConsistency::Matched,
                retention: None,
            }),
            O::NotStarted(ExecutorError::Unavailable),
            O::Uncertain {
                error: ExecutorError::StepFailed,
                snapshot: Some(snap.clone()),
            },
            O::Uncertain {
                error: ExecutorError::Unavailable,
                snapshot: None,
            },
        ] {
            assert_eq!(
                decode_capture(&encode_capture(&outcome), ROOT_FOR_RELAY),
                outcome
            );
        }
        let uncertain = O::Uncertain {
            error: ExecutorError::Unavailable,
            snapshot: None,
        };
        for bad in [
            "",
            "{}",
            "{\"outcome\":\"succeeded\",\"id\":\"short\"}",
            "{\"outcome\":\"failed\"}",
        ] {
            assert_eq!(decode_capture(bad, ROOT_FOR_RELAY), uncertain, "{bad}");
        }
    }

    #[test]
    fn each_consistency_label_round_trips_and_a_missing_one_is_never_matched() {
        use crate::capture::{CaptureOutcome as O, CapturedSnapshot};
        use rustiron_journal::{CaptureConsistency as C, UnmatchedReason as R};
        for consistency in [
            C::Matched,
            C::Unmatched(R::DatabaseChanged),
            C::Unmatched(R::MarkerUnavailable),
        ] {
            let outcome = O::Succeeded(CapturedSnapshot {
                id: "ab".repeat(32),
                files: None,
                bytes: None,
                manifest: None,
                consistency,
                retention: None,
            });
            assert_eq!(
                decode_capture(&encode_capture(&outcome), ROOT_FOR_RELAY),
                outcome
            );
        }
        let id = "ab".repeat(32);
        for line in [
            format!("{{\"outcome\":\"succeeded\",\"id\":\"{id}\"}}"),
            format!(
                "{{\"outcome\":\"succeeded\",\"id\":\"{id}\",\"consistency\":{{\"label\":\"matched\",\"reason\":\"x\"}}}}"
            ),
            format!(
                "{{\"outcome\":\"succeeded\",\"id\":\"{id}\",\"consistency\":{{\"label\":\"unmatched\",\"reason\":\"freeze_missed\"}}}}"
            ),
            format!("{{\"outcome\":\"succeeded\",\"id\":\"{id}\",\"consistency\":\"matched\"}}"),
        ] {
            let O::Succeeded(snapshot) = decode_capture(&line, ROOT_FOR_RELAY) else {
                panic!("a label problem must not change the outcome: {line}");
            };
            assert_eq!(
                snapshot.consistency,
                C::Unmatched(R::MarkerUnavailable),
                "{line}"
            );
        }
    }

    #[test]
    fn freeze_not_held_relays_only_for_a_frozen_capture_and_a_lost_label_is_never_held() {
        use crate::capture::{CaptureOutcome as O, CapturedSnapshot};
        use rustiron_journal::{CaptureConsistency as C, UnmatchedReason as R};
        let outcome = O::Succeeded(CapturedSnapshot {
            id: "ab".repeat(32),
            files: None,
            bytes: None,
            manifest: None,
            consistency: C::Unmatched(R::FreezeNotHeld),
            retention: None,
        });
        let line = encode_capture(&outcome);
        assert_eq!(decode_capture_for(&line, ROOT_FOR_RELAY, true), outcome);
        let O::Succeeded(plain) = decode_capture(&line, ROOT_FOR_RELAY) else {
            panic!("outcome changed");
        };
        assert_eq!(plain.consistency, C::Unmatched(R::MarkerUnavailable));
        let id = "ab".repeat(32);
        for lost in [
            format!("{{\"outcome\":\"succeeded\",\"id\":\"{id}\"}}"),
            format!("{{\"outcome\":\"succeeded\",\"id\":\"{id}\",\"consistency\":\"matched\"}}"),
        ] {
            let O::Succeeded(snapshot) = decode_capture_for(&lost, ROOT_FOR_RELAY, true) else {
                panic!("outcome changed: {lost}");
            };
            assert_eq!(
                snapshot.consistency,
                C::Unmatched(R::FreezeNotHeld),
                "{lost}"
            );
        }
    }

    #[test]
    fn refused_probe_is_failed_and_unknown_stays_running() {
        let (receipt, state) =
            probe_outcome(Reply::Refused(ExecutorError::Unavailable), "rp_00aa11").unwrap();
        assert_eq!(state, ProbeState::Failed);
        assert_eq!(receipt["refused"], "EXECUTOR_DEPENDENCY_UNAVAILABLE");
        assert_eq!(
            probe_outcome(Reply::Done(Some("junk".to_owned())), "rp_00aa11"),
            Err(ExecutorError::Unavailable)
        );
        assert_eq!(
            probe_outcome(Reply::Done(None), "rp_00aa11"),
            Err(ExecutorError::Unavailable)
        );
    }

    #[test]
    fn probe_replies_need_a_final_state_and_a_receipt() {
        let receipt = serde_json::json!({"hostname": "blog1.example"});
        for state in [
            ProbeState::Passed,
            ProbeState::Failed,
            ProbeState::CleanupIncomplete,
        ] {
            assert_eq!(
                decode_probe(&encode_probe(&receipt, state)),
                Some((receipt.clone(), state))
            );
        }
        assert_eq!(
            decode_probe(&encode_probe(&receipt, ProbeState::Running)),
            None
        );
        assert_eq!(decode_probe("{\"state\":\"passed\",\"receipt\":1}"), None);
        assert_eq!(decode_probe("nope"), None);
    }

    #[test]
    fn exactly_one_record_is_required() {
        let none = OperationRecords::default();
        assert_eq!(
            single_record(&none).err(),
            Some(ExecutorError::BindingDenied)
        );
        let both = OperationRecords {
            provision: Some(provision(ProvisionStep::Account, StepState::Intent)),
            probe: Some(probe(ProbeState::Running)),
            capture: None,
            probe_source: None,
            ..Default::default()
        };
        assert_eq!(
            single_record(&both).err(),
            Some(ExecutorError::BindingDenied)
        );
        let one = OperationRecords {
            provision: both.provision.clone(),
            probe: None,
            capture: None,
            probe_source: None,
            ..Default::default()
        };
        assert!(matches!(single_record(&one), Ok(Record::Provision(_))));
        // W200: an OLS operation is one record; with any other it is refused.
        let ols = OperationRecords {
            operation: Some(ols(RecordedState::Intent, false)),
            ..Default::default()
        };
        assert!(matches!(single_record(&ols), Ok(Record::Ols(_))));
        // W387: an OLS operation with its own ejection row is an ejection.
        let ejection = OperationRecords {
            ejection: Some(
                rustiron_contracts::approval::SiteId::try_from("blog9".to_owned()).unwrap(),
            ),
            ..ols.clone()
        };
        assert!(matches!(
            single_record(&ejection),
            Ok(Record::Ejection(_, site)) if site.as_str() == "blog9"
        ));
        let stray = OperationRecords {
            ejection: ejection.ejection.clone(),
            ..Default::default()
        };
        assert_eq!(
            single_record(&stray).err(),
            Some(ExecutorError::BindingDenied),
            "an ejection site without its operation"
        );
        let static_eject = OperationRecords {
            static_ejection: Some(Hostname::try_from("static.example.test".to_owned()).unwrap()),
            ..ejection.clone()
        };
        assert!(matches!(
            single_record(&static_eject),
            Ok(Record::Ejection(_, site)) if site.as_str() == "blog9"
        ));
        let stray_static = OperationRecords {
            static_ejection: static_eject.static_ejection.clone(),
            ..ols.clone()
        };
        assert_eq!(
            single_record(&stray_static).err(),
            Some(ExecutorError::BindingDenied),
            "a static ejection hostname without its ejection site"
        );
        let orphan_static = OperationRecords {
            static_ejection: static_eject.static_ejection.clone(),
            ..Default::default()
        };
        assert_eq!(
            single_record(&orphan_static).err(),
            Some(ExecutorError::BindingDenied),
            "a static ejection hostname without its operation"
        );
        let mixed = OperationRecords {
            provision: both.provision.clone(),
            operation: ols.operation.clone(),
            ..Default::default()
        };
        assert_eq!(
            single_record(&mixed).err(),
            Some(ExecutorError::BindingDenied)
        );
    }

    /// W377: a re-adoption row of either form.
    fn readoption(state: ReadoptState, site_form: bool) -> rustiron_journal::Readoption {
        use rustiron_contracts::approval::ReadoptForm;
        rustiron_journal::Readoption {
            intent: rustiron_journal::ReadoptionIntent {
                operation_id: id("op_a"),
                idempotency_key: id("k"),
                grant_id: id("g"),
                nonce: id("n"),
                plan_digest: digest(),
                grant_digest: digest(),
                host_id: id("h"),
                host_epoch: id("e"),
                form: if site_form {
                    ReadoptForm::Site
                } else {
                    ReadoptForm::Generation
                },
                site: site_form.then(|| {
                    (
                        site(),
                        Hostname::try_from("blog1.example.test".to_owned()).unwrap(),
                    )
                }),
                previous_epoch: id("e0"),
                evidence_sha256: digest(),
                expires_at: time(),
                plan: "{}".to_owned(),
            },
            state,
            facts: None,
            refusal: None,
        }
    }

    /// W377 (B06): the helper's `readopt_observe` decision matrix. Only a
    /// `verifying` re-adoption of the named operation, from the executor
    /// peer, may be observed; the site and root come from the journaled
    /// row; no other step is ever authorized for a re-adoption, and the
    /// observation step for no other record.
    #[test]
    fn readopt_observe_follows_the_journal_state_only() {
        for site_form in [true, false] {
            for state in [
                ReadoptState::Verifying,
                ReadoptState::Adopted,
                ReadoptState::Refused,
            ] {
                let row = readoption(state, site_form);
                for step in AdminStep::ALL {
                    let decided =
                        authorize(EXECUTOR, EXECUTOR, &ask(step), Record::Readoption(&row));
                    if step == AdminStep::ReadoptObserve && state == ReadoptState::Verifying {
                        let action = decided.unwrap();
                        let (account, root) = if site_form {
                            ("rs_blog1", PathBuf::from("/srv/sites/rs_blog1"))
                        } else {
                            ("ols_lab_listener", PathBuf::from(crate::ols::INCLUDE_DIR))
                        };
                        assert_eq!(action.account, account);
                        assert_eq!(action.root, root);
                    } else {
                        assert_eq!(
                            decided.err(),
                            Some(ExecutorError::BindingDenied),
                            "{site_form} {state:?} {step:?}"
                        );
                    }
                }
            }
        }
        let verifying = readoption(ReadoptState::Verifying, true);
        assert_eq!(
            authorize(
                1000,
                EXECUTOR,
                &ask(AdminStep::ReadoptObserve),
                Record::Readoption(&verifying)
            )
            .err(),
            Some(ExecutorError::PeerDenied)
        );
        let other = AdminRequest {
            operation_id: id("op_b"),
            step: AdminStep::ReadoptObserve,
        };
        assert_eq!(
            authorize(EXECUTOR, EXECUTOR, &other, Record::Readoption(&verifying)).err(),
            Some(ExecutorError::BindingDenied)
        );
        let observe = ask(AdminStep::ReadoptObserve);
        let provision = provision(ProvisionStep::Account, StepState::Intent);
        let (probe, capture) = (probe(ProbeState::Running), capture(CaptureState::Running));
        let attempted = ols(RecordedState::Intent, false);
        for record in [
            Record::Provision(&provision),
            Record::Probe(&probe),
            Record::Capture(&capture),
            Record::Ols(&attempted),
        ] {
            assert_eq!(
                authorize(EXECUTOR, EXECUTOR, &observe, record).err(),
                Some(ExecutorError::BindingDenied),
                "{record:?}"
            );
        }
    }

    /// W377: an adopted provision row shares its re-adoption's ID and is
    /// not a second record; any other record beside a re-adoption is.
    #[test]
    fn a_readoption_is_one_record_beside_only_its_own_adopted_provision() {
        let row = readoption(ReadoptState::Adopted, true);
        let mut adopted = provision(ProvisionStep::Account, StepState::Done);
        adopted.state = ProvisionState::Adopted;
        let records = OperationRecords {
            provision: Some(adopted.clone()),
            readoption: Some(row.clone()),
            ..Default::default()
        };
        assert!(matches!(single_record(&records), Ok(Record::Readoption(_))));
        // A running provision under the same ID is not the adopted row.
        let running = provision(ProvisionStep::Account, StepState::Intent);
        let mixed = OperationRecords {
            provision: Some(running),
            readoption: Some(row.clone()),
            ..Default::default()
        };
        assert_eq!(
            single_record(&mixed).err(),
            Some(ExecutorError::BindingDenied)
        );
        // An adopted provision of another operation is not this one's.
        adopted.intent.operation_id = id("op_b");
        let foreign = OperationRecords {
            provision: Some(adopted),
            readoption: Some(row.clone()),
            ..Default::default()
        };
        assert_eq!(
            single_record(&foreign).err(),
            Some(ExecutorError::BindingDenied)
        );
        let with_capture = OperationRecords {
            capture: Some(capture(CaptureState::Running)),
            readoption: Some(row),
            ..Default::default()
        };
        assert_eq!(
            single_record(&with_capture).err(),
            Some(ExecutorError::BindingDenied)
        );
    }

    #[test]
    fn planned_number_comes_from_the_last_step_only() {
        let mut record = provision(ProvisionStep::Labels, StepState::Intent);
        record.steps[0].resource = "uid=3001".to_owned();
        record.steps.last_mut().unwrap().resource = "level=s0:c205".to_owned();
        assert_eq!(planned(Record::Provision(&record), "level=s0:c"), Ok(205));
        assert_eq!(
            planned(Record::Provision(&record), "uid="),
            Err(ExecutorError::BindingDenied)
        );
    }

    #[test]
    fn stranger_peer_is_refused_before_the_journal() {
        let mut anchor = TrustAnchor::lab();
        anchor.owner_uid = rustix::process::getuid().as_raw().wrapping_add(1);
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .write_all(&ask(AdminStep::CaptureRun).encode())
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        handle(&anchor, server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "PEER_DENIED\n");
    }

    #[test]
    fn enrolled_socket_routes_through_the_helper() {
        let dir = std::env::temp_dir().join(format!("ri-admin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            stream.write_all(b"ok\n").unwrap();
            bytes
        });
        let asked = ask(AdminStep::ProvisionStep);
        let routed = route(Some(&socket), &asked, || panic!("ran in process"));
        assert_eq!(routed, Ok(()));
        assert_eq!(server.join().unwrap(), asked.encode());
        assert_eq!(route(None, &asked, || Ok(())), Ok(()));
        let missing = dir.join("absent.sock");
        assert_eq!(
            request(&missing, &asked),
            Ok(Reply::Refused(ExecutorError::HelperUnreachable))
        );
        assert_eq!(
            route(Some(&missing), &asked, || Ok(())),
            Err(ExecutorError::HelperUnreachable)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn context_type_reads_the_third_field() {
        assert_eq!(
            context_type("system_u:system_r:rustiron_executor_t:s0\0"),
            Some("rustiron_executor_t")
        );
        assert_eq!(
            context_type("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\n"),
            Some("unconfined_t")
        );
        assert_eq!(context_type("kernel"), None);
        assert_eq!(context_type("a:b::s0"), None);
    }

    #[test]
    fn same_uid_peer_outside_the_executor_domain_is_refused() {
        let mut anchor = TrustAnchor::lab();
        anchor.owner_uid = rustix::process::getuid().as_raw();
        // This test process is never in the lab executor domain.
        assert_ne!(process_type("self").as_deref(), Some(LAB_EXECUTOR_TYPE));
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        client
            .write_all(&ask(AdminStep::ProvisionStep).encode())
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        Helper::new(anchor, Some(LAB_EXECUTOR_TYPE.to_owned())).handle(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "PEER_DENIED\n");
    }

    fn status_reply(anchor: TrustAnchor, peer_type: Option<&str>, bytes: &[u8]) -> String {
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        client.write_all(bytes).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        Helper::new(anchor, peer_type.map(str::to_owned)).handle(server);
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn ols_status_keeps_the_peer_checks() {
        let mut stranger = TrustAnchor::lab();
        stranger.owner_uid = rustix::process::getuid().as_raw().wrapping_add(1);
        assert_eq!(
            status_reply(stranger, None, OLS_STATUS_REQUEST),
            "PEER_DENIED\n"
        );
        let mut same_uid = TrustAnchor::lab();
        same_uid.owner_uid = rustix::process::getuid().as_raw();
        assert_eq!(
            status_reply(same_uid, Some(LAB_EXECUTOR_TYPE), OLS_STATUS_REQUEST),
            "PEER_DENIED\n"
        );
    }

    #[test]
    fn ols_status_never_reaches_the_journal_or_a_step() {
        // The enrolled peer asking a near-miss of the status line gets the
        // ordinary parse refusal, never the read-only checks.
        let mut own = TrustAnchor::lab();
        own.owner_uid = rustix::process::getuid().as_raw();
        for bytes in [
            &b"v1 ols_status"[..],
            b"v1 ols_status \n",
            b"v1 ols_status\r\n",
            b"v1 ols_status\n\n",
            b"v2 ols_status\n",
            b"v1 op_w202 ols_status\n",
        ] {
            assert_eq!(
                status_reply(own.clone(), None, bytes),
                "INVALID_REQUEST\n",
                "{bytes:?}"
            );
        }
        // The exact line runs only the observation; in this test process
        // the enrolled policy is absent, so it is refused, not "ok".
        assert!(!status_reply(own, None, OLS_STATUS_REQUEST).starts_with("ok"));
    }

    #[test]
    fn recipe_step_without_a_recorded_recipe_is_refused() {
        let mut record = provision(ProvisionStep::Recipe, StepState::Intent);
        record.steps.last_mut().unwrap().resource = "Recipe rs_blog1".to_owned();
        let action = authorize(
            EXECUTOR,
            EXECUTOR,
            &ask(AdminStep::ProvisionStep),
            Record::Provision(&record),
        )
        .unwrap();
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        assert_eq!(
            helper.provision_step(&action, &record, None, None, None, None, false),
            Err(ExecutorError::BindingDenied)
        );
    }

    /// W572 (D-095): the executor journals a proxy site's Database,
    /// Credentials and PhpUnits steps without the helper, so the helper
    /// refuses to run one and changes nothing.
    #[test]
    fn a_proxy_site_step_without_an_effect_is_refused() {
        let mut helper = Helper::new(TrustAnchor::lab(), None);
        for step in [
            ProvisionStep::Database,
            ProvisionStep::Credentials,
            ProvisionStep::PhpUnits,
        ] {
            let record = provision(step, StepState::Intent);
            let action = authorize(
                EXECUTOR,
                EXECUTOR,
                &ask(AdminStep::ProvisionStep),
                Record::Provision(&record),
            )
            .unwrap();
            assert_eq!(
                helper.provision_step(&action, &record, None, None, None, None, true),
                Err(ExecutorError::BindingDenied),
                "{step:?}"
            );
            assert!(helper.password.is_none());
        }
    }

    /// W399: the Verify step runs with the recipe that the Recipe step
    /// journaled. The first W399 VM run read it from the Verify record, which
    /// names no recipe, so the helper verified an installed site against the
    /// unpack-only recipe and quarantined it.
    #[test]
    fn verify_runs_with_the_recipe_that_the_recipe_step_journaled() {
        use rustiron_contracts::approval::SiteRecipe;
        let mut record = provision(ProvisionStep::Verify, StepState::Intent);
        let recipe = ProvisionStep::ALL
            .iter()
            .position(|step| *step == ProvisionStep::Recipe)
            .unwrap();
        record.steps[recipe].resource = "Recipe rs_blog1 recipe=wordpress713_install_v1".to_owned();
        assert_eq!(
            step_recipe(&record, ProvisionStep::Verify),
            Ok(SiteRecipe::Wordpress713InstallV1)
        );
        assert_eq!(
            step_recipe(&record, ProvisionStep::Recipe),
            Ok(SiteRecipe::Wordpress713InstallV1)
        );
        record.steps[recipe].resource = "Recipe rs_blog1".to_owned();
        assert_eq!(
            step_recipe(&record, ProvisionStep::Verify),
            Err(ExecutorError::BindingDenied)
        );
        let early = provision(ProvisionStep::Database, StepState::Intent);
        assert_eq!(
            step_recipe(&early, ProvisionStep::Database),
            Ok(SiteRecipe::Wordpress713V1),
            "steps before the Recipe step do not read the recipe"
        );
    }

    #[test]
    fn recipe_names_round_trip() {
        use rustiron_contracts::approval::SiteRecipe;
        for recipe in [
            SiteRecipe::Wordpress713V1,
            SiteRecipe::Wordpress713InstallV1,
        ] {
            assert_eq!(
                crate::durable::recipe_from_name(crate::durable::recipe_name(recipe)),
                Some(recipe)
            );
        }
        assert_eq!(crate::durable::recipe_from_name("wordpress"), None);
    }

    #[test]
    fn credentials_without_the_database_password_fail_closed() {
        let layout = SiteLayout::derive(&site());
        let pinned = digest();
        let host =
            rustiron_contracts::approval::Hostname::try_from("blog1.example".to_owned()).unwrap();
        let step = crate::durable::SiteStep {
            layout: &layout,
            allocated: 0,
            recipe: rustiron_contracts::approval::SiteRecipe::Wordpress713V1,
            hostname: &host,
            wordpress: &pinned,
            recipes_dir: std::path::Path::new("/nonexistent"),
            quota: crate::quota::QuotaPlan::NotEnforced,
            site_uid: None,
        };
        assert_eq!(
            crate::durable::run_site_step(ProvisionStep::Credentials, &step, &mut None),
            Err(ExecutorError::StepFailed)
        );
    }
}

/// W186: request lines are read concurrently and within a whole deadline;
/// decisions stay on the one thread that owns the helper.
mod serving {
    use std::{
        io::{Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::PathBuf,
        time::{Duration, Instant},
    };

    use super::super::*;

    fn server(name: &str, max_reads: usize) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ri-w186-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        // A peer type nobody has: every request is refused before any journal read.
        let mut helper = Helper::new(TrustAnchor::lab(), Some("w186_nobody_t".to_owned()));
        std::thread::spawn(move || {
            let _ = serve_helper(&mut helper, &listener, max_reads);
        });
        socket
    }

    fn ask(socket: &PathBuf, line: &[u8]) -> (String, Duration) {
        let started = Instant::now();
        let mut stream = UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let _ = stream.write_all(line);
        let _ = stream.shutdown(std::net::Shutdown::Write);
        let mut reply = String::new();
        let _ = stream.read_to_string(&mut reply);
        (reply, started.elapsed())
    }

    fn idle(socket: &PathBuf, count: usize) -> Vec<UnixStream> {
        let held = (0..count)
            .map(|_| UnixStream::connect(socket).unwrap())
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        held
    }

    const LINE: &[u8] = b"v1 op_w186 capture_run\n";

    #[test]
    fn an_idle_connection_does_not_delay_the_next_request() {
        let socket = server("idle", MAX_PENDING_READS);
        let _held = idle(&socket, 3);
        let (reply, took) = ask(&socket, LINE);
        assert_eq!(reply, "PEER_DENIED\n");
        assert!(took < Duration::from_secs(1), "took {took:?}");
    }

    #[test]
    fn a_slow_writer_is_cut_at_the_whole_read_deadline() {
        let socket = server("slow", MAX_PENDING_READS);
        let mut slow = UnixStream::connect(&socket).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let started = Instant::now();
        let drip = {
            let mut writer = slow.try_clone().unwrap();
            std::thread::spawn(move || {
                for _ in 0..200 {
                    if writer.write_all(b"v").is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
        };
        let (reply, took) = ask(&socket, LINE);
        assert_eq!(reply, "PEER_DENIED\n");
        assert!(took < Duration::from_secs(1), "took {took:?}");
        let mut cut = String::new();
        let _ = slow.read_to_string(&mut cut);
        let elapsed = started.elapsed();
        assert_eq!(cut, "INVALID_REQUEST\n");
        assert!(
            elapsed < READ_DEADLINE + Duration::from_secs(1),
            "{elapsed:?}"
        );
        drop(slow);
        drip.join().unwrap();
    }

    #[test]
    fn the_read_limit_refuses_at_once_and_frees_on_close() {
        let socket = server("cap", 2);
        let held = idle(&socket, 2);
        let (reply, took) = ask(&socket, LINE);
        assert_eq!(reply, "EXECUTOR_DEPENDENCY_UNAVAILABLE\n");
        assert!(took < Duration::from_secs(1), "took {took:?}");
        drop(held);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(ask(&socket, LINE).0, "PEER_DENIED\n");
    }

    /// W361: the helper unit is `Type=simple`, so `systemctl start` returns
    /// before the helper binds its socket. Step 10 of the enrollment
    /// procedure (`ols-status --admin-helper` right after the start) failed
    /// with `EXECUTOR_DEPENDENCY_UNAVAILABLE` on a fresh host, two of three
    /// times. The status client waits for the socket as `reach` does.
    #[test]
    fn ols_status_waits_for_a_helper_that_binds_late() {
        use std::io::{Read, Write};
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("ri-status-late-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let _ = std::fs::remove_file(&socket);
        let checks = crate::ols::ServerChecks {
            parent_reviewed: true,
            webadmin_closed: false,
            adopted_vhosts_pinned: true,
            php_capacity: true,
            page_cache_ols_tested: true,
        };
        let late = socket.clone();
        let helper = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let listener = std::os::unix::net::UnixListener::bind(&late).unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).unwrap();
            let reply = ReplyLine::Done(Some(&checks.encode())).encode();
            stream.write_all(reply.as_bytes()).unwrap();
            request
        });
        assert_eq!(ols_status(&socket), Ok(checks));
        assert_eq!(helper.join().unwrap(), OLS_STATUS_REQUEST);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_absent_helper_socket_is_a_visible_error_after_the_wait() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("ri-reach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("helper.sock");
        let _ = std::fs::remove_file(&socket);
        let pause = Duration::from_millis(20);
        assert_eq!(
            reach(&socket, 3, pause),
            Err(ExecutorError::HelperUnreachable)
        );
        std::fs::write(&socket, b"").unwrap();
        assert_eq!(
            reach(&socket, 3, pause),
            Err(ExecutorError::HelperUnreachable),
            "not a socket"
        );
        std::fs::remove_file(&socket).unwrap();
        let late = socket.clone();
        let restarting = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            std::os::unix::net::UnixListener::bind(&late).unwrap()
        });
        assert_eq!(reach(&socket, 50, pause), Ok(()));
        drop(restarting.join().unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
