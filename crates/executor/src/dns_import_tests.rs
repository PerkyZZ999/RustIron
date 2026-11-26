//! W563: the zone import step against a fake PowerDNS.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use rustiron_contracts::Id;
use rustiron_contracts::approval::{Sha256Digest, ZoneName};
use rustiron_journal::{DnsImport, StepState};
use sha2::{Digest, Sha256};

use super::*;
use crate::test_support::{hex, private_dir, private_file};

/// A canonical zone with every type, as `pdnsutil zone list` would print
/// it after the load (tabs), with the file's own SOA and NS.
const ZONE: &str = "\
*.example.test. 3600 IN A 203.0.113.20
_dmarc.example.test. 3600 IN TXT \"v=DMARC1; p=none\"
example.test. 3600 IN A 203.0.113.10
example.test. 3600 IN CAA 0 issue \"letsencrypt.org\"
example.test. 3600 IN MX 10 mail.example.test.
example.test. 3600 IN NS ns.old-provider.example.
example.test. 3600 IN SOA ns.old-provider.example. admin.old-provider.example. 2026112101 7200 1800 1209600 300
example.test. 3600 IN TXT \"v=spf1 mx ~all\"
www.example.test. 300 IN CNAME example.test.
";

fn zone() -> ZoneName {
    ZoneName::try_from("example.test".to_owned()).unwrap()
}

fn policy() -> DnsPolicy {
    serde_json::from_str(
        r#"{"listen":["203.0.113.10"],
            "name_servers":["ns1.example.test","ns2.example.test"],
            "hostmaster":"hostmaster.example.test",
            "secondaries":["198.51.100.53"],
            "tsig_key":"rustiron-axfr",
            "soa":{"refresh":10800,"retry":3600,"expire":604800,"negative_ttl":3600}}"#,
    )
    .unwrap()
}

fn sha(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn import(text: &str) -> DnsImport {
    DnsImport {
        operation_id: Id::try_from("op_w563".to_owned()).unwrap(),
        zone: zone(),
        zone_sha256: sha(text.as_bytes()),
        record_sets: 9,
        state: StepState::Intent,
    }
}

/// A private intake folder holding `<zone>/zone.txt`.
struct Intake {
    root: PathBuf,
}

impl Intake {
    fn new(text: &str) -> Self {
        let mut random = [0; 8];
        rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty()).unwrap();
        let root =
            std::env::temp_dir().join(format!("ri-dns-{}-{}", std::process::id(), hex(&random)));
        private_dir(&root.join("example.test"));
        private_file(&root.join("example.test").join(ZONE_FILE), text.as_bytes());
        Self { root }
    }
}

impl Drop for Intake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A PowerDNS that loads one zone, applies `rrset replace`, and lists it.
#[derive(Default)]
struct FakePdns {
    zones: Vec<String>,
    lines: Vec<String>,
    calls: Vec<String>,
    fail: Option<&'static str>,
    /// Extra text the listing prints, to break the read-back.
    extra: Option<&'static str>,
}

impl Pdns for FakePdns {
    fn util(&mut self, args: &[&str], input: Option<&[u8]>) -> Result<String, ExecutorError> {
        let call = args.join(" ");
        self.calls.push(call.clone());
        if self.fail.is_some_and(|prefix| call.starts_with(prefix)) {
            return Err(ExecutorError::StepFailed);
        }
        match args {
            ["zone", "list-all"] => Ok(self.zones.iter().map(|z| format!("{z}\n")).collect()),
            ["zone", "load", name, "/dev/stdin"] => {
                self.zones.push((*name).to_owned());
                let text = std::str::from_utf8(input.unwrap()).unwrap();
                self.lines = text.lines().map(str::to_owned).collect();
                Ok(String::new())
            }
            ["rrset", "replace", _, owner, kind, ttl, records @ ..] => {
                let prefix = format!("{owner} ");
                self.lines.retain(|line| {
                    !(line.starts_with(&prefix) && line.contains(&format!(" IN {kind} ")))
                });
                for record in records {
                    self.lines.push(format!("{owner} {ttl} IN {kind} {record}"));
                }
                Ok(String::new())
            }
            ["zone", "increase-serial", _] => {
                for line in &mut self.lines {
                    if line.contains(" IN SOA ") {
                        let mut fields: Vec<String> = line.split(' ').map(str::to_owned).collect();
                        let serial: u64 = fields[6].parse().unwrap();
                        fields[6] = (serial + 1).to_string();
                        *line = fields.join(" ");
                    }
                }
                Ok(String::new())
            }
            ["zone", "list", _] => {
                let mut text = String::from("$ORIGIN .\n");
                for line in &self.lines {
                    let fields: Vec<&str> = line.splitn(5, ' ').collect();
                    text.push_str(&fields.join("\t"));
                    text.push('\n');
                }
                if let Some(extra) = self.extra {
                    text.push_str(extra);
                }
                Ok(text)
            }
            _ => Ok(String::new()),
        }
    }

    fn control(&mut self, args: &[&str]) -> Result<(), ExecutorError> {
        self.calls.push(format!("control {}", args.join(" ")));
        Ok(())
    }
}

#[test]
fn an_import_loads_sets_authority_and_reads_back() {
    let intake = Intake::new(ZONE);
    let mut pdns = FakePdns::default();
    run(
        &mut pdns,
        &import(ZONE),
        &policy(),
        &intake.root,
        rustix::process::getuid().as_raw(),
    )
    .unwrap();
    assert_eq!(
        pdns.calls,
        [
            "zone list-all",
            "zone load example.test /dev/stdin",
            "zone set-kind example.test primary",
            "rrset replace example.test example.test. SOA 3600 ns1.example.test. hostmaster.example.test. 2026112101 10800 3600 604800 3600",
            "rrset replace example.test example.test. NS 3600 ns1.example.test. ns2.example.test.",
            "tsigkey activate example.test rustiron-axfr primary",
            "zone check example.test",
            "zone increase-serial example.test",
            "control rediscover",
            "zone list example.test",
        ]
    );
}

#[test]
fn a_zone_already_on_the_server_is_refused_before_any_effect() {
    let intake = Intake::new(ZONE);
    let mut pdns = FakePdns {
        zones: vec!["example.test.".to_owned()],
        ..FakePdns::default()
    };
    let owner = rustix::process::getuid().as_raw();
    assert_eq!(
        run(&mut pdns, &import(ZONE), &policy(), &intake.root, owner),
        Err(ExecutorError::PreconditionChanged)
    );
    assert_eq!(pdns.calls, ["zone list-all"]);
}

#[test]
fn a_changed_intake_file_is_refused_before_any_effect() {
    let intake = Intake::new(&ZONE.replace("203.0.113.20", "203.0.113.21"));
    let mut pdns = FakePdns::default();
    let owner = rustix::process::getuid().as_raw();
    assert_eq!(
        run(&mut pdns, &import(ZONE), &policy(), &intake.root, owner),
        Err(ExecutorError::PreconditionChanged)
    );
    assert!(pdns.calls.is_empty());
    let mut counted = import(ZONE);
    counted.record_sets = 10;
    let intake = Intake::new(ZONE);
    assert_eq!(
        run(&mut pdns, &counted, &policy(), &intake.root, owner),
        Err(ExecutorError::PreconditionChanged)
    );
    assert!(pdns.calls.is_empty());
}

#[test]
fn a_readable_intake_or_a_wrong_owner_is_denied() {
    let intake = Intake::new(ZONE);
    let file = intake.root.join("example.test").join(ZONE_FILE);
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let owner = rustix::process::getuid().as_raw();
    let mut pdns = FakePdns::default();
    assert_eq!(
        run(&mut pdns, &import(ZONE), &policy(), &intake.root, owner),
        Err(ExecutorError::AccessDenied)
    );
    assert_eq!(
        intake_zone(&intake.root, owner + 1, &zone(), &sha(ZONE.as_bytes()), 9).err(),
        Some(ExecutorError::AccessDenied)
    );
}

#[test]
fn a_read_back_with_more_or_other_data_fails() {
    let owner = rustix::process::getuid().as_raw();
    for extra in [
        "stray.example.test.\t3600\tIN\tA\t192.0.2.1\n",
        "example.test.\t3600\tIN\tA\t192.0.2.1\n",
        "not a record\n",
    ] {
        let intake = Intake::new(ZONE);
        let mut pdns = FakePdns {
            extra: Some(extra),
            ..FakePdns::default()
        };
        assert_eq!(
            run(&mut pdns, &import(ZONE), &policy(), &intake.root, owner),
            Err(ExecutorError::StepFailed),
            "{extra}"
        );
    }
}

#[test]
fn a_failed_tool_stops_the_step() {
    let intake = Intake::new(ZONE);
    let mut pdns = FakePdns {
        fail: Some("zone check"),
        ..FakePdns::default()
    };
    let owner = rustix::process::getuid().as_raw();
    assert_eq!(
        run(&mut pdns, &import(ZONE), &policy(), &intake.root, owner),
        Err(ExecutorError::StepFailed)
    );
    assert_eq!(pdns.calls.last().unwrap(), "zone check example.test");
}

#[test]
fn without_secondaries_no_key_is_activated() {
    let intake = Intake::new(ZONE);
    let mut policy = policy();
    policy.secondaries.clear();
    let mut pdns = FakePdns::default();
    let owner = rustix::process::getuid().as_raw();
    run(&mut pdns, &import(ZONE), &policy, &intake.root, owner).unwrap();
    assert!(!pdns.calls.iter().any(|call| call.starts_with("tsigkey")));
}

#[test]
fn the_unit_runs_as_pdns_without_network_capabilities_or_pipes() {
    let args = unit_args(
        "rustiron-pdns-1",
        "/run/rustiron-admin/x.out",
        Some("/run/rustiron-admin/x.in"),
    );
    for wanted in [
        "User=pdns",
        "Group=pdns",
        "ReadWritePaths=/var/lib/pdns",
        "PrivateNetwork=yes",
        "CapabilityBoundingSet=",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "StandardOutput=truncate:/run/rustiron-admin/x.out",
        "StandardInput=file:/run/rustiron-admin/x.in",
        "--unit=rustiron-pdns-1",
    ] {
        assert!(args.iter().any(|p| p == wanted), "{wanted}");
    }
    // W564-F1: D-Bus may not carry the helper's pipes.
    assert!(!args.iter().any(|p| p == "--pipe"));
    let plain = unit_args("rustiron-pdns-2", "/run/rustiron-admin/y.out", None);
    assert!(!plain.iter().any(|p| p.starts_with("StandardInput=")));
}

#[test]
fn the_control_unit_runs_as_pdns_without_capabilities_or_output() {
    let args = control_args("rustiron-pdns-control-1");
    for wanted in [
        "User=pdns",
        "CapabilityBoundingSet=",
        "RestrictSUIDSGID=yes",
        "PrivateNetwork=yes",
        "StandardOutput=null",
        "--unit=rustiron-pdns-control-1",
    ] {
        assert!(args.iter().any(|p| p == wanted), "{wanted}");
    }
    // W564-F3: NoNewPrivileges would block the transition to pdns_control_t.
    assert!(!args.iter().any(|p| p.starts_with("NoNewPrivileges")));
}
