//! W565: the compare-and-set change step against a fake PowerDNS.

use rustiron_contracts::Id;
use rustiron_contracts::approval::{DnsChangePlan, ZoneName};
use rustiron_journal::{DnsChange, DnsChangeSet, StepState};

use super::*;

const PLAN: &str = include_str!("../../contracts/tests/fixtures/dns-change-plan.json");

/// The zone before the change: its TXT and CNAME match the plan's
/// expected digests, and `www` has no A set.
const BEFORE: &str = "\
example.test. 3600 IN NS ns1.example.test.
example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 10800 3600 604800 3600
example.test. 3600 IN TXT \"v=spf1 mx ~all\"
old.example.test. 3600 IN CNAME example.test.
";

fn plan() -> DnsChangePlan {
    DnsChangePlan::decode(PLAN.as_bytes()).unwrap()
}

/// The recorded change, with each set read from `zone` before intent.
fn change(zone: &str) -> DnsChange {
    let plan = plan();
    let parsed = parse_zone(plan.zone(), zone.as_bytes()).unwrap();
    let before = sets_in(&parsed, plan.operations());
    DnsChange {
        operation_id: Id::try_from("op_w565".to_owned()).unwrap(),
        zone: plan.zone().clone(),
        sets: plan
            .operations()
            .iter()
            .zip(before)
            .map(|(operation, before)| DnsChangeSet {
                owner: operation.owner.clone(),
                kind: operation.kind,
                expected: operation.expected.clone(),
                before,
                after: None,
            })
            .collect(),
        state: StepState::Intent,
    }
}

/// A PowerDNS holding one zone's lines in canonical form.
struct FakePdns {
    lines: Vec<String>,
    calls: Vec<String>,
    /// A `rrset delete` that does nothing, to break the read-back.
    lost_delete: bool,
}

impl FakePdns {
    fn new(zone: &str) -> Self {
        Self {
            lines: zone.lines().map(str::to_owned).collect(),
            calls: Vec::new(),
            lost_delete: false,
        }
    }

    fn drop_set(&mut self, owner: &str, kind: &str) {
        let prefix = format!("{owner} ");
        let infix = format!(" IN {kind} ");
        self.lines
            .retain(|line| !(line.starts_with(&prefix) && line.contains(&infix)));
    }
}

impl Pdns for FakePdns {
    fn util(&mut self, args: &[&str], _input: Option<&[u8]>) -> Result<String, ExecutorError> {
        self.calls.push(args.join(" "));
        match args {
            ["zone", "list", _] => {
                let mut text = String::from("$ORIGIN .\n");
                for line in &self.lines {
                    text.push_str(&line.splitn(5, ' ').collect::<Vec<_>>().join("\t"));
                    text.push('\n');
                }
                Ok(text)
            }
            ["rrset", "replace", _, owner, kind, ttl, records @ ..] => {
                self.drop_set(owner, kind);
                for record in records {
                    self.lines.push(format!("{owner} {ttl} IN {kind} {record}"));
                }
                Ok(String::new())
            }
            ["rrset", "delete", _, owner, kind] => {
                if !self.lost_delete {
                    self.drop_set(owner, kind);
                }
                Ok(String::new())
            }
            _ => Ok(String::new()),
        }
    }

    fn control(&mut self, args: &[&str]) -> Result<(), ExecutorError> {
        self.calls.push(format!("control {}", args.join(" ")));
        Ok(())
    }
}

fn rrset_calls(pdns: &FakePdns) -> Vec<&String> {
    pdns.calls
        .iter()
        .filter(|call| call.starts_with("rrset") || call.contains("serial"))
        .collect()
}

#[test]
fn a_change_applies_every_operation_then_reads_back() {
    let mut pdns = FakePdns::new(BEFORE);
    run(&mut pdns, &change(BEFORE), &plan()).unwrap();
    assert_eq!(
        pdns.calls,
        [
            "zone list example.test",
            "rrset replace example.test example.test. TXT 3600 \"v=spf1 mx include:spf.example.net ~all\"",
            "rrset replace example.test www.example.test. A 300 203.0.113.30",
            "rrset delete example.test old.example.test. CNAME",
            "zone increase-serial example.test",
            "control purge example.test$",
            "control purge old.example.test$",
            "control purge www.example.test$",
            "zone list example.test",
        ]
    );
}

#[test]
fn an_applied_change_is_settled_without_effects() {
    let mut pdns = FakePdns::new(BEFORE);
    run(&mut pdns, &change(BEFORE), &plan()).unwrap();
    let after: String = {
        let mut lines = pdns.lines.clone();
        lines.sort();
        lines.iter().map(|line| format!("{line}\n")).collect()
    };
    let mut again = FakePdns::new(&after);
    run(&mut again, &change(BEFORE), &plan()).unwrap();
    assert!(rrset_calls(&again).is_empty());
    assert_eq!(again.calls, ["zone list example.test"]);
}

#[test]
fn a_set_changed_since_the_read_is_refused_before_any_effect() {
    let moved = BEFORE.replace(
        "old.example.test. 3600 IN CNAME example.test.",
        "old.example.test. 3600 IN CNAME other.example.",
    );
    let mut pdns = FakePdns::new(&moved);
    assert_eq!(
        run(&mut pdns, &change(BEFORE), &plan()),
        Err(ExecutorError::PreconditionChanged)
    );
    assert!(rrset_calls(&pdns).is_empty());
}

#[test]
fn a_plan_that_is_not_the_change_is_denied() {
    let mut other = change(BEFORE);
    other.zone = ZoneName::try_from("other.test".to_owned()).unwrap();
    let mut pdns = FakePdns::new(BEFORE);
    assert_eq!(
        run(&mut pdns, &other, &plan()),
        Err(ExecutorError::BindingDenied)
    );
    let mut reordered = change(BEFORE);
    reordered.sets.swap(0, 1);
    assert_eq!(
        run(&mut pdns, &reordered, &plan()),
        Err(ExecutorError::BindingDenied)
    );
    assert!(pdns.calls.is_empty());
}

#[test]
fn a_read_back_that_differs_fails() {
    let mut pdns = FakePdns::new(BEFORE);
    pdns.lost_delete = true;
    assert_eq!(
        run(&mut pdns, &change(BEFORE), &plan()),
        Err(ExecutorError::StepFailed)
    );
}

#[test]
fn the_intended_sets_are_the_replacements_and_removals() {
    let wanted = intended(plan().operations());
    assert_eq!(
        wanted,
        [
            Some(
                "example.test. 3600 IN TXT \"v=spf1 mx include:spf.example.net ~all\"\n".to_owned()
            ),
            Some("www.example.test. 300 IN A 203.0.113.30\n".to_owned()),
            None,
        ]
    );
}

/// W566-F1: a zone listing crosses the helper's one-line reply as one JSON
/// string and comes back unchanged.
#[test]
fn a_listing_crosses_the_one_line_reply_as_json() {
    let text = serde_json::to_string(BEFORE).unwrap();
    assert!(!text.contains('\n'));
    let line = format!("ok {text}\n");
    let Ok(crate::admin_helper::Reply::Done(Some(payload))) =
        crate::admin_helper::parse_reply(&line)
    else {
        panic!("the reply did not parse");
    };
    assert_eq!(serde_json::from_str::<String>(&payload).unwrap(), BEFORE);
    // The raw multi-line listing does not parse.
    assert!(BEFORE.lines().count() > 1);
    assert!(crate::admin_helper::parse_reply(&format!("ok {BEFORE}\n")).is_err());
}
