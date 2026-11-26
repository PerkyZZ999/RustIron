//! W372 (D-030): `site_readopt` admission, observation and records with
//! synthetic keys and a real journal. The host observation is injected
//! (`fault-injection` builds); the pure rules are in `src/readopt_tests.rs`.
//! Nothing here creates, changes or removes anything on the host.

use std::{fs, path::PathBuf};

use rustiron_contracts::{
    Id, Timestamp,
    approval::{Hostname, ReadoptGrant, ReadoptPlan, SiteId},
};
use rustiron_executor::{
    AdmissionRequest, Executor, ExecutorError, Fault, ReadoptObservation, TrustAnchor, ols,
    readopt::{
        GenerationInput, HostGenerationFacts, HostSiteFacts, LabelFact, NamedNode, NodeFact,
        OLS_DROPIN, SiteInput, dropin_text, expected_grants,
    },
};
use rustiron_journal::{ProvisionState, ReadoptResult, ReadoptState};
use serde_json::{Value, json};
mod support;
use support::{KEYGEN, hex, new_key, private_dir, private_file, sign};
#[path = "readopt/w377.rs"]
mod w377;
#[path = "readopt/w394.rs"]
mod w394;

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Lab {
    _serial: std::sync::MutexGuard<'static, ()>,
    root: PathBuf,
    anchor: TrustAnchor,
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn id(value: &str) -> Id {
    Id::try_from(value.to_owned()).unwrap()
}

fn vector(name: &str) -> Value {
    let all: Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/readopt-plan-vectors.json"
    ))
    .unwrap();
    all.as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()
        .clone()
}

/// The site-form plan for `site` on `host_lab`/`epoch_1`, edited by `edit`.
fn site_plan(site: &str, edit: impl FnOnce(&mut Value)) -> Value {
    let mut plan: Value =
        serde_json::from_str(vector("site")["plan_input"].as_str().unwrap()).unwrap();
    plan["host_epoch"] = json!("epoch_1");
    plan["previous_epoch"] = json!("epoch_0");
    plan["site_id"] = json!(site);
    plan["hostname"] = json!(format!("{site}.example.test"));
    plan["observations"][0]["site_id"] = json!(site);
    plan["observations"][0]["hostname"] = json!(format!("{site}.example.test"));
    edit(&mut plan);
    plan
}

/// One planted fact: the rule it must fail, and how it is planted.
type Plant = (&'static str, fn(&mut SiteInput));

impl Lab {
    fn new(name: &str) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let root = std::env::temp_dir().join(format!("ri-readopt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        private_dir(&root);
        for dir in ["policy", "registry", "scratch", "journal", "mark", "keys"] {
            private_dir(&root.join(dir));
        }
        new_key(&root.join("keys").join("key"));
        let anchor = TrustAnchor {
            owner_uid: rustix::process::getuid().as_raw(),
            policy_dir: root.join("policy"),
            registry_dir: root.join("registry"),
            scratch_dir: root.join("scratch"),
            journal_dir: root.join("journal"),
            mark_dir: root.join("mark"),
            recipes_dir: root.join("journal"),
            admin_socket: None,
        };
        let lab = Self {
            _serial: serial,
            root,
            anchor,
        };
        let policy = json!({
            "schema_version": 1, "host_id": "host_lab", "host_epoch": "epoch_1",
            "profile_digest": "a".repeat(64), "requester": "agent_1", "requester_uid": 4242,
            "issuer": "operator_1", "signer_policy_epoch": "policy_1",
            "verifier_sha256": hex(&fs::read(KEYGEN).unwrap()),
            "provisioning": {
                "wordpress_713_sha256": "e".repeat(64),
                "uid_min": 3001, "uid_max": 3099, "category_min": 201, "category_max": 299,
                "quota": {"block_hard_kib": 262144, "inode_hard": 20000},
            },
            "ols": {
                "listener": "W372", "address": "127.0.0.1:8090", "adopted": [],
                "parent_sha256": "b".repeat(64), "webadmin_port": 7080,
            },
        });
        private_file(
            &lab.anchor.policy_dir.join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        let public = fs::read_to_string(lab.root.join("keys/key.pub")).unwrap();
        let public: Vec<_> = public.split_whitespace().take(2).collect();
        private_file(
            &lab.anchor.policy_dir.join("allowed_signers"),
            format!(
                "operator_1 namespaces=\"rustiron-plan-v1\" {}\n",
                public.join(" ")
            )
            .as_bytes(),
        );
        private_file(&lab.anchor.policy_dir.join("revocations"), b"");
        lab
    }

    fn anchor(&self) -> TrustAnchor {
        self.anchor.clone()
    }

    /// A signed site-form request for `site`, edited by `edit`.
    fn site(&self, site: &str, nonce: &str, edit: impl FnOnce(&mut Value)) -> Signed {
        self.signed(site_plan(site, edit), "site", nonce, json!([site]))
    }

    fn generation(
        &self,
        sites: &[&str],
        generation: &(Id, rustiron_contracts::approval::Sha256Digest),
        nonce: &str,
    ) -> Signed {
        let mut plan: Value =
            serde_json::from_str(vector("generation")["plan_input"].as_str().unwrap()).unwrap();
        plan["host_epoch"] = json!("epoch_1");
        plan["previous_epoch"] = json!("epoch_0");
        plan["site_ids"] = json!(sites);
        plan["expected_generation"] = json!(generation.0.as_str());
        plan["expected_digest"] = json!(generation.1.as_str());
        plan["observations"][0]["generation"] = json!(generation.0.as_str());
        plan["observations"][0]["content_digest"] = json!(generation.1.as_str());
        self.signed(plan, "generation", nonce, json!(sites))
    }

    fn signed(&self, plan: Value, form: &str, nonce: &str, sites: Value) -> Signed {
        self.signed_with(plan, form, nonce, sites, "key", |_| {})
    }

    /// [`Self::signed`] with `key` and a final grant edit (W377).
    fn signed_with(
        &self,
        plan: Value,
        form: &str,
        nonce: &str,
        sites: Value,
        key: &str,
        edit: impl FnOnce(&mut Value),
    ) -> Signed {
        let plan = serde_json::to_vec(&plan).unwrap();
        let decoded = ReadoptPlan::decode(&plan).unwrap();
        let mut grant: Value =
            serde_json::from_str(vector(form)["grant_input"].as_str().unwrap()).unwrap();
        grant["host_epoch"] = json!("epoch_1");
        grant["plan_digest"] = json!(decoded.digest().as_str());
        grant["nonce"] = json!(nonce);
        grant["grant_id"] = json!(format!("grant_{nonce}"));
        grant["site_ids"] = sites;
        edit(&mut grant);
        let grant = serde_json::to_vec(&grant).unwrap();
        let signature = sign(
            &self.root.join("keys").join(key),
            &self.root.join("message"),
            ReadoptGrant::decode(&grant).unwrap().as_bytes(),
            "rustiron-plan-v1",
        );
        Signed {
            plan,
            grant,
            signature,
        }
    }
}

struct Signed {
    plan: Vec<u8>,
    grant: Vec<u8>,
    signature: Vec<u8>,
}

impl Signed {
    fn request(&self, operation: &str) -> AdmissionRequest<'_> {
        AdmissionRequest {
            peer_uid: 4242,
            plan: &self.plan,
            grant: &self.grant,
            signature: &self.signature,
            operation_id: id(operation),
            idempotency_key: id(&format!("key_{operation}")),
            now: Some(Timestamp::try_from(1200).unwrap()),
        }
    }
}

fn dir(uid: u32, gid: u32, mode: u32) -> NodeFact {
    NodeFact {
        kind: "dir".to_owned(),
        uid,
        gid,
        mode,
        nlink: 2,
        same_device: true,
    }
}

/// What the host shows for a provisioned site `rs_<site>` with `uid` and
/// category `category`.
fn site_facts(site: &str, uid: u32, category: u32) -> SiteInput {
    let account = format!("rs_{site}");
    let root = format!("/srv/sites/{account}");
    let level = format!("s0:c{category}");
    let label = |entry: &str, kind: &str| LabelFact {
        entry: entry.to_owned(),
        context: Some(format!("system_u:object_r:{kind}:{level}")),
    };
    SiteInput {
        passwd: format!(
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n{account}:x:{uid}:{uid}:Rustiron lab site:{root}:/sbin/nologin\n"
        ),
        group: format!("root:x:0:\nnobody:x:65534:\n{account}:x:{uid}:\n"),
        fcontexts: format!(
            "{root}(/.*)?    system_u:object_r:httpd_sys_content_t:{level}\n{root}/(tmp|logs)(/.*)?    system_u:object_r:httpd_sys_rw_content_t:{level}\n"
        ),
        host: HostSiteFacts {
            root: Some(dir(0, 0, 0o751)),
            skeleton: Some(
                [
                    ("errors", dir(0, 0, 0o755)),
                    ("html", dir(uid, 65534, 0o750)),
                    ("logs", dir(uid, uid, 0o750)),
                    ("private", dir(uid, uid, 0o750)),
                    ("tmp", dir(uid, uid, 0o750)),
                ]
                .into_iter()
                .map(|(name, node)| NamedNode {
                    name: name.to_owned(),
                    node,
                })
                .collect(),
            ),
            labels: vec![
                label("root", "httpd_sys_content_t"),
                label("html", "httpd_sys_content_t"),
                label("tmp", "httpd_sys_rw_content_t"),
                label("logs", "httpd_sys_rw_content_t"),
            ],
            dropin_entries: Some(vec!["50-selinux.conf".to_owned()]),
            dropin_text: Some(dropin_text(&level)),
            socket_enabled: Some("enabled".to_owned()),
            timer_enabled: Some("enabled".to_owned()),
            socket_active: Some("active".to_owned()),
            schema: Some(true),
            user_hosts: Some(vec!["localhost".to_owned()]),
            schema_grantees: Some(vec![format!("{account}@localhost")]),
            grants: Some(expected_grants(&account)),
            credentials: Some(NodeFact {
                kind: "file".to_owned(),
                uid,
                gid: uid,
                mode: 0o600,
                nlink: 1,
                same_device: true,
            }),
            quota_enforced: true,
            quota_uid: Some(uid),
            quota: Some([262_144, 20_000, 0, 0]),
            ejected: false,
        },
    }
}

fn site(name: &str) -> SiteId {
    SiteId::try_from(name.to_owned()).unwrap()
}

/// Adopts `name` with the lab executor, as the site form does on a host.
fn adopt_site(
    executor: &mut Executor,
    lab: &Lab,
    name: &str,
    uid: u32,
    category: u32,
    nonce: &str,
) {
    let request = lab.site(name, nonce, |_| {});
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        name, uid, category,
    ))));
    let ReadoptResult::New(row) = executor
        .readopt(&request.request(&format!("op_{nonce}")))
        .unwrap()
    else {
        panic!("new re-adoption expected");
    };
    assert_eq!(row.state, ReadoptState::Adopted);
}

#[test]
fn a_verified_site_is_adopted_and_owned_with_nothing_else_recorded() {
    let lab = Lab::new("site-ok");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "n1");
    let provision = executor
        .provision_for_site(&site("blog1"))
        .unwrap()
        .unwrap();
    assert_eq!(provision.state, ProvisionState::Adopted);
    assert!(provision.steps.is_empty());
    assert_eq!(
        provision.intent.hostname,
        Hostname::try_from("blog1.example.test".to_owned()).unwrap()
    );
    let row = executor.readoption_status(&id("op_n1")).unwrap().unwrap();
    let facts: Value = serde_json::from_str(row.facts.as_deref().unwrap()).unwrap();
    assert_eq!(facts["uid"], 3001);
    assert_eq!(facts["level"], "s0:c201");
    assert_eq!(row.intent.previous_epoch.as_str(), "epoch_0");
    // The admission mark counts the re-adoption once.
    drop(executor);
    let mark = fs::read_to_string(lab.anchor.mark_dir.join("admission-mark")).unwrap();
    assert_eq!(mark.lines().last(), Some("1"), "{mark}");
    let executor = Executor::open(lab.anchor()).unwrap();
    let observed = Executor::observe(&lab.anchor()).unwrap();
    assert_eq!(observed["readoptions"][0]["state"], "adopted");
    assert_eq!(observed["sites"][0]["state"], "adopted");
    drop(executor);
}

#[test]
fn a_mismatching_fact_is_refused_and_nothing_else_is_recorded() {
    let lab = Lab::new("site-mismatch");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let mut tampered = site_facts("blog1", 3001, 201);
    tampered
        .host
        .schema_grantees
        .as_mut()
        .unwrap()
        .push("other@localhost".to_owned());
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(tampered)));
    let request = lab.site("blog1", "n1", |_| {});
    assert_eq!(
        executor.readopt(&request.request("op_n1")).err(),
        Some(ExecutorError::ReadoptMismatch)
    );
    let row = executor.readoption_status(&id("op_n1")).unwrap().unwrap();
    assert_eq!(row.state, ReadoptState::Refused);
    assert_eq!(
        row.refusal,
        Some(("READOPT_MISMATCH".to_owned(), "database".to_owned()))
    );
    assert_eq!(executor.provision_for_site(&site("blog1")).unwrap(), None);
    // The same request again is status only, and the grant stays spent.
    assert!(matches!(
        executor.readopt(&request.request("op_n1")).unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Refused
    ));
    assert_eq!(
        executor.readopt(&request.request("op_other")).err(),
        Some(ExecutorError::ReplayDenied)
    );
    // A corrected plan with a new grant may adopt the same site.
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "n2");
}

#[test]
fn each_planted_site_fact_gives_its_own_refused_row() {
    let lab = Lab::new("site-each");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let plants: Vec<Plant> = vec![
        ("account", |i| {
            i.passwd = i.passwd.replace("/sbin/nologin\n", "/bin/bash\n")
        }),
        ("site_root", |i| i.host.root.as_mut().unwrap().mode = 0o755),
        ("file_contexts", |i| i.fcontexts.clear()),
        ("labels", |i| i.host.labels[1].context = None),
        ("php_units", |i| {
            i.host.dropin_text = Some("[Service]\n".to_owned())
        }),
        ("database", |i| {
            i.host.user_hosts = Some(vec!["%".to_owned()])
        }),
        ("credentials", |i| i.host.credentials = None),
        ("quota", |i| i.host.quota = None),
        ("ejected", |i| i.host.ejected = true),
    ];
    for (n, (rule, plant)) in plants.into_iter().enumerate() {
        let mut facts = site_facts("blog1", 3001, 201);
        plant(&mut facts);
        executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(facts)));
        let nonce = format!("plant{n}");
        let request = lab.site("blog1", &nonce, |_| {});
        assert_eq!(
            executor
                .readopt(&request.request(&format!("op_{nonce}")))
                .err(),
            Some(ExecutorError::ReadoptMismatch),
            "{rule}"
        );
        let row = executor
            .readoption_status(&id(&format!("op_{nonce}")))
            .unwrap()
            .unwrap();
        assert_eq!(row.refusal.unwrap().1, rule);
        assert_eq!(executor.provision_for_site(&site("blog1")).unwrap(), None);
    }
}

#[test]
fn bindings_and_preconditions_refuse_before_any_record() {
    let lab = Lab::new("site-binding");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let old_epoch = lab.site("blog1", "n1", |plan| {
        plan["host_epoch"] = json!("epoch_0");
        plan["previous_epoch"] = json!("epoch_x");
    });
    assert_eq!(
        executor.readopt(&old_epoch.request("op_n1")).err(),
        Some(ExecutorError::BindingDenied),
        "a plan of another epoch"
    );
    let above_cap = lab.site("blog1", "n2", |plan| {
        plan["quota_limits"]["block_hard_kib"] = json!(262_145);
    });
    assert_eq!(
        executor.readopt(&above_cap.request("op_n2")).err(),
        Some(ExecutorError::BindingDenied)
    );
    let mut wrong_peer = lab.site("blog1", "n3", |_| {});
    let mut request = wrong_peer.request("op_n3");
    request.peer_uid = 1;
    assert_eq!(
        executor.readopt(&request).err(),
        Some(ExecutorError::PeerDenied)
    );
    wrong_peer.signature[40] ^= 1;
    assert_eq!(
        executor.readopt(&wrong_peer.request("op_n3")).err(),
        Some(ExecutorError::SignatureDenied)
    );
    assert_eq!(executor.readoption_status(&id("op_n1")).unwrap(), None);
    assert_eq!(executor.readoption_status(&id("op_n3")).unwrap(), None);
    // An owned site is refused before intent.
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "n4");
    let again = lab.site("blog1", "n5", |_| {});
    assert_eq!(
        executor.readopt(&again.request("op_n5")).err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert_eq!(executor.readoption_status(&id("op_n5")).unwrap(), None);
    // The same UID and category on another site are a recorded allocation.
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog2", 3001, 201,
    ))));
    let reused = lab.site("blog2", "n6", |_| {});
    assert_eq!(
        executor.readopt(&reused.request("op_n6")).err(),
        Some(ExecutorError::ReadoptMismatch)
    );
    assert_eq!(
        executor
            .readoption_status(&id("op_n6"))
            .unwrap()
            .unwrap()
            .refusal
            .unwrap()
            .1,
        "uid_recorded"
    );
}

#[test]
fn a_crash_after_intent_stays_verifying_blocks_work_and_reconcile_settles_it() {
    let lab = Lab::new("site-crash");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let request = lab.site("blog1", "n1", |_| {});
    executor.inject_fault(Fault::AfterReadoptIntent);
    assert_eq!(
        executor.readopt(&request.request("op_n1")).err(),
        Some(ExecutorError::Unavailable)
    );
    drop(executor);
    let mut executor = Executor::open(lab.anchor()).unwrap();
    let row = executor.readoption_status(&id("op_n1")).unwrap().unwrap();
    assert_eq!(row.state, ReadoptState::Verifying);
    assert_eq!(executor.provision_for_site(&site("blog1")).unwrap(), None);
    // Verifying blocks every other admission.
    let other = lab.site("blog2", "n2", |_| {});
    assert_eq!(
        executor.readopt(&other.request("op_n2")).err(),
        Some(ExecutorError::Busy)
    );
    // The exact repeat is status only and observes nothing.
    assert!(matches!(
        executor.readopt(&request.request("op_n1")).unwrap(),
        ReadoptResult::Existing(row) if row.state == ReadoptState::Verifying
    ));
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(site_facts(
        "blog1", 3001, 201,
    ))));
    let settled = executor.reconcile_readoption(&id("op_n1")).unwrap();
    assert_eq!(settled.state, ReadoptState::Adopted);
    assert_eq!(
        executor
            .provision_for_site(&site("blog1"))
            .unwrap()
            .unwrap()
            .state,
        ProvisionState::Adopted
    );
    // A settled row is returned as stored.
    assert_eq!(
        executor.reconcile_readoption(&id("op_n1")).unwrap().state,
        ReadoptState::Adopted
    );
}

#[test]
fn a_reconcile_that_observes_a_mismatch_records_the_refusal() {
    let lab = Lab::new("site-crash-refused");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let request = lab.site("blog1", "n1", |_| {});
    executor.inject_fault(Fault::AfterReadoptIntent);
    assert!(executor.readopt(&request.request("op_n1")).is_err());
    let mut changed = site_facts("blog1", 3001, 201);
    changed.host.quota = None;
    executor.inject_readopt_observation(ReadoptObservation::Site(Box::new(changed)));
    assert_eq!(
        executor.reconcile_readoption(&id("op_n1")).err(),
        Some(ExecutorError::ReadoptMismatch)
    );
    assert_eq!(
        executor
            .readoption_status(&id("op_n1"))
            .unwrap()
            .unwrap()
            .state,
        ReadoptState::Refused
    );
}

fn live_render(sites: &[(&str, &str)]) -> ols::Generation {
    let served: Vec<ols::ServedSite> = sites
        .iter()
        .map(|(name, host)| ols::ServedSite {
            account: format!("rs_{name}"),
            alias_hostname: None,
            hostname: Hostname::try_from((*host).to_owned()).unwrap(),
            ejected: false,
            static_ejected: false,
            lscache: false,
            tls_alias: None,
            tls: None,
            acme: false,
            proxy: None,
        })
        .collect();
    ols::render("W372", "127.0.0.1:8090", &[], &served)
}

fn generation_input(files: ols::Generation) -> GenerationInput {
    let digest = ols::digest(&files);
    GenerationInput {
        current: Some((ols::generation_id(&digest), digest)),
        stored: Some(files),
        host: Some(HostGenerationFacts {
            server: ols::ServerChecks {
                parent_reviewed: true,
                webadmin_closed: true,
                adopted_vhosts_pinned: true,
                php_capacity: true,
                page_cache_ols_tested: true,
            },
            unit_state: Some("active".to_owned()),
            kill_mode: Some("mixed".to_owned()),
            dropins: Some(vec![
                OLS_DROPIN.to_owned(),
                #[cfg(rustiron_profile = "product")]
                rustiron_executor::readopt::OLS_BOOT_GUARD_DROPIN.to_owned(),
            ]),
            probes: true,
        }),
    }
}

#[test]
fn the_live_generation_is_adopted_only_when_it_is_the_render_of_owned_sites() {
    let lab = Lab::new("generation");
    let mut executor = Executor::initialize(lab.anchor()).unwrap();
    let files = live_render(&[("blog1", "blog1.example.test")]);
    let digest = ols::digest(&files);
    let live = (ols::generation_id(&digest), digest);
    // A site the journal does not own: refused before intent.
    let unowned = lab.generation(&["blog1"], &live, "g1");
    assert_eq!(
        executor.readopt(&unowned.request("op_g1")).err(),
        Some(ExecutorError::PreconditionChanged)
    );
    assert_eq!(executor.readoption_status(&id("op_g1")).unwrap(), None);
    adopt_site(&mut executor, &lab, "blog1", 3001, 201, "s1");
    // A generation with one extra vhost, signed as the live one: refused.
    let mut planted = files.clone();
    planted.insert(
        "rs_evil.vhost".to_owned(),
        b"docRoot /srv/sites/rs_evil/html/\n".to_vec(),
    );
    let planted_digest = ols::digest(&planted);
    let planted_live = (ols::generation_id(&planted_digest), planted_digest);
    executor.inject_readopt_observation(ReadoptObservation::Generation(Box::new(
        generation_input(planted),
    )));
    let request = lab.generation(&["blog1"], &planted_live, "g2");
    assert_eq!(
        executor.readopt(&request.request("op_g2")).err(),
        Some(ExecutorError::ReadoptMismatch)
    );
    assert_eq!(
        executor
            .readoption_status(&id("op_g2"))
            .unwrap()
            .unwrap()
            .refusal,
        Some(("READOPT_MISMATCH".to_owned(), "render".to_owned()))
    );
    // An empty history establishes the bootstrap generation in the product
    // profile and nothing in the lab profile (W362).
    let empty = if cfg!(rustiron_profile = "product") {
        "bootstrap"
    } else {
        "none"
    };
    assert_eq!(executor.ols_established_by().unwrap(), empty);
    // Server checks that fail are drift.
    let mut drift = generation_input(files.clone());
    drift.host.as_mut().unwrap().server.webadmin_closed = false;
    executor.inject_readopt_observation(ReadoptObservation::Generation(Box::new(drift)));
    let request = lab.generation(&["blog1"], &live, "g3");
    assert_eq!(
        executor.readopt(&request.request("op_g3")).err(),
        Some(ExecutorError::Drift)
    );
    // The byte-identical render is adopted, once.
    executor.inject_readopt_observation(ReadoptObservation::Generation(Box::new(
        generation_input(files.clone()),
    )));
    let request = lab.generation(&["blog1"], &live, "g4");
    let ReadoptResult::New(row) = executor.readopt(&request.request("op_g4")).unwrap() else {
        panic!("new");
    };
    assert_eq!(row.state, ReadoptState::Adopted);
    assert_eq!(executor.ols_established_by().unwrap(), "adoption");
    let again = lab.generation(&["blog1"], &live, "g5");
    assert_eq!(
        executor.readopt(&again.request("op_g5")).err(),
        Some(ExecutorError::PreconditionChanged)
    );
}
