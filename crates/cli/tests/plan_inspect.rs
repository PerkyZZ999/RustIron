//! `rustiron-plan inspect`: every closed lab plan decodes to its verb and
//! digest; anything else is refused with a fixed message that echoes nothing.

use std::process::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../contracts/tests/fixtures");

fn inspect(path: &str) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .args(["inspect", path])
        .output()
        .unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn each_plan_kind_is_described_with_its_digest() {
    for (file, verb, digest) in [
        (
            "site-plan.json",
            "site_provision",
            "c33d38f7e35973b5dfb88846d667b06ee9f1d2544fe1fcfa35354797553b2ccf",
        ),
        (
            "ols-plan.json",
            "config_activate",
            "00d79e742240c6626d1c5fb3e4415cf158bca560e7c71bbdf0fcae33eb9eb88f",
        ),
        (
            "eject-plan.json",
            "site_eject",
            "ca015fc46a331406c894bff50a4de8314d65e67c7f8834574520e651ba830727",
        ),
        (
            "capture-plan.json",
            "backup_capture",
            "31441613f3d96fe2b9cbdafa8dceea164405fa09d877d63ccdda3d06f3e28135",
        ),
        (
            "probe-plan.json",
            "restore_probe",
            "38d7827be2d1c72f470a71fe34a0172f0b9fdd877ac9ea1532a7e48aa795caf9",
        ),
        (
            "certificate-plan.json",
            "certificate_issue",
            "2a77e6b6cb8b921320606ce1254d703905ef16af70529ec4533f788bb1dbcc1f",
        ),
        (
            "scrub-plan.json",
            "import_scrub",
            "ef47112571ba7150df7ea2a2aa123534c541ecfe8d3a5d7876e913c38fe56945",
        ),
        (
            "update-plan.json",
            "site_update",
            "1008422dc14d15fcbc24f7d07de1695e0cd338c21c2882bb701350d8b1eb542f",
        ),
        (
            "dns-import-plan.json",
            "dns_zone_import",
            "5c0bd1a59dadf79c81966dd8b334d54dd2d6572692c1a8443c3c6aee49ce9a60",
        ),
        (
            "proxy-site-plan.json",
            "proxy_site_provision",
            "4cfba528410ceb7335442c622ce436e43fdc8ccdf5093afb7e1e064ecb9a6b34",
        ),
    ] {
        let (ok, text) = inspect(&format!("{FIXTURES}/{file}"));
        assert!(ok, "{file}: {text}");
        assert!(
            text.starts_with(&format!("verb: {verb}\nplan digest: {digest}\n")),
            "{file}: {text}"
        );
        assert!(text.ends_with("authority: none (review only; signing happens elsewhere)\n"));
    }
}

#[test]
fn single_name_static_eject_review_states_the_handover_and_runtime_gate() {
    let (ok, text) = inspect(&format!("{FIXTURES}/eject-plan-v3.json"));
    assert!(ok, "{text}");
    for expected in [
        "verb: site_eject",
        "hostname: static.example.test",
        "scripting disabled",
        "stops and disables managed PHP units",
        "operator owns backups and certificate renewal",
        "NOT_ADMITTED_FOR_EFFECT",
        "authority: none",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }
}

/// W387 (D-037): the review of an eject names what the signer accepts: the
/// standalone vhost, the stopped Rustiron PHP units, and the isolation loss.
#[test]
fn an_eject_review_names_the_standalone_php_and_the_isolation_loss() {
    let (ok, text) = inspect(&format!("{FIXTURES}/eject-plan.json"));
    assert!(ok, "{text}");
    for wanted in [
        "standalone vhost",
        "OLS starts the site PHP as the site account",
        "stops and disables the site's Rustiron PHP units",
        "no SELinux category, PHP sandbox, network refusal, or cgroup limit",
        "nothing deleted",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
}

/// W341: the review summary names the plan's quota source and limits.
#[test]
fn site_plans_show_their_quota_limits_or_the_policy_source() {
    let (ok, text) = inspect(&format!("{FIXTURES}/site-plan.json"));
    assert!(ok, "{text}");
    assert!(
        text.contains("quota: enrolled policy limits (plan schema 1)\n"),
        "{text}"
    );
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/site-plan-v2-vectors.json"
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ri-inspect-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plan.json");
    std::fs::write(&path, vectors[1]["plan_canonical"].as_str().unwrap()).unwrap();
    let (ok, text) = inspect(path.to_str().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok, "{text}");
    assert!(
        text.starts_with(&format!(
            "verb: site_provision\nplan digest: {}\n",
            vectors[1]["plan_digest"].as_str().unwrap()
        )),
        "{text}"
    );
    assert!(
        text.contains("quota: hard 65536 KiB, 1000 inodes (signed; at most the enrolled quota)\n"),
        "{text}"
    );
}

/// W368: a v2 activation names the page-cache site, recipe and pin; v1 none.
#[test]
fn activation_plans_show_their_page_cache_opt_in() {
    let (ok, text) = inspect(&format!("{FIXTURES}/ols-plan.json"));
    assert!(ok, "{text}");
    assert!(!text.contains("page cache"), "{text}");
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/ols-plan-v2-vectors.json"
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ri-inspect-ols-v2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plan.json");
    std::fs::write(&path, vectors[0]["plan_canonical"].as_str().unwrap()).unwrap();
    let (ok, text) = inspect(path.to_str().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok, "{text}");
    assert!(
        text.starts_with(&format!(
            "verb: config_activate\nplan digest: {}\n",
            vectors[0]["plan_digest"].as_str().unwrap()
        )),
        "{text}"
    );
    for line in [
        "page cache site: blog5\n",
        "page cache recipe: litespeed_cache_793_v1\n",
        &format!("page cache recipe sha256: {}\n", "e".repeat(64)),
        "page cache effects: per-site cache storage and post-password bypass; pinned plugin \
         unpacked (or the same pinned tree reused) and activated as the site; fixed settings \
         stored and locked with the page cache off; existing logins ended; no network\n",
    ] {
        assert!(text.contains(line), "{line} in {text}");
    }
}

/// W370: a v3 activation names the page-cache opt-out site and its effects.
#[test]
fn activation_plans_show_their_page_cache_opt_out() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/ols-plan-v3-vectors.json"
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ri-inspect-ols-v3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plan.json");
    std::fs::write(&path, vectors[0]["plan_canonical"].as_str().unwrap()).unwrap();
    let (ok, text) = inspect(path.to_str().unwrap());
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(ok, "{text}");
    assert!(
        text.starts_with(&format!(
            "verb: config_activate\nplan digest: {}\n",
            vectors[0]["plan_digest"].as_str().unwrap()
        )),
        "{text}"
    );
    for line in [
        "page cache opt-out site: blog5\n",
        "page cache recipe: litespeed_cache_793_v1\n",
        "page cache effects: cache storage removed from the site's server settings; plugin \
         deactivated as the site; the site's own cache storage emptied; no network\n",
    ] {
        assert!(text.contains(line), "{line} in {text}");
    }
    assert!(!text.contains("page cache site:"), "{text}");
}

/// W395: the cache-on recipe says that the page cache is turned on, and its
/// opt-out names the same recipe.
#[test]
fn activation_plans_show_the_cache_on_recipe() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../contracts/tests/fixtures/ols-plan-cache-on-vectors.json"
    ))
    .unwrap();
    let dir = std::env::temp_dir().join(format!("ri-inspect-ols-on-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plan.json");
    let mut texts = Vec::new();
    for vector in vectors.as_array().unwrap() {
        std::fs::write(&path, vector["plan_canonical"].as_str().unwrap()).unwrap();
        let (ok, text) = inspect(path.to_str().unwrap());
        assert!(ok, "{text}");
        texts.push(text);
    }
    std::fs::remove_dir_all(&dir).unwrap();
    for line in [
        "page cache site: blog5\n",
        "page cache recipe: litespeed_cache_793_cache_on_v1\n",
        "page cache recipe sha256: 3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767\n",
        "page cache effects: per-site cache storage and post-password bypass; pinned plugin \
         unpacked (or the same pinned tree reused) and activated as the site; fixed settings \
         stored and locked with the page cache ON for anonymous visitors; existing logins \
         ended; an anonymous GET / must be stored and then served from the cache; no network\n",
    ] {
        assert!(texts[0].contains(line), "{line} in {}", texts[0]);
    }
    assert!(!texts[0].contains("page cache off"), "{}", texts[0]);
    for line in [
        "page cache opt-out site: blog5\n",
        "page cache recipe: litespeed_cache_793_cache_on_v1\n",
    ] {
        assert!(texts[1].contains(line), "{line} in {}", texts[1]);
    }
}

#[test]
fn grants_unknown_input_and_bad_usage_are_refused_without_echo() {
    let dir = std::env::temp_dir().join(format!("ri-plan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let canary = dir.join("canary.json");
    std::fs::write(&canary, b"{\"plan\":\"CANARY_VALUE\"}").unwrap();
    for path in [
        format!("{FIXTURES}/site-grant.json"),
        canary.to_string_lossy().into_owned(),
        dir.join("missing.json").to_string_lossy().into_owned(),
    ] {
        let (ok, text) = inspect(&path);
        assert!(!ok);
        assert_eq!(
            text,
            "{\"scope\":\"plan_inspect\",\"error\":\"INVALID_PLAN_INPUT\"}\n"
        );
    }
    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .arg("sign")
        .output()
        .unwrap();
    assert!(!out.status.success());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn inspector_refuses_a_final_symlink_and_special_file() {
    let dir = std::env::temp_dir().join(format!("ri-plan-links-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let link = dir.join("plan.json");
    std::os::unix::fs::symlink(format!("{FIXTURES}/site-plan.json"), &link).unwrap();
    for path in [link.to_string_lossy().into_owned(), "/dev/null".to_owned()] {
        let (ok, text) = inspect(&path);
        assert!(!ok);
        assert_eq!(
            text,
            "{\"scope\":\"plan_inspect\",\"error\":\"INVALID_PLAN_INPUT\"}\n"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// W440 (D-053): the review of an import names the exact archive, the
/// dry-run facts the executor rechecks, and what the import never does.
#[test]
fn an_import_review_names_the_archive_the_checked_facts_and_the_limits() {
    let (ok, text) = inspect(&format!("{FIXTURES}/import-plan.json"));
    assert!(ok, "{text}");
    assert!(text.starts_with(
        "verb: site_import\nplan digest: 1895f25c6f844fe2d4bbd366846581b9a47d2daa753a51c19688923ace660e8c\n"
    ), "{text}");
    for wanted in [
        "site: blog1",
        "hostname: blog1.example.test",
        &format!("archive sha256: {}", "b".repeat(64)),
        &format!("manifest sha256: {}", "c".repeat(64)),
        "files: 4200 entries, 90000000 bytes",
        "database dump: 12000000 bytes",
        "php: 8.2",
        "quota: hard 5242880 KiB, 500000 inodes",
        "foreign code and database",
        "no traffic activation, no DNS or mail change",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
}

#[test]
fn a_static_alias_review_displays_both_names_and_the_admission_limit() {
    let (ok, summary) = inspect(&format!("{FIXTURES}/import-plan-alias.json"));
    assert!(ok, "{summary}");
    for line in [
        "hostname: blog1.example.test",
        "alias hostname: alternate.example.test",
        "alias serving: HTTP on the enrolled loopback listener after separate activation",
    ] {
        assert!(summary.lines().any(|actual| actual == line), "{summary}");
    }
}

#[test]
fn an_alias_certificate_review_names_both_hosts_and_its_renewal_scope() {
    let (ok, summary) = inspect(&format!("{FIXTURES}/certificate-plan-alias.json"));
    assert!(ok, "{summary}");
    for line in [
        "hostname: blog1.example.test",
        "alias hostname: alternate.example.test",
        "alias certificate support: private CA and loopback listeners",
        "standing renewal: through Unix timestamp 3600 for both hostnames",
    ] {
        assert!(summary.lines().any(|actual| actual == line), "{summary}");
    }
}

/// D-070: a renamed import review names both hostnames and what it rewrites;
/// an import under the same name says so.
#[test]
fn an_import_review_names_a_hostname_change() {
    let (ok, text) = inspect(&format!("{FIXTURES}/import-plan-rename.json"));
    assert!(ok, "{text}");
    for wanted in [
        "hostname: blog1.example.test\n",
        "source hostname: blog1.example.org; the import rewrites //blog1.example.org to //blog1.example.test in the site's database\n",
    ] {
        assert!(text.contains(wanted), "{wanted}: {text}");
    }
    let (ok, text) = inspect(&format!("{FIXTURES}/import-plan.json"));
    assert!(ok, "{text}");
    assert!(
        text.contains("source hostname: the same hostname\n"),
        "{text}"
    );
}

/// W459 (D-057): a scrub review names what is removed and that no site is deleted.
#[test]
fn an_import_scrub_review_names_what_is_removed() {
    let (ok, text) = inspect(&format!("{FIXTURES}/scrub-plan.json"));
    assert!(ok, "{text}");
    for line in [
        "site: blog1\n",
        "import operation: op_import\n",
        "deletes no site, account, database or document root",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
}

/// W513 (D-084): the review of an update names each component with both
/// versions, the capture, and what a failure restores.
/// W571 (D-095): the review of a proxy site names every route and
/// WebSocket path with its loopback port, and what the plan never does.
#[test]
fn a_proxy_site_review_names_each_route_and_the_limits() {
    let (ok, text) = inspect(&format!("{FIXTURES}/proxy-site-plan.json"));
    assert!(ok, "{text}");
    for line in [
        "site: ytproxy\n",
        "hostname: yt.example.test\n",
        "route: / -> 127.0.0.1:3100\n",
        "route: /api/ -> 127.0.0.1:3101\n",
        "route: /downloads/ -> 127.0.0.1:3101\n",
        "websocket: /ws/ -> 127.0.0.1:3100\n",
        "no PHP and no database",
        "starts, changes, and backs up no service behind the ports",
        "adds no X-Forwarded-For",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
}

/// W553 (D-091): the review of a record change marks each mail set.
#[test]
fn a_dns_change_review_marks_mail_sets() {
    let (ok, text) = inspect(&format!("{FIXTURES}/dns-change-plan.json"));
    assert!(ok, "{text}");
    assert!(text.starts_with("verb: dns_change\n"), "{text}");
    assert!(text.contains("example.test. TXT [MAIL]"), "{text}");
    assert!(text.contains("old.example.test. CNAME"), "{text}");
}

#[test]
fn an_update_review_names_each_component_and_the_rollback() {
    let (ok, text) = inspect(&format!("{FIXTURES}/update-plan.json"));
    assert!(ok, "{text}");
    for line in [
        "site: blog1\n",
        "capture operation: op_capture\n",
        "component: plugin hello-dolly 1.7.1 -> 1.7.2\n",
        "component: theme twentytwentyfour 1.2 -> 1.3\n",
        "restores the site database from the capture",
        "deletes no backup",
    ] {
        assert!(text.contains(line), "{line}: {text}");
    }
}

/// W576 (D-095): the review of a schema 2 deletion says it names no
/// capture and is refused unless the site is a proxy site.
#[test]
fn a_proxy_deletion_review_says_no_capture() {
    let mut plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{FIXTURES}/delete-plan.json")).unwrap())
            .unwrap();
    plan["schema_version"] = serde_json::json!(2);
    plan.as_object_mut().unwrap().remove("capture_operation_id");
    let path = std::env::temp_dir().join(format!("ri-delete-v2-{}.json", std::process::id()));
    std::fs::write(&path, plan.to_string()).unwrap();
    let (ok, text) = inspect(path.to_str().unwrap());
    std::fs::remove_file(&path).unwrap();
    assert!(ok, "{text}");
    assert!(text.starts_with("verb: site_delete\n"), "{text}");
    assert!(
        text.contains("capture operation: none: refused unless the site is a proxy site"),
        "{text}"
    );
}

#[test]
fn p23_inspect_and_envelope_expose_blast_radius_and_all_site_ols_impact() {
    let (ok, text) = inspect(&format!("{FIXTURES}/ols-plan.json"));
    assert!(ok, "{text}");
    assert!(
        text.contains("blast radius: scope AllServedSitesOlsReload;"),
        "{text}"
    );
    assert!(
        text.contains("all-site OLS impact: Global OLS reload: affects every served site"),
        "{text}"
    );

    let out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .args(["envelope", &format!("{FIXTURES}/ols-plan.json")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let env: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(env["verb"], "config_activate");
    assert_eq!(env["all_served_sites"], true);
    assert_eq!(env["ols_reloads"], 1);
    assert_eq!(env["compensation_reloads"], 1);
    assert!(
        env["all_site_ols_impact"]
            .as_str()
            .unwrap()
            .contains("Global OLS reload")
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .args(["envelope", &format!("{FIXTURES}/missing-plan.json")])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn p27_app_plans_build_inspect_and_report_envelopes_offline() {
    let dir = std::env::temp_dir().join(format!("ri-p27-plans-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let digest = "a".repeat(64);
    let art = "b".repeat(64);
    let man = "c".repeat(64);

    // 1. app_provision
    let prov = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "app-provision",
            "--plan-id",
            "plan_ap1",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            &digest,
            "--requester",
            "agent_1",
            "--site-id",
            "serpapi",
            "--hostname",
            "api.example.test",
            "--runtime",
            "bun_1_v1",
            "--port",
            "43187",
            "--websocket-prefix",
            "/ws/",
            "--entrypoint",
            "src/index.ts",
            "--worker-entrypoint",
            "src/worker.ts",
            "--health-path",
            "/health",
            "--env-key",
            "Z_TOKEN",
            "--env-key",
            "A_SECRET",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(
        prov.status.success(),
        "{}",
        String::from_utf8_lossy(&prov.stderr)
    );
    let prov_path = dir.join("app-provision.json");
    std::fs::write(&prov_path, &prov.stdout).unwrap();
    let (ok, text) = inspect(prov_path.to_str().unwrap());
    assert!(ok, "{text}");
    for expected in [
        "verb: app_provision",
        "runtime: bun_1_v1",
        "loopback port: 127.0.0.1:43187",
        "worker entrypoint: src/worker.ts",
        "env keys: A_SECRET, Z_TOKEN (names only;",
        "blast radius: scope SingleSite;",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }

    // 2. app_deploy
    let dep = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "app-deploy",
            "--plan-id",
            "plan_ad1",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            &digest,
            "--requester",
            "agent_1",
            "--site-id",
            "serpapi",
            "--release-id",
            "rel-1.0.0",
            "--runtime",
            "bun_1_v1",
            "--artifact-sha256",
            &art,
            "--manifest-sha256",
            &man,
            "--file-count",
            "42",
            "--total-bytes",
            "65536",
            "--health-path",
            "/health",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(
        dep.status.success(),
        "{}",
        String::from_utf8_lossy(&dep.stderr)
    );
    let dep_path = dir.join("app-deploy.json");
    std::fs::write(&dep_path, &dep.stdout).unwrap();
    let (ok, text) = inspect(dep_path.to_str().unwrap());
    assert!(ok, "{text}");
    assert!(text.contains("verb: app_deploy\n"), "{text}");
    assert!(text.contains("release: rel-1.0.0\n"), "{text}");

    // 3. app_lifecycle
    let life = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "app-lifecycle",
            "--plan-id",
            "plan_al1",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            &digest,
            "--requester",
            "agent_1",
            "--site-id",
            "serpapi",
            "--action",
            "restart",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(
        life.status.success(),
        "{}",
        String::from_utf8_lossy(&life.stderr)
    );
    let life_path = dir.join("app-lifecycle.json");
    std::fs::write(&life_path, &life.stdout).unwrap();
    let (ok, text) = inspect(life_path.to_str().unwrap());
    assert!(ok, "{text}");
    assert!(text.contains("verb: app_lifecycle\n"), "{text}");
    assert!(text.contains("action: restart\n"), "{text}");

    let env_out = Command::new(env!("CARGO_BIN_EXE_rustiron-plan"))
        .args(["envelope", dep_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(env_out.status.success());
    let env: serde_json::Value = serde_json::from_slice(&env_out.stdout).unwrap();
    assert_eq!(env["verb"], "app_deploy");
    assert_eq!(env["ols_reloads"], 0);
    assert_eq!(env["all_served_sites"], false);

    // 4. D-102 schema v2: fullstack_split with Caddy + PostgreSQL 18 + blue/green + SSE
    let split = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "app-provision",
            "--plan-id",
            "plan_ap_v2",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            &digest,
            "--requester",
            "agent_1",
            "--site-id",
            "saasv2",
            "--hostname",
            "saas.example.test",
            "--runtime",
            "bun_1_v1",
            "--port",
            "4101",
            "--ingress",
            "caddy",
            "--topology",
            "fullstack_split",
            "--database",
            "postgresql_18",
            "--blue-green",
            "--standby-port",
            "4102",
            "--spa-fallback",
            "--frontend-dir",
            "frontend",
            "--route-prefix",
            "/api/",
            "--strip-api-prefix",
            "/api/",
            "--sse-prefix",
            "/api/events/",
            "--entrypoint",
            "backend/index.ts",
            "--health-path",
            "/api/health",
            "--env-key",
            "DATABASE_URL",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(
        split.status.success(),
        "{}",
        String::from_utf8_lossy(&split.stderr)
    );
    let split_path = dir.join("app-provision-v2.json");
    std::fs::write(&split_path, &split.stdout).unwrap();
    let (ok, text) = inspect(split_path.to_str().unwrap());
    assert!(ok, "{text}");
    for expected in [
        "ingress: caddy",
        "topology: fullstack_split",
        "database: postgresql_18",
        "blue/green: true",
        "standby port: 127.0.0.1:4102",
        "frontend dir: frontend",
        "sse prefixes: /api/events/",
        "strip api prefixes: /api/",
    ] {
        assert!(text.contains(expected), "{expected}: {text}");
    }

    // 5. D-102 schema v2: site-credential-rotate for app_postgresql_18_password
    let rot_pg = Command::new(env!("CARGO_BIN_EXE_rustiron"))
        .args([
            "plan",
            "create",
            "site-credential-rotate",
            "--plan-id",
            "plan_rot_pg1",
            "--host-id",
            "host_lab",
            "--host-epoch",
            "epoch_1",
            "--profile-digest",
            &digest,
            "--requester",
            "agent_1",
            "--site-id",
            "saasv2",
            "--hostname",
            "saas.example.test",
            "--target",
            "app_postgresql_18_password",
            "--valid-from",
            "1000",
            "--expires-at",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(
        rot_pg.status.success(),
        "{}",
        String::from_utf8_lossy(&rot_pg.stderr)
    );
    let rot_path = dir.join("rotate-pg.json");
    std::fs::write(&rot_path, &rot_pg.stdout).unwrap();
    let (ok, text) = inspect(rot_path.to_str().unwrap());
    assert!(ok, "{text}");
    assert!(
        text.contains("target: app_postgresql_18_password"),
        "{text}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}
