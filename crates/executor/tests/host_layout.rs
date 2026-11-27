//! W284 (B01): `layout.rs` is the only executor source that names a
//! Rustiron-owned host location, and the copies that cannot import it (PHP
//! assets, other crates, lab units, SELinux file contexts) still agree.
use std::{fs, path::Path};

use rustiron_executor::layout::{lab as layout, product};

/// Path fragments only a Rustiron-owned location contains.
const OWNED: [&str; 9] = [
    "/etc/rustiron",
    "/var/lib/rustiron",
    "/run/rustiron",
    "libexec/rustiron",
    "/srv/sites",
    "/srv/restore-probes",
    "/systemd/system/rustiron",
    "rustiron-s0",
    "rustiron-sites",
];

/// Production lines of one source file: everything before its first test
/// module, without comment lines.
fn production_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .take_while(|(_, line)| !line.contains("#[cfg(test)]"))
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

fn sources(directory: &Path, found: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if path.is_dir() {
            sources(&path, found);
        } else if name.ends_with(".rs") && !name.ends_with("tests.rs") && name != "layout.rs" {
            found.push(path);
        }
    }
}

#[test]
fn no_other_source_names_an_owned_location() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() > 20, "source walk found {} files", files.len());
    let mut hits = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file).unwrap();
        for (number, line) in production_lines(&text) {
            if OWNED.iter().any(|fragment| line.contains(fragment)) {
                hits.push(format!(
                    "{}:{}: {}",
                    file.display(),
                    number + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "owned locations outside layout.rs:\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_guard_sees_a_planted_literal() {
    // The scan must not pass because it reads nothing.
    let planted = "fn f() {\n    let p = \"/etc/rustiron-s02-lab/x\";\n}\n#[cfg(test)]\nmod t {}\n";
    let hits: Vec<_> = production_lines(planted)
        .filter(|(_, line)| OWNED.iter().any(|fragment| line.contains(fragment)))
        .collect();
    assert_eq!(hits.len(), 1);
    let test_only = "#[cfg(test)]\nmod t { const P: &str = \"/srv/sites/x\"; }\n";
    assert_eq!(production_lines(test_only).count(), 0);
}

#[test]
fn php_assets_name_only_the_sites_root() {
    for asset in [
        include_str!("../src/provision_assets/install.php"),
        include_str!("../src/provision_assets/verify.php"),
        include_str!("../src/restore_assets/render.php"),
    ] {
        let roots = asset.matches("/srv/").count();
        assert_eq!(roots, asset.matches(layout::SITES_ROOT).count());
        for fragment in OWNED.iter().filter(|f| **f != "/srv/sites") {
            assert!(!asset.contains(fragment), "asset names {fragment}");
        }
    }
    assert!(include_str!("../src/provision_assets/verify.php").contains(layout::SITES_ROOT));
}

#[test]
fn other_crates_repeat_the_same_locations() {
    let submit = include_str!("../../cli/src/submit_main.rs");
    assert!(submit.contains(&format!("default_value = \"{}\"", layout::EXECUTOR_SOCKET)));
    let host = include_str!("../../control/src/host.rs");
    assert!(host.contains(&format!(
        "\"{}/current/vhosts.conf\"",
        layout::OLS_INCLUDE_DIR
    )));
    let uninstall = include_str!("../../cli/src/uninstall.rs");
    let state = Path::new(layout::JOURNAL_DIR).parent().unwrap();
    let recipes = Path::new(layout::RECIPES_DIR).parent().unwrap();
    for path in [
        Path::new(layout::OLS_INCLUDE_DIR),
        Path::new(layout::POLICY_DIR),
        state,
        recipes,
    ] {
        let relative = path.strip_prefix("/").unwrap().to_str().unwrap();
        assert!(
            uninstall.contains(&format!("\"{relative}\",")),
            "uninstall does not move {relative}"
        );
    }
    // Every executor state directory sits under the one moved root.
    for path in [
        layout::FIXTURE_REGISTRY_DIR.unwrap(),
        layout::SCRATCH_DIR,
        layout::MARK_DIR,
    ] {
        assert!(Path::new(path).starts_with(state), "{path}");
    }
}

fn setting<'a>(unit: &'a str, key: &str) -> Vec<&'a str> {
    unit.lines()
        .filter_map(|line| line.trim().strip_prefix(key)?.strip_prefix('='))
        .collect()
}

#[test]
fn lab_units_create_the_runtime_directories_the_binaries_bind_in() {
    let executor = include_str!("../../../lab/s02/rustiron-s02-lab-executor.service");
    let helper = include_str!("../../../lab/s10/rustiron-s10-lab-admin-helper.service");
    let socket = include_str!("../../../lab/s03/rustiron-site-php@.socket");
    let run = |directory: &str| format!("/run/{directory}");
    assert_eq!(
        setting(executor, "RuntimeDirectory")
            .into_iter()
            .map(run)
            .collect::<Vec<_>>(),
        [Path::new(layout::EXECUTOR_SOCKET)
            .parent()
            .unwrap()
            .to_str()
            .unwrap()]
    );
    assert_eq!(
        setting(helper, "RuntimeDirectory")
            .into_iter()
            .map(run)
            .collect::<Vec<_>>(),
        [layout::ADMIN_RUNTIME_DIR]
    );
    assert_eq!(
        setting(socket, "ListenStream"),
        [format!("{}/%i.sock", layout::SITE_SOCKETS_DIR)]
    );
    let state = Path::new(layout::JOURNAL_DIR)
        .parent()
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(setting(executor, "ReadWritePaths"), [state]);
}

#[test]
fn product_units_match_the_compiled_layout() {
    let executor = include_str!("../../../packaging/systemd/rustiron-executor.service");
    let helper = include_str!("../../../packaging/systemd/rustiron-admin-helper.service");
    let executor_runtime = format!("/run/{}", setting(executor, "RuntimeDirectory")[0]);
    let helper_runtime = format!("/run/{}", setting(helper, "RuntimeDirectory")[0]);
    // W500-F1: the helper starts after the store namespace handle exists.
    assert_eq!(setting(helper, "After"), ["rustiron-store-netns.service"]);
    assert_eq!(
        Path::new(&executor_runtime),
        Path::new(product::EXECUTOR_SOCKET).parent().unwrap()
    );
    assert_eq!(helper_runtime, product::ADMIN_RUNTIME_DIR);

    let state = Path::new(product::JOURNAL_DIR)
        .parent()
        .unwrap()
        .to_str()
        .unwrap();
    let writable: Vec<_> = setting(executor, "ReadWritePaths")
        .into_iter()
        .flat_map(str::split_whitespace)
        .collect();
    assert_eq!(
        writable,
        [
            state,
            product::OLS_INCLUDE_DIR,
            product::OLS_EJECTED_DIR,
            product::CADDY_CONFIG_DIR
        ]
    );
    // W381 (D-032): the boot guard writes only the journal lease and the
    // `current` link, through the executor binary.
    let guard = include_str!("../../../packaging/systemd/rustiron-ols-boot-guard.service");
    let writable: Vec<_> = setting(guard, "ReadWritePaths")
        .into_iter()
        .flat_map(str::split_whitespace)
        .collect();
    assert_eq!(writable, [state, product::OLS_INCLUDE_DIR]);
    assert_eq!(
        setting(guard, "ExecStart"),
        ["/usr/libexec/rustiron/rustiron-executor ols-boot-guard"]
    );
}

#[test]
fn selinux_file_contexts_name_the_job_and_helper_locations() {
    let capture = include_str!("../../../lab/s07/selinux/rustiron_capture.fc");
    assert!(
        capture
            .lines()
            .any(|l| l.split_whitespace().next() == Some(layout::JOB_RESTIC))
    );
    for line in capture.lines().filter(|l| l.contains("libexec")) {
        assert!(
            line.starts_with(&format!("{}/", layout::JOB_BIN_DIR)),
            "{line}"
        );
    }
    let admin = include_str!("../../../policy/selinux/rustiron_admin.fc");
    assert!(admin.contains(&format!("{}\t-d\t", layout::RESTORE_PROBES_ROOT)));
    assert!(admin.contains(&format!("{}(/.*)?\t", layout::ADMIN_RUNTIME_DIR)));
    let executor = include_str!("../../../policy/selinux/rustiron_executor.fc");
    for path in [
        layout::OLS_INCLUDE_DIR,
        layout::OLS_EJECTED_DIR,
        layout::CADDY_CONFIG_DIR,
    ] {
        assert!(executor.contains(&format!("{path}(/.*)?\t")), "{path}");
    }
}
