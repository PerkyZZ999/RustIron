//! W368: pure parts of the page-cache opt-in effect. W370: the stored and
//! locked settings, the re-enable check and the closed purge job. No host
//! effects outside temporary folders.

use super::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::os::unix::fs::{DirBuilderExt, symlink};

const V1: PageCacheRecipe = PageCacheRecipe::LitespeedCache793V1;
const ON: PageCacheRecipe = PageCacheRecipe::LitespeedCache793CacheOnV1;

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn list(files: &[(&str, &[u8])]) -> Vec<u8> {
    let listed: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(path, data)| {
            (
                (*path).to_owned(),
                json!({"md5": "0".repeat(32), "sha256": hex(data)}),
            )
        })
        .collect();
    serde_json::to_vec(&json!({
        "plugin": "litespeed-cache", "version": "7.9.3",
        "source": "https://plugins.svn.wordpress.org/litespeed-cache/tags/7.9.3/",
        "zip": "https://downloads.wordpress.org/plugin/litespeed-cache.7.9.3.zip",
        "files": listed,
    }))
    .unwrap()
}

#[test]
fn the_recipe_pins_are_the_reviewed_values() {
    assert_eq!(
        TAR_SHA256,
        "0db968c7e9ae8a17023f2db3fef1134ba006e1e3f104c3fe715b7f46534e20a9"
    );
    assert_eq!(
        CHECKSUMS_SHA256,
        "41dc8e796d55435e69abefd7274c075c694c2a7f451084095be9bfd38112d982"
    );
    assert_eq!(RECIPE_TAR, "litespeed-cache-7.9.3.tar");
    assert_eq!(RECIPE_CHECKSUMS, "litespeed-cache-7.9.3.checksums.json");
    assert_eq!(
        recipe_digest(PageCacheRecipe::LitespeedCache793V1).as_str(),
        TAR_SHA256
    );
}

#[test]
fn the_checksum_list_decoder_is_closed() {
    let good = list(&[("litespeed-cache.php", b"a"), ("src/base.cls.php", b"b")]);
    let parsed = parse_checksums(&good).unwrap();
    assert_eq!(
        parsed,
        vec![
            ("litespeed-cache.php".to_owned(), hex(b"a")),
            ("src/base.cls.php".to_owned(), hex(b"b")),
        ]
    );
    let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();
    let base: serde_json::Value = serde_json::from_slice(&good).unwrap();
    let mut with = |label, pointer: &str, value: serde_json::Value| {
        let mut changed = base.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        cases.push((label, changed));
    };
    with("other plugin", "/plugin", json!("other"));
    with("other version", "/version", json!("7.9.4"));
    with("files not a map", "/files", json!([]));
    with("empty", "/files", json!({}));
    with(
        "array digest",
        "/files/litespeed-cache.php/sha256",
        json!([hex(b"a")]),
    );
    with(
        "upper hex",
        "/files/litespeed-cache.php/sha256",
        json!(hex(b"a").to_uppercase()),
    );
    with(
        "short hex",
        "/files/litespeed-cache.php/sha256",
        json!("ab"),
    );
    with("extra member", "/source", json!({"x": 1}));
    for path in [
        "/abs.php",
        "a/../b.php",
        "./a.php",
        "a b.php",
        "a//b.php",
        "a/",
        "ü.php",
    ] {
        let mut changed = base.clone();
        changed["files"][path] = json!({"sha256": hex(b"c")});
        cases.push(("unsafe path", changed));
    }
    let mut extra_top = base.clone();
    extra_top["command"] = json!("wp plugin install");
    cases.push(("unknown top member", extra_top));
    for (label, value) in cases {
        assert!(
            parse_checksums(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{label}"
        );
    }
    assert!(parse_checksums(b"not json").is_err());
    let many: Vec<(String, &[u8])> = (0..=MAX_FILES)
        .map(|n| (format!("f{n}.php"), b"x".as_slice()))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = many.iter().map(|(p, d)| (p.as_str(), *d)).collect();
    assert!(parse_checksums(&list(&borrowed)).is_err(), "too many files");
}

#[test]
fn the_unpack_job_writes_only_the_plugins_folder_as_the_site() {
    let args = unpack_args(
        "rs_blog1",
        "s0:c201",
        "/srv/sites/rs_blog1/html/wp-content/plugins",
        "/srv/sites/rs_blog1/tmp/page-cache-unpack.tar",
    );
    let properties: Vec<&str> = args
        .windows(2)
        .filter(|pair| pair[0] == "--property")
        .map(|pair| pair[1].as_str())
        .collect();
    for want in [
        "User=rs_blog1",
        "Group=rs_blog1",
        "SELinuxContext=system_u:system_r:rustiron_unpack_t:s0:c201",
        "ReadWritePaths=/srv/sites/rs_blog1/html/wp-content/plugins",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "PrivateNetwork=yes",
        "ProtectSystem=strict",
        "UMask=0022",
    ] {
        assert!(properties.contains(&want), "{want}");
    }
    assert_eq!(
        properties
            .iter()
            .filter(|p| p.starts_with("ReadWritePaths="))
            .count(),
        1
    );
    let command: Vec<&str> = args
        .iter()
        .skip_while(|arg| *arg != "--")
        .map(String::as_str)
        .collect();
    assert_eq!(
        command,
        [
            "--",
            "/usr/bin/tar",
            "--extract",
            "--file=/srv/sites/rs_blog1/tmp/page-cache-unpack.tar",
            "--directory=/srv/sites/rs_blog1/html/wp-content/plugins",
            "--no-same-owner",
            "--numeric-owner",
            "--no-same-permissions",
            "--keep-old-files",
        ]
    );
}

#[test]
fn the_settings_file_has_fixed_bytes_and_keeps_every_feature_off() {
    let value: serde_json::Value = serde_json::from_str(SETTINGS_JSON).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(
        object.len(),
        SETTINGS.len() + LIST_SETTINGS.len() + TEXT_SETTINGS.len()
    );
    assert_eq!(object.len(), 35);
    for key in SETTINGS {
        assert_eq!(object[key], json!(0), "{key}");
    }
    for (key, items) in LIST_SETTINGS {
        assert_eq!(object[key], json!(items), "{key}");
    }
    for (key, text) in TEXT_SETTINGS {
        assert_eq!(object[key], json!(text), "{key}");
    }
    for required in [
        "cache",
        "cache-priv",
        "cache-commenter",
        "cache-page_login",
        "cache-rest",
        "esi",
        "guest",
        "guest_optm",
        "object",
        "crawler",
        "auto_upgrade",
        "news",
        "cdn-quic",
    ] {
        assert!(SETTINGS.contains(&required), "{required}");
    }
    // W370 (A8, A9): WordPress's pending-comment link page is never cached.
    assert_eq!(
        object["cache-exc_qs"],
        json!(["unapproved", "moderation-hash"])
    );
    // W370: no forced public or forced cacheable URI, and the default login
    // vary cookie that OLS keys on (`_lscache_vary`).
    assert_eq!(object["cache-force_uri"], json!([]));
    assert_eq!(object["cache-force_pub_uri"], json!([]));
    assert_eq!(object["cache-login_cookie"], json!(""));
    assert_eq!(
        hex(SETTINGS_JSON.as_bytes()),
        SETTINGS_SHA256,
        "the fixed settings bytes are pinned"
    );
    // W368 pinned the 31 zero keys alone.
    assert_ne!(
        SETTINGS_SHA256,
        "8909e131db6458f2c45aa2ea3e03b5a0c9a32c532f2481227aa1b57438d72f9a"
    );
}

/// W370: the must-use file defines one `LITESPEED_CONF__*` constant per
/// fixed setting with the same value, so the plugin reads the fixed values
/// over its stored options and the dashboard cannot change them.
#[test]
fn the_lock_file_defines_one_constant_per_fixed_setting() {
    let text = lock_file(V1);
    assert_eq!(
        hex(text.as_bytes()),
        LOCK_SHA256,
        "the lock bytes are pinned"
    );
    assert!(text.starts_with("<?php\n"));
    assert!(text.contains("\ndefined('ABSPATH') || exit;\n"));
    assert!(text.contains("\ndefine('LITESPEED_CONF', true);\n"));
    let defines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("define('LITESPEED_CONF__"))
        .collect();
    assert_eq!(defines.len(), 35);
    for line in [
        "define('LITESPEED_CONF__CACHE', 0);",
        "define('LITESPEED_CONF__CACHE__PRIV', 0);",
        "define('LITESPEED_CONF__IMG_OPTM__AUTO', 0);",
        "define('LITESPEED_CONF__CACHE__EXC_QS', ['unapproved', 'moderation-hash']);",
        "define('LITESPEED_CONF__CACHE__FORCE_URI', []);",
        "define('LITESPEED_CONF__CACHE__FORCE_PUB_URI', []);",
        "define('LITESPEED_CONF__CACHE__LOGIN_COOKIE', '');",
    ] {
        assert!(defines.contains(&line), "{line}\n{text}");
    }
    assert_eq!(
        const_name("optm-ggfonts_async"),
        "LITESPEED_CONF__OPTM__GGFONTS_ASYNC"
    );
    for forbidden in [
        "$_", "$argv", "exec(", "system(", "eval(", "include", "require",
    ] {
        assert!(!text.contains(forbidden), "{forbidden}");
    }
    for line in text.lines() {
        assert!(
            line.starts_with("define('LITESPEED_CONF__")
                || line.starts_with("// ")
                || [
                    "<?php",
                    "defined('ABSPATH') || exit;",
                    "define('LITESPEED_CONF', true);"
                ]
                .contains(&line),
            "unexpected line {line:?}"
        );
    }
}

#[test]
fn the_listing_must_be_exactly_the_listed_regular_files() {
    let names = "litespeed-cache/a.php\nlitespeed-cache/src/b.php\n";
    let verbose = "-rw-r--r-- 0/0 1 1970-01-01 00:00 litespeed-cache/a.php\n\
                   -rw-r--r-- 0/0 1 1970-01-01 00:00 litespeed-cache/src/b.php\n";
    assert!(listing_matches(names, verbose, 2));
    assert!(!listing_matches(names, verbose, 3), "count");
    assert!(!listing_matches(
        "litespeed-cache/a.php\nother/b.php\n",
        verbose,
        2
    ));
    assert!(!listing_matches(
        names,
        "-rw-r--r-- 0/0 1 1970-01-01 00:00 litespeed-cache/a.php\n\
         lrwxrwxrwx 0/0 0 1970-01-01 00:00 litespeed-cache/src/b.php -> /etc\n",
        2
    ));
    assert!(!listing_matches("", "", 0), "empty");
}

struct Tree(std::path::PathBuf);
impl Drop for Tree {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn tree(files: &[(&str, &[u8])]) -> Tree {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "ri-page-cache-tree-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(&root)
        .unwrap();
    for (path, data) in files {
        let full = root.join(path);
        std::fs::DirBuilder::new()
            .mode(0o755)
            .recursive(true)
            .create(full.parent().unwrap())
            .unwrap();
        std::fs::write(full, data).unwrap();
    }
    Tree(root)
}

#[test]
fn every_listed_file_must_match_its_digest_through_no_link() {
    let uid = rustix::process::getuid().as_raw();
    let files: &[(&str, &[u8])] = &[("a.php", b"a"), ("src/b.php", b"b"), ("src/c/d.php", b"d")];
    let listed = parse_checksums(&list(files)).unwrap();
    let good = tree(files);
    let dir = crate::files::open_traversable_directory(&good.0, uid).unwrap();
    assert_eq!(verify_listed(&dir, uid, &listed), Ok(()));
    drop(good);

    let changed = tree(&[("a.php", b"a"), ("src/b.php", b"B"), ("src/c/d.php", b"d")]);
    let dir = crate::files::open_traversable_directory(&changed.0, uid).unwrap();
    assert!(verify_listed(&dir, uid, &listed).is_err(), "changed bytes");
    drop(changed);

    let missing = tree(&[("a.php", b"a"), ("src/b.php", b"b")]);
    let dir = crate::files::open_traversable_directory(&missing.0, uid).unwrap();
    assert!(verify_listed(&dir, uid, &listed).is_err(), "missing file");
    drop(missing);

    let linked = tree(&[
        ("a.php", b"a"),
        ("src/c/d.php", b"d"),
        ("elsewhere/b.php", b"b"),
    ]);
    symlink(linked.0.join("elsewhere/b.php"), linked.0.join("src/b.php")).unwrap();
    let dir = crate::files::open_traversable_directory(&linked.0, uid).unwrap();
    assert!(verify_listed(&dir, uid, &listed).is_err(), "final link");
    drop(linked);

    let dir_link = tree(&[
        ("a.php", b"a"),
        ("real/b.php", b"b"),
        ("real/c/d.php", b"d"),
    ]);
    symlink(dir_link.0.join("real"), dir_link.0.join("src")).unwrap();
    let dir = crate::files::open_traversable_directory(&dir_link.0, uid).unwrap();
    assert!(verify_listed(&dir, uid, &listed).is_err(), "directory link");
}

fn report() -> serde_json::Value {
    let fixed: serde_json::Map<_, _> = serde_json::from_str::<serde_json::Value>(SETTINGS_JSON)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    let settings: serde_json::Map<_, _> = fixed
        .iter()
        .map(|(key, value)| {
            let stored = if *value == json!(0) {
                json!("0")
            } else {
                value.clone()
            };
            (key.clone(), stored)
        })
        .collect();
    let view: serde_json::Map<_, _> = fixed
        .iter()
        .map(|(key, value)| {
            let read = if *value == json!(0) {
                json!(false)
            } else {
                value.clone()
            };
            (key.clone(), read)
        })
        .collect();
    json!({
        "user": "rs_blog1",
        "version": "7.9.3",
        "active_before": false,
        "activated": "ok",
        "active": true,
        "settings": settings,
        "plugin_view": view,
        "lock_on": true,
        "locked": 35,
        "sessions": 0,
    })
}

#[test]
fn the_opt_in_report_must_show_the_active_pinned_plugin_and_settings() {
    assert!(opt_in_report_matches(&report(), "rs_blog1", V1));
    assert!(!opt_in_report_matches(&report(), "rs_blog2", V1));
    for (pointer, value) in [
        ("/version", json!("7.9.4")),
        ("/active_before", json!(true)),
        ("/activated", json!("error")),
        ("/active", json!(false)),
        ("/sessions", json!(1)),
        ("/settings/cache", json!("1")),
        ("/settings/cache-priv", json!("")),
        ("/plugin_view/cache", json!(1)),
        ("/plugin_view/esi", json!(null)),
        ("/plugin_view/guest", json!(true)),
        ("/settings/cache-exc_qs", json!(["unapproved"])),
        ("/settings/cache-exc_qs", json!("unapproved")),
        ("/plugin_view/cache-exc_qs", json!([])),
        ("/plugin_view/cache-force_pub_uri", json!(["/"])),
        ("/settings/cache-login_cookie", json!("x")),
        ("/plugin_view/cache-login_cookie", json!(null)),
        ("/lock_on", json!(false)),
        ("/locked", json!(34)),
    ] {
        let mut changed = report();
        *changed.pointer_mut(pointer).unwrap() = value.clone();
        assert!(
            !opt_in_report_matches(&changed, "rs_blog1", V1),
            "{pointer} {value}"
        );
    }
    let mut zero = report();
    zero["plugin_view"]["cache"] = json!(0);
    assert!(
        opt_in_report_matches(&zero, "rs_blog1", V1),
        "an int option off"
    );
    let mut extra = report();
    extra["settings"]["optm-qs_rm"] = json!("0");
    assert!(
        !opt_in_report_matches(&extra, "rs_blog1", V1),
        "unlisted key"
    );
    let mut missing = report();
    missing["settings"].as_object_mut().unwrap().remove("esi");
    assert!(
        !opt_in_report_matches(&missing, "rs_blog1", V1),
        "missing key"
    );
}

#[test]
fn an_anonymous_response_must_be_a_page_with_no_cache_hit_or_public_mark() {
    let ok =
        "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nX-LiteSpeed-Cache-Control: no-cache\r\n";
    assert!(anonymous_uncached(200, ok));
    assert!(anonymous_uncached(
        200,
        "HTTP/1.0 200 OK\r\nServer: LiteSpeed\r\n"
    ));
    assert!(!anonymous_uncached(302, ok), "not the page");
    for headers in [
        "HTTP/1.0 200 OK\r\nX-LiteSpeed-Cache: hit\r\n",
        "HTTP/1.0 200 OK\r\nx-litespeed-cache: HIT,private\r\n",
        "HTTP/1.0 200 OK\r\nX-LiteSpeed-Cache-Control: public,max-age=604800\r\n",
        "HTTP/1.0 200 OK\r\nX-Litespeed-Cache: miss\r\n",
    ] {
        assert!(!anonymous_uncached(200, headers), "{headers}");
    }
}

#[test]
fn the_opt_in_and_deactivate_scripts_run_fixed_steps_only() {
    for script in [OPT_IN_SCRIPT, DEACTIVATE_SCRIPT] {
        for forbidden in [
            "$_GET",
            "$_POST",
            "$argv",
            "shell_exec",
            "exec(",
            "system(",
            "eval(",
        ] {
            assert!(!script.contains(forbidden), "{forbidden}");
        }
        assert!(script.contains("litespeed-cache/litespeed-cache.php"));
    }
    assert!(OPT_IN_SCRIPT.contains("WP_Session_Tokens::destroy_all_for_all_users()"));
    let seeded = OPT_IN_SCRIPT.find("update_option(").unwrap();
    let activated = OPT_IN_SCRIPT.find("activate_plugin(").unwrap();
    assert!(
        seeded < activated,
        "the fixed settings are stored before the plugin first runs"
    );
    assert!(DEACTIVATE_SCRIPT.contains("deactivate_plugins("));
    // W368 VM run 1: with read-only code WordPress picks the FTP filesystem
    // and the plugin's activation dies in ftp_nlist(null). Both scripts pin
    // the direct method before WordPress loads.
    for script in [OPT_IN_SCRIPT, DEACTIVATE_SCRIPT] {
        let pinned = script.find("define('FS_METHOD', 'direct');").unwrap();
        assert!(pinned < script.find("wp-load.php").unwrap());
    }
    // W370: settings are stored as their JSON values (lists stay lists), and
    // the report says whether the lock file's constants are in force.
    assert!(!OPT_IN_SCRIPT.contains("(int) $value"));
    assert!(OPT_IN_SCRIPT.contains("'lock_on'"));
    assert!(OPT_IN_SCRIPT.contains("'locked'"));
}

/// W370: the purge runs as the server's own account with no capability, no
/// network and only the site's storage folder writable, and deletes inside
/// that folder only. GNU find with `-P` never follows a link, `-xdev` stays
/// on one file system, and `-mindepth 1` keeps the folder itself.
#[test]
fn the_purge_job_writes_only_the_site_storage_as_the_server_account() {
    let store = crate::ols::cache_storage("rs_blog1");
    assert_eq!(store, "/usr/local/lsws/cachedata/rs_blog1");
    let args = purge_args(&store);
    let properties: Vec<&str> = args
        .windows(2)
        .filter(|pair| pair[0] == "--property")
        .map(|pair| pair[1].as_str())
        .collect();
    assert_eq!(
        properties,
        [
            "User=nobody",
            "Group=nobody",
            "ReadWritePaths=/usr/local/lsws/cachedata/rs_blog1",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "PrivateDevices=yes",
            "PrivateNetwork=yes",
            "RuntimeMaxSec=120",
        ]
    );
    let command: Vec<&str> = args
        .iter()
        .skip_while(|arg| *arg != "--")
        .map(String::as_str)
        .collect();
    assert_eq!(
        command,
        [
            "--",
            "/usr/bin/find",
            "-P",
            "/usr/local/lsws/cachedata/rs_blog1",
            "-xdev",
            "-mindepth",
            "1",
            "-delete",
        ]
    );
    assert_eq!(&args[..3], ["--wait", "--quiet", "--collect"]);
}

/// W370: what the opt-in finds at the plugin folder. Absent: unpack. A real
/// folder: re-enable, which the census and the per-file digests must then
/// accept. Anything else is refused.
#[test]
fn the_plugin_folder_is_absent_a_real_folder_or_refused() {
    let root = tree(&[("keep.txt", b"k")]);
    let uid = rustix::process::getuid().as_raw();
    let dir = crate::files::open_traversable_directory(&root.0, uid).unwrap();
    assert_eq!(plugin_folder(&dir), Ok(false), "absent");
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(root.0.join("litespeed-cache"))
        .unwrap();
    assert_eq!(plugin_folder(&dir), Ok(true), "a real folder");
    std::fs::remove_dir(root.0.join("litespeed-cache")).unwrap();
    symlink(root.0.join("keep.txt"), root.0.join("litespeed-cache")).unwrap();
    assert_eq!(plugin_folder(&dir), Err(ExecutorError::Collision), "a link");
    std::fs::remove_file(root.0.join("litespeed-cache")).unwrap();
    std::fs::write(root.0.join("litespeed-cache"), b"x").unwrap();
    assert_eq!(plugin_folder(&dir), Err(ExecutorError::Collision), "a file");
}

/// W370: the storage count walks below the folder without following a link
/// and the emptiness check sees any entry.
#[test]
fn the_storage_count_and_emptiness_check_see_every_entry() {
    let root = tree(&[("a/b/c1", b"1"), ("a/b/c2", b"2"), (".cacheman.shm", b"s")]);
    symlink("/etc", root.0.join("link")).unwrap();
    let uid = rustix::process::getuid().as_raw();
    let dir = crate::files::open_traversable_directory(&root.0, uid).unwrap();
    assert_eq!(count_entries(&dir, 0), Ok(6), "a, a/b, c1, c2, shm, link");
    assert_eq!(is_empty(&dir), Ok(false));
    let empty = tree(&[]);
    let dir = crate::files::open_traversable_directory(&empty.0, uid).unwrap();
    assert_eq!(is_empty(&dir), Ok(true));
    assert_eq!(count_entries(&dir, 0), Ok(0));
}

/// W395 (D-044): the cache-on recipe keeps every W370 setting and turns
/// only `cache` on. The pins were computed independently in Python
/// (`docs/validation/S10-W395/make-cache-on-vectors.py`).
#[test]
fn the_cache_on_recipe_changes_only_the_cache_setting() {
    assert_eq!(settings_json(V1), SETTINGS_JSON);
    let on: serde_json::Value = serde_json::from_str(settings_json(ON)).unwrap();
    let off: serde_json::Value = serde_json::from_str(SETTINGS_JSON).unwrap();
    let (on, off) = (on.as_object().unwrap(), off.as_object().unwrap());
    assert_eq!(
        on.keys().collect::<Vec<_>>(),
        off.keys().collect::<Vec<_>>(),
        "same keys, same order"
    );
    for (key, value) in off {
        if key == "cache" {
            assert_eq!(on[key], json!(1));
        } else {
            assert_eq!(&on[key], value, "{key}");
        }
    }
    assert_eq!(
        hex(settings_json(ON).as_bytes()),
        "fec9698019115ae148051642af24ca9f26b0e9d70703e7d1aee1a90c28ab30f7"
    );
    assert_eq!(settings_sha256(ON), hex(settings_json(ON).as_bytes()));
    assert_eq!(settings_sha256(V1), SETTINGS_SHA256);
}

#[test]
fn the_cache_on_lock_differs_from_the_w370_lock_in_the_recipe_and_cache_lines() {
    let (on, off) = (lock_file(ON), lock_file(V1));
    assert_eq!(
        hex(off.as_bytes()),
        LOCK_SHA256,
        "the W370 lock is unchanged"
    );
    assert_eq!(
        hex(on.as_bytes()),
        "6a299e0b2e178b1cd861e7759afd1467bf85762762f149bfbfac631bb490045d"
    );
    assert_eq!(lock_sha256(ON), hex(on.as_bytes()));
    assert_eq!(lock_sha256(V1), LOCK_SHA256);
    let changed: Vec<(&str, &str)> = on
        .lines()
        .zip(off.lines())
        .filter(|(a, b)| a != b)
        .collect();
    assert_eq!(on.lines().count(), off.lines().count());
    assert_eq!(
        changed,
        [
            (
                "// Rustiron page-cache recipe litespeed_cache_793_cache_on_v1: the fixed LiteSpeed",
                "// Rustiron page-cache recipe litespeed_cache_793_v1: the fixed LiteSpeed"
            ),
            (
                "define('LITESPEED_CONF__CACHE', 1);",
                "define('LITESPEED_CONF__CACHE', 0);"
            ),
        ]
    );
}

/// The plan's `recipe_digest` for the cache-on recipe is the SHA-256 of a
/// fixed manifest that names every pin, so the signed plan binds the
/// settings and the lock as well as the plugin.
#[test]
fn the_cache_on_recipe_digest_binds_the_plugin_settings_and_lock() {
    assert_eq!(
        recipe_manifest(ON),
        format!(
            "rustiron page-cache recipe litespeed_cache_793_cache_on_v1\n\
             plugin litespeed-cache 7.9.3\n\
             archive litespeed-cache-7.9.3.tar {TAR_SHA256}\n\
             checksums litespeed-cache-7.9.3.checksums.json {CHECKSUMS_SHA256}\n\
             settings fec9698019115ae148051642af24ca9f26b0e9d70703e7d1aee1a90c28ab30f7\n\
             lock 6a299e0b2e178b1cd861e7759afd1467bf85762762f149bfbfac631bb490045d\n"
        )
    );
    assert_eq!(
        recipe_digest(ON).as_str(),
        "3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767"
    );
    assert_eq!(
        recipe_digest(ON).as_str(),
        hex(recipe_manifest(ON).as_bytes())
    );
    assert_eq!(recipe_digest(V1).as_str(), TAR_SHA256, "W368 meaning kept");
    assert_eq!(recipe_name(V1), "litespeed_cache_793_v1");
    assert_eq!(recipe_name(ON), "litespeed_cache_793_cache_on_v1");
    for recipe in [V1, ON] {
        assert_eq!(recipe_from_name(recipe_name(recipe)), Some(recipe));
        assert_eq!(
            serde_json::to_value(recipe).unwrap(),
            json!(recipe_name(recipe))
        );
    }
    assert_eq!(recipe_from_name("litespeed_cache_latest"), None);
}

fn report_with_cache_on() -> serde_json::Value {
    let mut value = report();
    value["settings"]["cache"] = json!("1");
    value["plugin_view"]["cache"] = json!(true);
    value
}

#[test]
fn the_cache_on_report_must_show_the_page_cache_on_and_everything_else_fixed() {
    let on = report_with_cache_on();
    assert!(opt_in_report_matches(&on, "rs_blog1", ON));
    assert!(!opt_in_report_matches(&on, "rs_blog1", V1));
    assert!(
        !opt_in_report_matches(&report(), "rs_blog1", ON),
        "cache off"
    );
    let mut int = on.clone();
    int["plugin_view"]["cache"] = json!(1);
    assert!(
        opt_in_report_matches(&int, "rs_blog1", ON),
        "an int option on"
    );
    for (pointer, value) in [
        ("/settings/cache", json!("0")),
        ("/settings/cache", json!(1)),
        ("/plugin_view/cache", json!(false)),
        ("/plugin_view/cache", json!(2)),
        ("/plugin_view/cache-priv", json!(true)),
        ("/settings/esi", json!("1")),
        ("/settings/cache-exc_qs", json!([])),
        ("/locked", json!(34)),
        ("/lock_on", json!(false)),
        ("/sessions", json!(1)),
    ] {
        let mut changed = on.clone();
        *changed.pointer_mut(pointer).unwrap() = value.clone();
        assert!(
            !opt_in_report_matches(&changed, "rs_blog1", ON),
            "{pointer} {value}"
        );
    }
}

/// After a cache-on opt-in, the first anonymous `GET /` is stored (or
/// already stored) and the second one is a public hit.
#[test]
fn a_cache_on_check_needs_a_public_store_and_then_a_public_hit() {
    let miss = "HTTP/1.1 200 OK\r\nX-LiteSpeed-Cache-Control: public,max-age=604800\r\nX-LiteSpeed-Cache: miss\r\n";
    let hit = "HTTP/1.1 200 OK\r\nx-litespeed-cache: hit\r\n";
    assert!(anonymous_cached((200, miss), (200, hit)));
    assert!(anonymous_cached((200, hit), (200, hit)));
    assert!(!anonymous_cached((200, miss), (200, miss)), "never served");
    assert!(!anonymous_cached((404, miss), (200, hit)), "not the page");
    assert!(!anonymous_cached((200, miss), (302, hit)), "not the page");
    let none = "HTTP/1.1 200 OK\r\nX-LiteSpeed-Cache-Control: no-cache\r\n";
    assert!(
        !anonymous_cached((200, none), (200, none)),
        "nothing stored"
    );
    let private = "HTTP/1.1 200 OK\r\nX-LiteSpeed-Cache: hit,private\r\n";
    assert!(
        !anonymous_cached((200, miss), (200, private)),
        "private hit"
    );
    assert!(
        !anonymous_cached(
            (200, miss),
            (
                200,
                "HTTP/1.1 200 OK\r\nX-LiteSpeed-Cache: hit\r\nX-LiteSpeed-Cache: miss\r\n"
            )
        ),
        "two cache headers"
    );
}

/// The helper replaces the lock file only when it holds the exact lock of
/// the other approved recipe; any other content is a collision.
#[test]
fn a_lock_is_replaced_only_from_the_other_recipe_lock() {
    assert_eq!(lock_state(lock_file(ON).as_bytes(), ON), LockState::Current);
    assert_eq!(lock_state(lock_file(V1).as_bytes(), ON), LockState::Replace);
    assert_eq!(lock_state(lock_file(ON).as_bytes(), V1), LockState::Replace);
    assert_eq!(lock_state(lock_file(V1).as_bytes(), V1), LockState::Current);
    let mut edited = lock_file(V1).into_bytes();
    edited.push(b'\n');
    assert_eq!(lock_state(&edited, ON), LockState::Foreign);
    assert_eq!(lock_state(b"", V1), LockState::Foreign);
    assert_eq!(
        lock_state(
            lock_file(V1)
                .replace("LITESPEED_CONF__CACHE', 0", "LITESPEED_CONF__CACHE', 1")
                .as_bytes(),
            ON
        ),
        LockState::Foreign,
        "the W370 root edit is not an approved lock"
    );
    assert_eq!(LOCK_STAGING, "rustiron-page-cache.php.new");
    assert!(!LOCK_STAGING.ends_with(".php"), "WordPress never loads it");
}
