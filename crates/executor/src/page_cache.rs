//! W368 (B08, D-028 item 2): the page-cache opt-in effect of a signed
//! `config_activate` v2 plan.
//!
//! After the activation has given the site its own cache storage and every
//! site answered, the effect installs the pinned LiteSpeed Cache plugin as
//! the site identity, with no network:
//!
//! 1. Read the pinned plugin archive and per-file checksum list from the
//!    root-owned recipe store ([`provision::read_pinned`]).
//! 2. Require that the site has no `litespeed-cache` plugin folder.
//! 3. List the archive: exactly the listed regular files, all under
//!    `litespeed-cache/`.
//! 4. Unpack it as the site account in `rustiron_unpack_t` at the site
//!    level, with write access to `wp-content/plugins` only.
//! 5. Check the tree: the census (owner, label, no link or special file)
//!    and the SHA-256 of every listed file.
//! 6. Run the fixed opt-in script with the site's own PHP: store the fixed
//!    settings, activate the plugin, end every login session.
//! 7. Check again: the tree, and two anonymous `GET /` with no cache hit and
//!    no public mark.
//!
//! The plan carries no file, command, option text or path. WP-CLI is not
//! used: it refuses the `litespeed` SAPI of `lsphp`, the only site PHP entry
//! point (W368 evidence). A failed check after activation deactivates the
//! plugin as the site; the plugin files are left in place.
//!
//! W370 adds:
//!
//! - list and text settings (`cache-exc_qs` for WordPress's pending-comment
//!   link, no forced public URI, the default login vary cookie);
//! - a fixed must-use file that locks every fixed setting with the plugin's
//!   `LITESPEED_CONF__*` constants, so the dashboard cannot change them;
//! - the re-enable path: a site that opted out keeps the pinned plugin tree,
//!   which the census and the per-file digests must accept again;
//! - [`remove`]: the opt-out and compensation step. It deactivates the
//!   plugin as the site and empties the site's own cache storage with a
//!   closed job that runs as the server account.
//!
//! W395 (D-044) adds the cache-on recipe `litespeed_cache_793_cache_on_v1`:
//! the same pinned plugin, the W370 settings with `cache` 1, and its own
//! lock file. Its plan `recipe_digest` is the SHA-256 of [`recipe_manifest`],
//! which names the four pins. After activation, an anonymous `GET /` must be
//! stored and then served as a public hit. The helper replaces the lock file
//! only when it holds the other recipe's exact lock.

use std::path::Path;

use rustiron_contracts::approval::{Hostname, PageCacheRecipe, Sha256Digest};
use rustix::fs::{self, AtFlags};
use sha2::{Digest, Sha256};

use crate::{ExecutorError, files, provision, provision::SiteLayout};

/// Recipe-store file: the deterministic ustar archive that
/// `packaging/page-cache-recipe.py` writes from the reviewed plugin zip.
pub(crate) const RECIPE_TAR: &str = "litespeed-cache-7.9.3.tar";
/// Recipe-store file: the WordPress.org per-file checksum list, unchanged.
pub(crate) const RECIPE_CHECKSUMS: &str = "litespeed-cache-7.9.3.checksums.json";
/// SHA-256 of [`RECIPE_TAR`], measured twice on the W368 VM.
pub(crate) const TAR_SHA256: &str =
    "0db968c7e9ae8a17023f2db3fef1134ba006e1e3f104c3fe715b7f46534e20a9";
/// SHA-256 of [`RECIPE_CHECKSUMS`] as WordPress.org served it on 2026-11-13.
pub(crate) const CHECKSUMS_SHA256: &str =
    "41dc8e796d55435e69abefd7274c075c694c2a7f451084095be9bfd38112d982";
const PLUGIN: &str = "litespeed-cache";
const VERSION: &str = "7.9.3";
/// Upper bound on listed files (7.9.3 has 321).
pub(crate) const MAX_FILES: usize = 2000;
const MAX_PATH: usize = 255;
const MAX_DEPTH: usize = 16;
// W528-F2: a listed file of a core update may reach 32 MiB (the recipe cap).
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Plugin options the opt-in stores before activation, every one `0`. Each
/// key exists in `data/const.default.json` or `src/base.cls.php` of 7.9.3.
/// `cache` stays 0 until the B08 acceptance passes (D-028). The lock file
/// fixes each one with a constant (W370).
pub(crate) const SETTINGS: [&str; 31] = [
    "cache",
    "cache-priv",
    "cache-commenter",
    "cache-rest",
    "cache-page_login",
    "cache-mobile",
    "esi",
    "guest",
    "guest_optm",
    "object",
    "crawler",
    "auto_upgrade",
    "news",
    "cdn",
    "cdn-quic",
    "img_optm-auto",
    "media-lazy",
    "media-lqip",
    "media-vpi",
    "media-placeholder_resp",
    "optm-css_min",
    "optm-css_comb",
    "optm-js_min",
    "optm-js_comb",
    "optm-html_min",
    "optm-ucss",
    "optm-css_async",
    "optm-localize",
    "optm-ggfonts_async",
    "discuss-avatar_cache",
    "debug",
];
/// W370: list options, stored and locked with these exact items.
/// `cache-exc_qs`: the plugin sends `no-cache` for any request with one of
/// these query keys. WordPress sends a commenter to
/// `?unapproved=ID&moderation-hash=H`, a page that shows the pending
/// comment and the commenter's name (W368 A8, A9). The forced URI lists stay
/// empty, so no URI is ever forced cacheable or public.
pub(crate) const LIST_SETTINGS: [(&str, &[&str]); 3] = [
    ("cache-exc_qs", &["unapproved", "moderation-hash"]),
    ("cache-force_uri", &[]),
    ("cache-force_pub_uri", &[]),
];
/// W370: text options, stored and locked. An empty `cache-login_cookie`
/// keeps the login vary cookie `_lscache_vary`, the one name OLS adds to the
/// public cache key.
pub(crate) const TEXT_SETTINGS: [(&str, &str); 1] = [("cache-login_cookie", "")];
/// The fixed settings file, exactly these bytes: [`SETTINGS`], then
/// [`LIST_SETTINGS`], then [`TEXT_SETTINGS`].
pub(crate) const SETTINGS_JSON: &str = r#"{"cache":0,"cache-priv":0,"cache-commenter":0,"cache-rest":0,"cache-page_login":0,"cache-mobile":0,"esi":0,"guest":0,"guest_optm":0,"object":0,"crawler":0,"auto_upgrade":0,"news":0,"cdn":0,"cdn-quic":0,"img_optm-auto":0,"media-lazy":0,"media-lqip":0,"media-vpi":0,"media-placeholder_resp":0,"optm-css_min":0,"optm-css_comb":0,"optm-js_min":0,"optm-js_comb":0,"optm-html_min":0,"optm-ucss":0,"optm-css_async":0,"optm-localize":0,"optm-ggfonts_async":0,"discuss-avatar_cache":0,"debug":0,"cache-exc_qs":["unapproved","moderation-hash"],"cache-force_uri":[],"cache-force_pub_uri":[],"cache-login_cookie":""}"#;
/// SHA-256 of [`SETTINGS_JSON`] (W370; W368 pinned `8909e131…2f9a` for the
/// 31 zero keys alone).
pub(crate) const SETTINGS_SHA256: &str =
    "228da3f62ee49332fd316cac3bae14e599268eda8681bef87b1e51f5401b8343";
/// W370: the must-use file that locks the fixed settings, relative to the
/// site's `html` folder.
pub(crate) const LOCK_DIR: &str = "wp-content/mu-plugins";
/// File name of the lock in [`LOCK_DIR`].
pub(crate) const LOCK_FILE: &str = "rustiron-page-cache.php";
/// SHA-256 of [`lock_file`].
pub(crate) const LOCK_SHA256: &str =
    "f19e073b78a4586f368055327139de9c4b85e0c6ba57bb54196f59715c22b723";
/// The OLS server account (the reviewed parent's `user`); the purge job runs
/// as it.
const OLS_USER: &str = "nobody";
pub(crate) const OPT_IN_SCRIPT: &str = include_str!("page_cache_assets/opt-in.php");
pub(crate) const DEACTIVATE_SCRIPT: &str = include_str!("page_cache_assets/deactivate.php");
/// Name of the verified archive copy placed in the site's tmp for the job.
const UNPACK_INPUT: &str = "page-cache-unpack.tar";

/// W395: the fixed settings of the cache-on recipe: [`SETTINGS_JSON`] with
/// `cache` 1 and every other key unchanged.
pub(crate) const CACHE_ON_SETTINGS_JSON: &str = r#"{"cache":1,"cache-priv":0,"cache-commenter":0,"cache-rest":0,"cache-page_login":0,"cache-mobile":0,"esi":0,"guest":0,"guest_optm":0,"object":0,"crawler":0,"auto_upgrade":0,"news":0,"cdn":0,"cdn-quic":0,"img_optm-auto":0,"media-lazy":0,"media-lqip":0,"media-vpi":0,"media-placeholder_resp":0,"optm-css_min":0,"optm-css_comb":0,"optm-js_min":0,"optm-js_comb":0,"optm-html_min":0,"optm-ucss":0,"optm-css_async":0,"optm-localize":0,"optm-ggfonts_async":0,"discuss-avatar_cache":0,"debug":0,"cache-exc_qs":["unapproved","moderation-hash"],"cache-force_uri":[],"cache-force_pub_uri":[],"cache-login_cookie":""}"#;
/// SHA-256 of [`CACHE_ON_SETTINGS_JSON`] (W395).
pub(crate) const CACHE_ON_SETTINGS_SHA256: &str =
    "fec9698019115ae148051642af24ca9f26b0e9d70703e7d1aee1a90c28ab30f7";
/// SHA-256 of the cache-on [`lock_file`] (W395).
pub(crate) const CACHE_ON_LOCK_SHA256: &str =
    "6a299e0b2e178b1cd861e7759afd1467bf85762762f149bfbfac631bb490045d";
/// W395: the name a lock replacement is written under before it is renamed
/// over [`LOCK_FILE`]. WordPress loads only `*.php` must-use files.
pub(crate) const LOCK_STAGING: &str = "rustiron-page-cache.php.new";

/// Journal and plan name of an approved recipe.
pub(crate) fn recipe_name(recipe: PageCacheRecipe) -> &'static str {
    match recipe {
        PageCacheRecipe::LitespeedCache793V1 => "litespeed_cache_793_v1",
        PageCacheRecipe::LitespeedCache793CacheOnV1 => "litespeed_cache_793_cache_on_v1",
    }
}

/// Inverse of [`recipe_name`]; anything else is not an approved recipe.
pub(crate) fn recipe_from_name(name: &str) -> Option<PageCacheRecipe> {
    [
        PageCacheRecipe::LitespeedCache793V1,
        PageCacheRecipe::LitespeedCache793CacheOnV1,
    ]
    .into_iter()
    .find(|recipe| recipe_name(*recipe) == name)
}

/// The fixed settings file of a recipe.
pub(crate) fn settings_json(recipe: PageCacheRecipe) -> &'static str {
    match recipe {
        PageCacheRecipe::LitespeedCache793V1 => SETTINGS_JSON,
        PageCacheRecipe::LitespeedCache793CacheOnV1 => CACHE_ON_SETTINGS_JSON,
    }
}

/// The pinned SHA-256 of a recipe's settings file.
pub(crate) fn settings_sha256(recipe: PageCacheRecipe) -> &'static str {
    match recipe {
        PageCacheRecipe::LitespeedCache793V1 => SETTINGS_SHA256,
        PageCacheRecipe::LitespeedCache793CacheOnV1 => CACHE_ON_SETTINGS_SHA256,
    }
}

/// The pinned SHA-256 of a recipe's lock file.
pub(crate) fn lock_sha256(recipe: PageCacheRecipe) -> &'static str {
    match recipe {
        PageCacheRecipe::LitespeedCache793V1 => LOCK_SHA256,
        PageCacheRecipe::LitespeedCache793CacheOnV1 => CACHE_ON_LOCK_SHA256,
    }
}

/// W395: the fixed text that names every pin of a recipe. The plan digest of
/// the cache-on recipe is its SHA-256; the W368 recipe keeps the archive
/// digest as its plan digest.
pub(crate) fn recipe_manifest(recipe: PageCacheRecipe) -> String {
    format!(
        "rustiron page-cache recipe {}\n\
         plugin {PLUGIN} {VERSION}\n\
         archive {RECIPE_TAR} {TAR_SHA256}\n\
         checksums {RECIPE_CHECKSUMS} {CHECKSUMS_SHA256}\n\
         settings {}\n\
         lock {}\n",
        recipe_name(recipe),
        settings_sha256(recipe),
        lock_sha256(recipe)
    )
}

/// The artifact digest the executor pins for an approved recipe: the W368
/// archive digest, or (W395) the SHA-256 of the cache-on manifest.
pub(crate) fn recipe_digest(recipe: PageCacheRecipe) -> Sha256Digest {
    let pin = match recipe {
        PageCacheRecipe::LitespeedCache793V1 => TAR_SHA256.to_owned(),
        PageCacheRecipe::LitespeedCache793CacheOnV1 => hex(recipe_manifest(recipe).as_bytes()),
    };
    Sha256Digest::try_from(pin).unwrap_or_else(|_| unreachable!())
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn failed(what: &'static str) -> ExecutorError {
    eprintln!("{{\"scope\":\"page_cache\",\"step_failure\":\"{what}\"}}");
    ExecutorError::StepFailed
}

/// A relative path of `[A-Za-z0-9._-]` components, never `.` or `..`.
fn safe_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    !path.is_empty()
        && path.len() <= MAX_PATH
        && parts.len() <= MAX_DEPTH
        && parts.iter().all(|part| {
            !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

/// Decodes the WordPress.org checksum list of the pinned plugin version into
/// sorted `(path, sha256)` pairs. Only `plugin`, `version`, `source`, `zip`
/// and `files` are allowed; every digest is one lowercase SHA-256 string.
pub(crate) fn parse_checksums(bytes: &[u8]) -> Result<Vec<(String, String)>, ExecutorError> {
    let bad = || failed("checksum list");
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
    let top = value.as_object().ok_or_else(bad)?;
    let allowed = ["plugin", "version", "source", "zip", "files"];
    if top.keys().any(|key| !allowed.contains(&key.as_str()))
        || top.get("plugin").and_then(|v| v.as_str()) != Some(PLUGIN)
        || top.get("version").and_then(|v| v.as_str()) != Some(VERSION)
        || ["source", "zip"]
            .iter()
            .any(|key| top.get(*key).is_some_and(|v| !v.is_string()))
    {
        return Err(bad());
    }
    let files = top
        .get("files")
        .and_then(|v| v.as_object())
        .ok_or_else(bad)?;
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(bad());
    }
    let mut listed = Vec::with_capacity(files.len());
    for (path, sums) in files {
        let digest = sums
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(bad)?;
        if !safe_path(path)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(bad());
        }
        listed.push((path.clone(), digest.to_owned()));
    }
    listed.sort();
    Ok(listed)
}

/// `systemd-run` arguments for the plugin unpack job: the existing unpack
/// confinement (site account, its MCS level in `rustiron_unpack_t`, no
/// network, no capabilities), writable `wp-content/plugins` only, and GNU tar
/// on the uncompressed archive. `--keep-old-files` refuses any overwrite.
pub(crate) fn unpack_args(account: &str, level: &str, plugins: &str, source: &str) -> Vec<String> {
    let mut args = provision::unpack_properties(account, level, plugins);
    args.extend(["--", "/usr/bin/tar", "--extract"].map(String::from));
    args.push(format!("--file={source}"));
    args.push(format!("--directory={plugins}"));
    args.extend(
        [
            "--no-same-owner",
            "--numeric-owner",
            "--no-same-permissions",
            "--keep-old-files",
        ]
        .map(String::from),
    );
    args
}

/// The archive listing holds exactly `count` regular files, all under
/// `litespeed-cache/`, and nothing else.
pub(crate) fn listing_matches(names: &str, verbose: &str, count: usize) -> bool {
    let names: Vec<&str> = names.lines().collect();
    let kinds: Vec<&str> = verbose.lines().collect();
    count > 0
        && names.len() == count
        && kinds.len() == count
        && names
            .iter()
            .all(|name| name.strip_prefix("litespeed-cache/").is_some_and(safe_path))
        && kinds.iter().all(|line| line.starts_with('-'))
}

/// Every listed file, reached one component at a time with no link
/// followed, is a single-link regular file of the site with the listed
/// SHA-256. The census proves there is no other file.
pub(crate) fn verify_listed(
    plugin: &rustix::fd::OwnedFd,
    uid: u32,
    listed: &[(String, String)],
) -> Result<(), ExecutorError> {
    for (path, want) in listed {
        let mut parts: Vec<&str> = path.split('/').collect();
        let name = parts.pop().ok_or_else(|| failed("plugin file path"))?;
        let mut directory = None;
        for part in parts {
            let parent = directory.as_ref().unwrap_or(plugin);
            directory = Some(
                files::open_child_directory(parent, part, uid)
                    .map_err(|_| failed("plugin folder"))?,
            );
        }
        let parent = directory.as_ref().unwrap_or(plugin);
        let bytes = files::read_child(parent, name, uid, files::Exposure::Readable, MAX_FILE_BYTES)
            .map_err(|_| failed("plugin file"))?;
        if &hex(&bytes) != want {
            return Err(failed("plugin file digest"));
        }
    }
    Ok(())
}

/// The opt-in report shows the site's own account, the pinned version
/// newly activated, every fixed setting of `recipe` stored and read by the
/// plugin with its fixed value (a zero key as `"0"` and off; W395: the
/// cache-on key as `"1"` and on), every one locked by its constant (W370),
/// and no login session left.
pub(crate) fn opt_in_report_matches(
    value: &serde_json::Value,
    account: &str,
    recipe: PageCacheRecipe,
) -> bool {
    let Ok(serde_json::Value::Object(fixed)) = serde_json::from_str(settings_json(recipe)) else {
        return false;
    };
    let exact = |member: &str, want: fn(&serde_json::Value, &serde_json::Value) -> bool| {
        value[member].as_object().is_some_and(|map| {
            map.len() == fixed.len()
                && fixed
                    .iter()
                    .all(|(key, fixed)| map.get(key).is_some_and(|got| want(fixed, got)))
        })
    };
    value["user"] == account
        && value["version"] == VERSION
        && value["active_before"] == false
        && value["activated"] == "ok"
        && value["active"] == true
        && value["sessions"] == 0
        && value["lock_on"] == true
        && value["locked"] == fixed.len()
        && exact("settings", |fixed, got| match fixed.as_u64() {
            Some(number) => got.as_str() == Some(number.to_string().as_str()),
            None => got == fixed,
        })
        && exact("plugin_view", |fixed, got| match fixed.as_u64() {
            Some(0) => *got == false || *got == 0,
            Some(1) => *got == true || *got == 1,
            Some(_) => false,
            None => got == fixed,
        })
}

/// The plugin constant that fixes option `key` (`Base::conf_const` in 7.9.3).
pub(crate) fn const_name(key: &str) -> String {
    format!(
        "LITESPEED_CONF__{}",
        key.replace('-', "__").to_ascii_uppercase()
    )
}

/// W370: the fixed must-use file. WordPress loads it before the plugin; the
/// plugin then reads each `LITESPEED_CONF__*` constant over the stored
/// option of the same key, and its settings screens show the value as set by
/// a constant. The file is root-written, site-owned and read-only to the
/// site PHP like the rest of the code. W395: the cache-on recipe names
/// itself in the header and sets `LITESPEED_CONF__CACHE` to 1.
pub(crate) fn lock_file(recipe: PageCacheRecipe) -> String {
    let mut text = format!(
        "<?php\n\
         // Rustiron page-cache recipe {}: the fixed LiteSpeed\n\
         // Cache settings, locked. The plugin reads these constants over its\n\
         // stored options. Written by the Rustiron administration helper.\n\
         defined('ABSPATH') || exit;\n\
         define('LITESPEED_CONF', true);\n",
        recipe_name(recipe)
    );
    let cache_on = recipe == PageCacheRecipe::LitespeedCache793CacheOnV1;
    for key in SETTINGS {
        let value = u8::from(cache_on && key == "cache");
        text.push_str(&format!("define('{}', {value});\n", const_name(key)));
    }
    for (key, items) in LIST_SETTINGS {
        let items: Vec<String> = items.iter().map(|item| format!("'{item}'")).collect();
        text.push_str(&format!(
            "define('{}', [{}]);\n",
            const_name(key),
            items.join(", ")
        ));
    }
    for (key, value) in TEXT_SETTINGS {
        text.push_str(&format!("define('{}', '{value}');\n", const_name(key)));
    }
    text
}

/// An anonymous `GET /` answered with the page (200), with no
/// `X-LiteSpeed-Cache` header at all (no hit and no miss: nothing was
/// looked up or stored for it) and no public `X-LiteSpeed-Cache-Control`.
pub(crate) fn anonymous_uncached(status: u16, headers: &str) -> bool {
    status == 200
        && headers.lines().all(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.starts_with("x-litespeed-cache:")
                && !(lower.starts_with("x-litespeed-cache-control:") && lower.contains("public"))
        })
}

/// The value of the one `X-LiteSpeed-Cache` header, lowercase and trimmed;
/// `None` when there is none or more than one.
fn cache_state(headers: &str) -> Option<String> {
    let mut values = headers.lines().filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("x-litespeed-cache")
            .then(|| value.trim().to_ascii_lowercase())
    });
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

/// W395: after a cache-on opt-in, the first anonymous `GET /` answers the
/// page and is stored (`miss`, or `hit` when already stored), and the
/// second is served from the public cache (`hit`, not `hit,private`).
pub(crate) fn anonymous_cached(first: (u16, &str), second: (u16, &str)) -> bool {
    first.0 == 200
        && second.0 == 200
        && matches!(cache_state(first.1).as_deref(), Some("miss" | "hit"))
        && cache_state(second.1).as_deref() == Some("hit")
}

/// W395: what the lock file in place is to `recipe`.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LockState {
    /// The exact lock of `recipe`.
    Current,
    /// The exact lock of the other approved recipe; the helper replaces it.
    Replace,
    /// Anything else; refused.
    Foreign,
}

/// Classifies the bytes found at the lock file for `recipe`.
pub(crate) fn lock_state(found: &[u8], recipe: PageCacheRecipe) -> LockState {
    let other = match recipe {
        PageCacheRecipe::LitespeedCache793V1 => PageCacheRecipe::LitespeedCache793CacheOnV1,
        PageCacheRecipe::LitespeedCache793CacheOnV1 => PageCacheRecipe::LitespeedCache793V1,
    };
    if found == lock_file(recipe).as_bytes() {
        LockState::Current
    } else if found == lock_file(other).as_bytes() {
        LockState::Replace
    } else {
        LockState::Foreign
    }
}

/// The effect for one site; see the module comment. Every target derives
/// from the site layout, `recipe` (from the journal) and the compiled pins.
pub(crate) fn install(
    layout: &SiteLayout,
    recipes: &Path,
    address: &str,
    hostname: &Hostname,
    recipe: PageCacheRecipe,
) -> Result<String, ExecutorError> {
    let tar_pin =
        Sha256Digest::try_from(TAR_SHA256.to_owned()).map_err(|_| ExecutorError::Unavailable)?;
    let list_pin = Sha256Digest::try_from(CHECKSUMS_SHA256.to_owned())
        .map_err(|_| ExecutorError::Unavailable)?;
    let archive = provision::read_pinned(recipes, RECIPE_TAR, &tar_pin)?;
    let listed = parse_checksums(&provision::read_pinned(
        recipes,
        RECIPE_CHECKSUMS,
        &list_pin,
    )?)?;
    let account = &layout.account;
    let uid = provision::account_uid(&provision::read_etc("passwd")?, account)
        .ok_or(ExecutorError::StepFailed)?;
    let plugins = layout.root.join("html/wp-content/plugins");
    let plugins_str = plugins.to_str().ok_or(ExecutorError::StepFailed)?;
    let plugins_dir = files::open_traversable_directory(&plugins, uid)?;
    let level = crate::capture::site_level(layout)?;
    // W370: a site that opted out keeps the pinned tree; re-enabling checks
    // it below exactly as a fresh unpack.
    let reused = plugin_folder(&plugins_dir)?;
    if !reused {
        let names = provision::spawn(
            "/usr/bin/tar",
            &["--list", "--file=-"],
            true,
            Some(&archive),
        )?;
        let verbose = provision::spawn(
            "/usr/bin/tar",
            &["--list", "--verbose", "--file=-"],
            true,
            Some(&archive),
        )?;
        if !listing_matches(&names, &verbose, listed.len()) {
            return Err(failed("archive listing"));
        }
        provision::run_unpack_job(layout, uid, &archive, UNPACK_INPUT, |source| {
            unpack_args(account, &level, plugins_str, source)
        })?;
    }
    let plugin_dir = files::open_traversable_directory(&plugins.join(PLUGIN), uid)?;
    let want = format!("system_u:object_r:httpd_sys_content_t:{level}");
    let census = crate::census::census_labelled(
        &plugin_dir,
        uid,
        want.as_bytes(),
        &crate::census::label_of,
        crate::census::BOUNDS,
    )?;
    if !provision::tree_matches(&census, listed.len()) {
        return Err(failed("plugin tree census"));
    }
    verify_listed(&plugin_dir, uid, &listed)?;
    let lock = write_lock(layout, uid, want.as_bytes(), recipe)?;
    let checked = provision::run_site_php(
        layout,
        "rustiron-page-cache",
        OPT_IN_SCRIPT,
        &[(
            "rustiron-page-cache.settings",
            settings_json(recipe).as_bytes(),
        )],
    )
    .and_then(|(report, _)| {
        if opt_in_report_matches(&report, account, recipe) {
            after_activation(&plugin_dir, uid, &listed, address, hostname, recipe)
                .and_then(|()| lock_unchanged(&lock, uid, recipe))
        } else {
            Err(failed("opt-in report"))
        }
    });
    if let Err(error) = checked {
        // Compensation within the step: never leave the plugin active after
        // a failed script or check. The files stay; nothing is deleted.
        let off = deactivate(layout);
        eprintln!(
            "{{\"scope\":\"page_cache\",\"deactivated\":{}}}",
            off.is_ok()
        );
        return Err(error);
    }
    Ok(format!(
        "page cache plugin {PLUGIN} {VERSION} recipe={} files={} reused={reused} settings={} lock={}",
        recipe_name(recipe),
        listed.len(),
        settings_sha256(recipe),
        lock_sha256(recipe)
    ))
}

/// Whether the plugin folder exists as a real directory (`true`: re-enable),
/// is absent (`false`: unpack), or is anything else (refused).
pub(crate) fn plugin_folder(plugins: &rustix::fd::OwnedFd) -> Result<bool, ExecutorError> {
    match fs::statat(plugins, PLUGIN, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Ok(stat) if fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::Directory => {
            Ok(true)
        }
        _ => Err(ExecutorError::Collision),
    }
}

/// W370: writes the lock file (or finds it with the exact bytes) in the
/// site's must-use folder, site-owned, read-only to the site PHP and in the
/// site label `want`. Returns the folder it is in. W395: a lock with the
/// exact bytes of the other approved recipe is replaced: the new lock is
/// written under [`LOCK_STAGING`], labelled, and renamed over it.
fn write_lock(
    layout: &SiteLayout,
    uid: u32,
    want: &[u8],
    recipe: PageCacheRecipe,
) -> Result<rustix::fd::OwnedFd, ExecutorError> {
    let content = files::open_traversable_directory(&layout.root.join("html/wp-content"), uid)?;
    let folder = layout.root.join("html").join(LOCK_DIR);
    let created = match fs::mkdirat(&content, "mu-plugins", fs::Mode::from_raw_mode(0o700)) {
        Ok(()) => true,
        Err(rustix::io::Errno::EXIST) => false,
        Err(_) => return Err(failed("lock folder")),
    };
    if created {
        let fd = fs::openat(
            &content,
            "mu-plugins",
            fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::NOFOLLOW | fs::OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .map_err(|_| failed("lock folder"))?;
        fs::fchown(
            &fd,
            Some(rustix::fs::Uid::from_raw(uid)),
            Some(rustix::fs::Gid::from_raw(uid)),
        )
        .and_then(|()| fs::fchmod(&fd, fs::Mode::from_raw_mode(0o755)))
        .map_err(|_| failed("lock folder"))?;
        provision::run(
            "/usr/sbin/restorecon",
            &["-F", "--", provision::path_str(&folder)?],
        )?;
    }
    let dir = files::open_child_directory(&content, "mu-plugins", uid)?;
    let bytes = lock_file(recipe);
    match files::read_child(&dir, LOCK_FILE, uid, files::Exposure::Readable, 64 * 1024) {
        Ok(found) => match lock_state(&found, recipe) {
            LockState::Current => {}
            LockState::Replace => replace_lock(&dir, &folder, bytes.as_bytes(), uid)?,
            LockState::Foreign => return Err(ExecutorError::Collision),
        },
        Err(_) => {
            provision::write_owned(&dir, LOCK_FILE, bytes.as_bytes(), uid, 0o644)?;
            provision::run(
                "/usr/sbin/restorecon",
                &["-F", "--", provision::path_str(&folder.join(LOCK_FILE))?],
            )?;
        }
    }
    let name = std::ffi::CString::new(LOCK_FILE).map_err(|_| failed("lock name"))?;
    if crate::census::label_of(&dir, &name).as_deref() != Some(want) {
        return Err(failed("lock label"));
    }
    lock_unchanged(&dir, uid, recipe)?;
    Ok(dir)
}

/// W395: writes `bytes` under [`LOCK_STAGING`] (a leftover regular file of
/// an interrupted replacement is removed first), labels it, and renames it
/// over [`LOCK_FILE`] in one step.
fn replace_lock(
    dir: &rustix::fd::OwnedFd,
    folder: &Path,
    bytes: &[u8],
    uid: u32,
) -> Result<(), ExecutorError> {
    match fs::statat(dir, LOCK_STAGING, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        Ok(stat) if fs::FileType::from_raw_mode(stat.st_mode) == fs::FileType::RegularFile => {
            fs::unlinkat(dir, LOCK_STAGING, AtFlags::empty())
                .map_err(|_| failed("lock staging"))?;
        }
        _ => return Err(ExecutorError::Collision),
    }
    provision::write_owned(dir, LOCK_STAGING, bytes, uid, 0o644)?;
    provision::run(
        "/usr/sbin/restorecon",
        &["-F", "--", provision::path_str(&folder.join(LOCK_STAGING))?],
    )?;
    fs::renameat(dir, LOCK_STAGING, dir, LOCK_FILE).map_err(|_| failed("lock rename"))?;
    eprintln!("{{\"scope\":\"page_cache\",\"lock\":\"replaced\"}}");
    Ok(())
}

/// The lock file still holds exactly the fixed bytes of `recipe`.
fn lock_unchanged(
    dir: &rustix::fd::OwnedFd,
    uid: u32,
    recipe: PageCacheRecipe,
) -> Result<(), ExecutorError> {
    let found = files::read_child(dir, LOCK_FILE, uid, files::Exposure::Readable, 64 * 1024)
        .map_err(|_| failed("lock file"))?;
    if found == lock_file(recipe).as_bytes() {
        Ok(())
    } else {
        Err(failed("lock file changed"))
    }
}

/// After activation: the tree still matches, and two anonymous requests get
/// the page with no cache header and no public mark. W395: for the cache-on
/// recipe, the first is stored and the second is a public hit.
fn after_activation(
    plugin_dir: &rustix::fd::OwnedFd,
    uid: u32,
    listed: &[(String, String)],
    address: &str,
    hostname: &Hostname,
    recipe: PageCacheRecipe,
) -> Result<(), ExecutorError> {
    verify_listed(plugin_dir, uid, listed)?;
    if recipe == PageCacheRecipe::LitespeedCache793CacheOnV1 {
        let (first, first_headers, _) = crate::ols::get_response(address, hostname.as_str(), "/")?;
        let (second, second_headers, _) =
            crate::ols::get_response(address, hostname.as_str(), "/")?;
        eprintln!(
            "{}",
            serde_json::json!({
                "scope": "page_cache",
                "cache_on_check": [cache_state(&first_headers), cache_state(&second_headers)],
            })
        );
        return if anonymous_cached((first, &first_headers), (second, &second_headers)) {
            Ok(())
        } else {
            Err(failed("anonymous response not cached"))
        };
    }
    for _ in 0..2 {
        let (status, headers, _) = crate::ols::get_response(address, hostname.as_str(), "/")?;
        if !anonymous_uncached(status, &headers) {
            return Err(failed("anonymous response cached or public"));
        }
    }
    Ok(())
}

/// W370: the opt-out and compensation step for one site. Deactivates the
/// plugin as the site (nothing to do when it is not installed), empties the
/// site's own cache storage, and requires two anonymous `GET /` with no
/// cache hit and no public mark. Every target derives from the site layout.
pub(crate) fn remove(
    layout: &SiteLayout,
    address: &str,
    hostname: &Hostname,
) -> Result<String, ExecutorError> {
    deactivate(layout)?;
    let removed = purge(&layout.account)?;
    for _ in 0..2 {
        let (status, headers, _) = crate::ols::get_response(address, hostname.as_str(), "/")?;
        if !anonymous_uncached(status, &headers) {
            return Err(failed("anonymous response cached or public after removal"));
        }
    }
    Ok(format!(
        "page cache off: plugin {PLUGIN} inactive, storage {} entries removed={removed}",
        crate::ols::cache_storage(&layout.account)
    ))
}

/// `systemd-run` arguments for the purge job: the server account, no
/// capability or network, only `store` writable; GNU find deletes every
/// entry below `store` without following a link or leaving the file system.
pub(crate) fn purge_args(store: &str) -> Vec<String> {
    let mut args: Vec<String> = ["--wait", "--quiet", "--collect"]
        .map(String::from)
        .to_vec();
    for property in [
        format!("User={OLS_USER}"),
        format!("Group={OLS_USER}"),
        format!("ReadWritePaths={store}"),
        "NoNewPrivileges=yes".into(),
        "CapabilityBoundingSet=".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=yes".into(),
        "PrivateTmp=yes".into(),
        "PrivateDevices=yes".into(),
        "PrivateNetwork=yes".into(),
        "RuntimeMaxSec=120".into(),
    ] {
        args.push("--property".into());
        args.push(property);
    }
    args.extend(
        [
            "--",
            "/usr/bin/find",
            "-P",
            store,
            "-xdev",
            "-mindepth",
            "1",
            "-delete",
        ]
        .map(String::from),
    );
    args
}

/// Empties the cache storage of `account` and returns how many entries
/// were below it. An absent storage folder has nothing to empty. Anything
/// but a real folder of the server account is refused.
fn purge(account: &str) -> Result<u64, ExecutorError> {
    let owner = provision::account_uid(&provision::read_etc("passwd")?, OLS_USER)
        .ok_or_else(|| failed("server account"))?;
    let root =
        files::open_traversable_directory(std::path::Path::new(crate::ols::CACHE_ROOT), owner)?;
    let Some(store) = storage_folder(&root, account, owner)? else {
        return Ok(0);
    };
    let before = count_entries(&store, 0)?;
    let path = crate::ols::cache_storage(account);
    let args = purge_args(&path);
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    provision::run("/usr/bin/systemd-run", &borrowed)?;
    let store = storage_folder(&root, account, owner)?.ok_or_else(|| failed("storage folder"))?;
    if !is_empty(&store)? {
        return Err(failed("storage not empty after purge"));
    }
    Ok(before)
}

/// The site's storage folder below the cache root: `None` when absent, a
/// real directory of the server account that others cannot write, or
/// refused.
fn storage_folder(
    root: &rustix::fd::OwnedFd,
    account: &str,
    owner: u32,
) -> Result<Option<rustix::fd::OwnedFd>, ExecutorError> {
    let fd = match fs::openat(
        root,
        account,
        fs::OFlags::RDONLY | fs::OFlags::DIRECTORY | fs::OFlags::NOFOLLOW | fs::OFlags::CLOEXEC,
        fs::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(failed("storage folder")),
    };
    let stat = fs::fstat(&fd).map_err(|_| failed("storage folder"))?;
    if stat.st_uid != owner || stat.st_mode & 0o002 != 0 {
        return Err(failed("storage folder owner"));
    }
    Ok(Some(fd))
}

/// Entries below `dir`, walked without following a link (bounded).
pub(crate) fn count_entries(dir: &rustix::fd::OwnedFd, depth: usize) -> Result<u64, ExecutorError> {
    const MAX_DEPTH_WALK: usize = 8;
    let mut count = 0;
    for entry in fs::Dir::read_from(dir).map_err(|_| failed("storage walk"))? {
        let entry = entry.map_err(|_| failed("storage walk"))?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        count += 1;
        let kind = match entry.file_type() {
            fs::FileType::Unknown => fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
                .map(|stat| fs::FileType::from_raw_mode(stat.st_mode))
                .map_err(|_| failed("storage walk"))?,
            kind => kind,
        };
        if kind == fs::FileType::Directory {
            if depth >= MAX_DEPTH_WALK {
                return Err(failed("storage too deep"));
            }
            let child = fs::openat(
                dir,
                name,
                fs::OFlags::RDONLY
                    | fs::OFlags::DIRECTORY
                    | fs::OFlags::NOFOLLOW
                    | fs::OFlags::CLOEXEC,
                fs::Mode::empty(),
            )
            .map_err(|_| failed("storage walk"))?;
            count += count_entries(&child, depth + 1)?;
        }
    }
    Ok(count)
}

/// Whether `dir` holds no entry.
pub(crate) fn is_empty(dir: &rustix::fd::OwnedFd) -> Result<bool, ExecutorError> {
    for entry in fs::Dir::read_from(dir).map_err(|_| failed("storage read"))? {
        let entry = entry.map_err(|_| failed("storage read"))?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The fixed deactivation as the site.
pub(crate) fn deactivate(layout: &SiteLayout) -> Result<(), ExecutorError> {
    let (report, _) =
        provision::run_site_php(layout, "rustiron-page-cache-off", DEACTIVATE_SCRIPT, &[])?;
    if report["user"] == layout.account.as_str() && report["active"] == false {
        Ok(())
    } else {
        Err(failed("deactivation report"))
    }
}

#[cfg(test)]
#[path = "page_cache_tests.rs"]
mod tests;
