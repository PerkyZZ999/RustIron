# Page cache with the LiteSpeed Cache plugin (B08)

Status: built, 2026-11-13. [W336](../validation/S10-W336/README.md) built the render change. [W368](../validation/S10-W368/README.md) built the opt-in effect. [W370](../validation/S10-W370/README.md) closed the W368 failures and ran the B08 acceptance again on a throwaway product VM. [W395](../validation/S10-W395/README.md) added the signed cache-on recipe ([D-044](../decisions/D-044-cache-on-recipe.md)) and passed A1 to A14 with no root edit.

This design applies [D-028](../decisions/D-028-delegated-b-row-choices.md) item 2.
**The B08 acceptance passed in W370** on one host with OLS 1.9.4 and LiteSpeed Cache 7.9.3. Cases A4 and A5 pass under the D-028 revision rule. See [B08 acceptance](#b08-acceptance).

Two recipes are approved. `litespeed_cache_793_v1` keeps the plugin option `cache` at 0. `litespeed_cache_793_cache_on_v1` (W395) has the same plugin and every other setting, with `cache` 1, its own settings pin and lock pin. A product site caches anonymous pages only after a signed plan with the cache-on recipe. See [Cache-on recipe](#cache-on-recipe-w395).

## Scope

This document defines:

- the vhost text that the renderer writes for opted-in sites and for every other site;
- what the LiteSpeed Cache plugin needs from OpenLiteSpeed (OLS);
- the opt-in, opt-out and re-enable flows;
- the fixed and locked plugin settings;
- how Rustiron pins the plugin;
- what Rustiron verifies after each change;
- the B08 acceptance tests.

Website traffic does not pass through Rustiron. OLS serves the cache. The plugin decides what OLS stores.

## How OLS looks up the cache

W370 read the OLS 1.9.4 cache module source ([`src/modules/cache/cache.cpp`](https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/modules/cache/cache.cpp)). The reading corrects W336:

- The define `USE_RECV_REQ_HEADER_HOOK` is commented out in 1.9.3 and 1.9.4. The module therefore looks up the cache in the `URI_MAP` hook, not in `RCVD_REQ_HEADER`.
- `HttpSession` runs `URI_MAP` after the vhost rewrite and the context rewrite (`src/http/httpsession.cpp`, `HSPS_VHOST_REWRITE`, `HSPS_CONTEXT_REWRITE`, `HSPS_HKPT_URI_MAP`). A vhost rewrite rule can therefore set an environment variable that the lookup reads.
- `checkAssignHandler` turns the module off for a request whose `modcache` variable is `0`. OLS 1.9.3 read that variable with a 1-byte buffer, so the value was always empty. OLS 1.9.4 reads it with a 3-byte buffer. The 1.9.3 defect explains the [W201](../validation/S10-W201/README.md) failure.
- `createEntry` looks for the response header `X-LiteSpeed-Vary` with the length `sizeof(s_x_vary) - 1`, and `s_x_vary` is a pointer. The module looks for a 7-character name and never finds the header. The defect explains the [W368](../validation/S10-W368/README.md) A6 result: OLS ignored the plugin's post-password vary.
- The public cache key always includes the value of the `_lscache_vary` cookie (`getCacheVaryCookie`).
- A vhost `module cache { ls_enabled 0 }` turns every hook of the module off for the sessions of that vhost (`ModuleConfig::parseConfig`, `ModuleManager::applyConfigToHttpRt`, `HttpVHost` module list).

## Model

1. OLS loads the cache module with `enableCache 0` and `enablePrivateCache 0`. OLS stores nothing on its own.
2. The plugin marks each WordPress response with `X-LiteSpeed-Cache-Control`: public, private or `no-cache`. OLS stores only what the plugin marks.
3. At login, the plugin sets the `_lscache_vary` cookie. OLS puts the cookie value into the cache key. A logged-in user therefore does not match an anonymous cache entry.
4. Each opted-in site has its own cache storage folder.
5. Every other site has the cache module off (W370). A public mark from its PHP is not stored and not served.

## Rendered vhost text

A site that is not opted in gets one block at the end of the W336 text:

```
module cache {
 ls_enabled 0
}
```

W370 moved the W336 pins on purpose. The test `an_unopted_vhost_turns_the_cache_module_off_with_pinned_bytes` pins the new bytes and checks that the W336 text is the exact prefix.

| Pin | W336 | W370 |
| --- | --- | --- |
| Generation of `rs_blog5` | `8f08795a62521731266511d1bdc64033a7af2c0f5474a810ae56aeb68f3ee0bd` | `3f09e5153a9cce91d177a4eea1a47043858b8da2e97433d27512cce7530d3e1b` |
| Vhost text of `rs_blog5` | `0f16421f95f364c163912c261b263bb5e5f49843108eb12cf38d012270cf8419` | `e4626ea31d516446aa44aaa5f0433d3996013bda49125f8266258823d1f362a4` |

An opted-in site gets one rewrite rule in its vhost rewrite block and the storage block at the end:

```
rewrite {
 enable 1
 autoLoadHtaccess 1
 rules <<<END_rules
RewriteCond %{REQUEST_METHOD} ^(GET|HEAD)$
RewriteCond %{HTTP_COOKIE} (^|;\s*)wp-postpass_[^=;]*=
RewriteCond %{HTTP_COOKIE} !(^|;\s*)wordpress_logged_in_[^=;]*=
RewriteRule .* - [E=modcache:0]
 END_rules
}
...
module cache {
 ls_enabled 1
 enableCache 0
 enablePrivateCache 0
 storagePath /usr/local/lsws/cachedata/rs_<site>
}
```

- A GET or HEAD with a WordPress post-password cookie and no login cookie skips the cache module. That visitor never gets the cached password form, and the unlocked page is never stored.
- The rule does not match a login cookie. A logged-in request keeps the module, so OLS still applies the plugin's `X-LiteSpeed-Purge` headers. W370 case A6c proved a purge by an administrator who also held a post-password cookie.
- The rule does not match a POST. A comment POST keeps its purge headers.
- No `enableCache 1`, no forced public cache and no TTL. The plugin sends the TTL.
- The lookup settings come from the reviewed parent. Nothing changes at listener or server scope.
- The rule works only where OLS reads `modcache` after the vhost rewrite. [D-052](../decisions/D-052-page-cache-ols-versions.md) lists the tested versions (`1.9.4`). On another version, an activation that serves a cache-on site is drift, and `ols-status` reports `page_cache_ols_tested: false` ([W426](../validation/S10-W426/README.md)).

Code: [`ols.rs`](../../crates/executor/src/ols.rs) `vhost`. Tests: [`ols_render.rs`](../../crates/executor/tests/ols_render.rs) `an_unopted_vhost_turns_the_cache_module_off_with_pinned_bytes` and `lscache_renders_per_site_storage_and_the_post_password_bypass`.

## What the plugin needs from OLS

| Need | Value | Source |
| --- | --- | --- |
| Cache module registered at server scope | The parent registers `module cache` | [OLS LSCache configuration](https://docs.openlitespeed.org/config/lscache/), "Cache Settings Inheritance" |
| Server cache switches off | `enableCache 0`, `enablePrivateCache 0`; the plugin decides | [OLS forum, plugin users set both to 0](https://forum.openlitespeed.org/threads/cache-module-not-caching-all-the-time.4091/) |
| Lookup on | `checkPublicCache 1`; `checkPrivateCache 1` | [OLS LSCache configuration](https://docs.openlitespeed.org/config/lscache/), parameter list |
| Per-vhost storage | `storagePath` that differs for each vhost | [OLS LSCache configuration](https://docs.openlitespeed.org/config/lscache/), "Set up Virtual Host-Level Cache Settings" |
| Server detection | A non-empty `X-LSCACHE` server variable in PHP | [LiteSpeed Cache `litespeed-cache.php`](https://github.com/litespeedtech/lscache_wp/blob/master/litespeed-cache.php) |
| No ESI | OLS does not support ESI; the plugin ESI option stays off | [LSCWP Cache screen](https://docs.litespeedtech.com/lscache/lscwp/cache/), "ESI tab" |
| Post-password vary | The plugin's `.htaccess` sets it; the site PHP cannot write `.htaccess`. Rustiron renders the `modcache:0` rule instead | LiteSpeed Cache 7.9.3 `src/htaccess.cls.php` |

## CyberPanel behavior

D-028 records CyberPanel commit `277cc4cacf18d286b2ebe1aab1b10d0281b0f91e`. CyberPanel is GPL-3.0. Rustiron copies no CyberPanel code or templates.

- The CyberPanel parent configuration turns both cache switches off and turns both lookups on.
- The CyberPanel vhost template sets only a per-vhost `storagePath` in its cache block.
- The CyberPanel WordPress installer runs WP-CLI with `--allow-root` to install the newest `litespeed-cache` release. The installer pins no version and checks no digest.

Rustiron keeps the same server model. Rustiron differs in these ways:

- The plugin runs as the site identity.
- Rustiron pins the plugin version and bytes.
- The effects have no network access.
- Sites that are not opted in have the cache module off.
- The settings are fixed and locked.

## Opt-in flow

W368 builds the opt-in as an extension of the existing `config_activate` verb. W370 adds the opt-out the same way. The verb catalogue keeps five verbs.

### Plan and grant

`config_activate` plan schema 2 adds one closed object, `page_cache`, with exactly three members:

| Member | Value |
| --- | --- |
| `site_id` | One of the plan's `site_ids` |
| `recipe_id` | `litespeed_cache_793_v1`, or `litespeed_cache_793_cache_on_v1` (W395) |
| `recipe_digest` | `litespeed_cache_793_v1`: the SHA-256 of the recipe archive. `litespeed_cache_793_cache_on_v1`: the SHA-256 of the [recipe manifest](#cache-on-recipe-w395). The executor refuses any value other than its own pin (`FIXTURE_BINDING_DENIED`) |

The plan carries no file, command, option text or path. The grant stays schema 1 and binds the object through `plan_digest`.
Code: [`ols.rs` contract](../../crates/contracts/src/approval/ols.rs). Vectors: [`ols-plan-v2-vectors.json`](../../crates/contracts/tests/fixtures/ols-plan-v2-vectors.json) and, for the cache-on recipe, [`ols-plan-cache-on-vectors.json`](../../crates/contracts/tests/fixtures/ols-plan-cache-on-vectors.json), checked by `check_canonical_vectors.py`.

### Steps

1. Before intent, the executor checks the opt-in. The site must be in the predecessor generation, so a bootstrap activation never opts in. The site must not be opted in.
2. The executor records the intent and the opt-in row in one transaction (journal table `page_cache_optins`). The journal refuses the row while the site has an unresolved page-cache change.
3. The activation renders the site with its own `storagePath` and the post-password rule. Every later activation renders the same for each opted-in site. The existing path runs the switch, the configuration test, the reload and the all-site probes.
4. After the probes pass, the executor asks the admin helper for step `page_cache_install`. The helper reads the site from the journal, never from the request. The helper runs the step only while the activation runs.
5. The helper reads the archive and the per-file list from the root-owned recipe store with `read_pinned`.
6. If the site has no `litespeed-cache` folder, the helper checks the archive listing and unpacks the archive as the site account in `rustiron_unpack_t`. If the folder exists as a real directory, the helper reuses it (W370 re-enable). Anything else at that name is refused.
7. The census checks owner, label and kind of every entry. The helper checks the SHA-256 of every listed file, one folder at a time with no link followed. A reused tree passes the same checks as a fresh unpack.
8. The helper writes the lock file (W370), or finds it with the exact bytes. See [Locked settings](#locked-settings).
9. The fixed script `opt-in.php` runs with the site PHP launcher (`run_site_php`). The launcher sets the site user and `rustiron_php_t` at the site level. It allows no network and no capabilities, and only the site `tmp` is writable. The script:
   1. stores the fixed settings before the plugin first runs;
   2. activates the plugin;
   3. ends every login session of the site;
   4. reports the version, the stored settings, the settings as the plugin reads them, whether the lock constants are in force, and the session count.
10. The checks in [Verification](#verification) run. If the script or a check fails, `deactivate.php` deactivates the plugin as the site, and the activation takes its single signed restore. The restore also runs the [removal step](#removal-step).

### No WP-CLI

The effect uses fixed PHP scripts, not WP-CLI. The only site PHP entry point is `lsphp` (`rustiron_php_exec_t`), and it reports the `litespeed` SAPI. WP-CLI 2.12.0 refuses every SAPI except `cli` ([W368 02c-sapi.log](../validation/S10-W368/02c-sapi.log)). The scripts take no argument.

### Read-only code and the WordPress file system

The site PHP cannot write its code. Both scripts define `FS_METHOD` as `direct` before WordPress loads ([W368 run 1](../validation/S10-W368/README.md#run-1-failure-and-recovery)). The plugin's writes to `.htaccess`, `wp-config.php` and its data files fail without effect. The audit log records them as `write` denials on the `html` folder.

## Opt-out flow

`config_activate` plan schema 3 (W370) adds one closed object, `page_cache_opt_out`, with exactly two members: `site_id` (one of the plan's `site_ids`) and `recipe_id` (the recipe of the site's opt-in; W395). Schema 3 never has `page_cache`, and schemas 1 and 2 never have `page_cache_opt_out`.
Vectors: [`ols-plan-v3-vectors.json`](../../crates/contracts/tests/fixtures/ols-plan-v3-vectors.json), made by [`make-v3-vectors.py`](../validation/S10-W370/make-v3-vectors.py) and checked by `check_canonical_vectors.py`.

1. Before intent, the executor checks the opt-out. The site must be in the predecessor generation and opted in. A site that the lab policy `ols.lscache` lists cannot opt out.
2. The executor records the intent and the opt-out row in one transaction (journal v16, table `page_cache_optouts`).
3. The activation renders the site with the cache module off and without the rewrite rule. From the reload on, OLS serves no stored entry of the site.
4. After the probes pass, the helper runs the [removal step](#removal-step) for the journaled site on the target generation.

A site is opted in while its latest succeeded page-cache change is an opt-in. A later schema 2 plan re-enables an opted-out site. The re-enable reuses the plugin tree and the lock file after the checks in steps 6 to 8.

### Removal step

Helper step `page_cache_remove` (W370) runs:

- after the verified target of an opt-out;
- after the single signed restore of an opt-in or an opt-out, inline or through `rustiron-executor compensate OP --admin-helper`.

The helper never runs it in a reconcile or for a bootstrap. The site comes from the journaled change. The live generation must be the target (opt-out) or the predecessor (restore).

1. `deactivate.php` deactivates the plugin as the site. If the plugin is not installed, the script reports it inactive.
2. The helper checks that `/usr/local/lsws/cachedata/rs_<site>` is absent, or is a real folder of the OLS account `nobody` that others cannot write. The path derives from the site account only.
3. A transient unit runs `/usr/bin/find -P <storage> -xdev -mindepth 1 -delete` as `nobody` with no capability, no network, `ProtectSystem=strict` and only that folder writable. The unit runs in `unconfined_service_t`, the domain that OLS itself runs in ([32-purge-domain.log](../validation/S10-W370/32-purge-domain.log)).
4. The helper requires the storage folder to be empty.
5. Two anonymous `GET /` must answer 200 with no `X-LiteSpeed-Cache` header and no public mark.

A failed removal after a restore leaves the operation unverified (`needs_attention`). The plugin files and the lock file stay; nothing in the site tree is deleted.

## Locked settings

The fixed settings file holds 35 keys, SHA-256 `228da3f62ee49332fd316cac3bae14e599268eda8681bef87b1e51f5401b8343`. W368 pinned 31 keys (`8909e131…2f9a`).

| Key | Value | Reason |
| --- | --- | --- |
| `cache` | `0`; `1` in the cache-on recipe (W395) | The cache-on recipe turns the page cache on for anonymous visitors |
| `cache-priv` | `0` | Logged-in users get `no-cache` |
| `cache-commenter` | `0` | A commenter gets `no-cache` |
| `cache-page_login` | `0` | The login page is never cached |
| `cache-rest` | `0` | REST responses are never cached |
| `esi` | `0` | OLS has no ESI |
| `guest`, `guest_optm` | `0` | No guest vary file |
| `object` | `0` | No object-cache drop-in |
| `crawler`, `auto_upgrade`, `news`, `cdn`, `cdn-quic`, `debug`, `cache-mobile` | `0` | No outbound calls, updates, variants or debug log |
| Page and image optimization keys | `0` | No file changes from the plugin |
| `cache-exc_qs` | `["unapproved", "moderation-hash"]` | WordPress's pending-comment link page shows the pending comment and the commenter's name (W368 A8, A9) |
| `cache-force_uri`, `cache-force_pub_uri` | `[]` | No URI is forced cacheable or public |
| `cache-login_cookie` | `""` | The login vary cookie stays `_lscache_vary`, the one name OLS keys on |

The plugin reads a `LITESPEED_CONF__<KEY>` constant over the stored option when `LITESPEED_CONF` is true (`Conf::load_options`, `Base::conf_const`, `Root::conf` in 7.9.3). The helper writes the fixed must-use file `wp-content/mu-plugins/rustiron-page-cache.php`, SHA-256 `f19e073b78a4586f368055327139de9c4b85e0c6ba57bb54196f59715c22b723`. The file defines `LITESPEED_CONF` and one constant for each of the 35 keys. WordPress loads it before the plugin. The file is site-owned, in the site label, and read-only to the site PHP.
A site administrator can still change a stored option in the dashboard, but the plugin reads the constant.

## Pins

| Artifact | Pin | Where |
| --- | --- | --- |
| Plugin archive `litespeed-cache.7.9.3.zip` (867,612 bytes) | `8ab0373e41a3e9d4329d8fa6f99f3afd096cc21ac2befb0a84dc005d8afb36d7` | [`page-cache-recipe.py`](../../packaging/page-cache-recipe.py) |
| WordPress.org checksum list for 7.9.3 (321 files) | `41dc8e796d55435e69abefd7274c075c694c2a7f451084095be9bfd38112d982` | The tool and the executor (`page_cache.rs`) |
| Recipe archive `litespeed-cache-7.9.3.tar` (3,123,200 bytes) | `0db968c7e9ae8a17023f2db3fef1134ba006e1e3f104c3fe715b7f46534e20a9` | The executor; the plan `recipe_digest` |
| Settings file | `228da3f62ee49332fd316cac3bae14e599268eda8681bef87b1e51f5401b8343` | The executor |
| Lock file | `f19e073b78a4586f368055327139de9c4b85e0c6ba57bb54196f59715c22b723` | The executor |

Rustiron keeps no plugin file: the plugin is GPL-2.0, and Rustiron is Apache-2.0 ([D-014](../decisions/DECISIONS.md)). The recipe tool writes a deterministic ustar archive at recipe preparation. Rustiron fetches nothing at effect time. A new plugin version or new settings is a new recipe and a new approved plan.

## Verification

The executor accepts an opt-in only if each check passes:

1. The opt-in report names the site account and version 7.9.3, newly activated, and the plugin is active.
2. WordPress holds each of the 35 settings with its fixed value, and the plugin reads each one with that value. No other key is in the report.
3. `LITESPEED_CONF` is true and all 35 constants are defined.
4. No user has a login session.
5. The plugin tree still matches the per-file list, and the lock file still has its exact bytes.
6. Two anonymous `GET /` answer 200 with no `X-LiteSpeed-Cache` header and no public mark.
7. The all-site probes passed before the plugin step.

The effects do not check WordPress core checksums or the audit log after activation. The lab runs did.

## Cache-on recipe (W395)

[D-044](../decisions/D-044-cache-on-recipe.md) accepted the recipe `litespeed_cache_793_cache_on_v1`. It uses the W368 plugin archive and checksum list.

| Pin | Value |
| --- | --- |
| Settings file (the W370 bytes with `"cache":1`) | `fec9698019115ae148051642af24ca9f26b0e9d70703e7d1aee1a90c28ab30f7` |
| Lock file (the recipe name in the header, `LITESPEED_CONF__CACHE` 1) | `6a299e0b2e178b1cd861e7759afd1467bf85762762f149bfbfac631bb490045d` |
| Recipe manifest, the plan `recipe_digest` | `3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767` |

The manifest is six fixed lines: the recipe name, `plugin litespeed-cache 7.9.3`, the archive name and digest, the checksum list name and digest, the settings digest and the lock digest. [make-cache-on-vectors.py](../validation/S10-W395/make-cache-on-vectors.py) computes all three pins with Python only. It also reproduces the W370 lock pin.

Differences from the W368 recipe:

- The journal records the recipe with the intent (journal v19, table `page_cache_recipes`). The opt-in and opt-out rows keep `litespeed_cache_793_v1`, the plugin they share. The admin helper reads the recipe from the journal.
- After activation, the first anonymous `GET /` must be stored (`miss`, or `hit` when already stored) and the second must be a public `hit`. The executor log line `cache_on_check` records both values.
- The helper replaces the lock file only when it holds the exact lock of the other recipe. It writes `rustiron-page-cache.php.new`, labels it, and renames it over the lock. Any other content is refused (`PROVISION_COLLISION`).
- The opt-out must name the recipe of the site's opt-in (`PRECONDITION_CHANGED` otherwise). A switch between the recipes is an opt-out, then an opt-in.
- The observation states `cache_on` for the site. The console shows "Opted in · page cache on for anonymous visitors".

The effect still uses the fixed scripts as the site account. WP-CLI cannot run under `lsphp`, and no PHP runs as root.

## B08 acceptance

Run on a throwaway lab site only. Real WordPress users and comments. The cookies stay on the VM.
W370 turned the page cache on for the run: root changed the one `LITESPEED_CONF__CACHE` line of the lock file ([W370 deviations](../validation/S10-W370/README.md#deviations)). W395 turned it on with the signed cache-on recipe and made no root edit ([W395](../validation/S10-W395/README.md#b08-acceptance)).

| ID | Case | Pass | W370 result (W395: the same result unless noted) |
| --- | --- | --- | --- |
| A1 | Anonymous `GET /` twice | `miss` then `hit` | Pass. W395: the opt-in check got `miss` then `hit`; A1 then got `hit` twice |
| A2 | User logs in, then `GET /` | No public hit; `no-cache`; response shows the user | Pass. A login while `cache` was 0 also got `_lscache_vary`. W395: a second login with the cache on |
| A3 | Same user, 5 requests to 3 cached pages | No `hit` | Pass |
| A4 | Login cookie from before activation | Session refused; the response shows no user | Pass under the revision rule: public hit of the anonymous page |
| A5 | Forged `wordpress_logged_in_*` cookie with no `_lscache_vary` | Response shows no user; record whether a public hit occurs | Pass under the revision rule: public hit of the anonymous page |
| A6 | Visitor unlocks a password-protected post | That visitor never gets the cached form page; the protected text never enters the public cache | **Pass.** The visitor got no cache header, `no-cache` and the text. 0 stored entries had the text |
| A6c (added) | Administrator with a post-password cookie purges | The purge reaches OLS | Pass. The next anonymous request was `miss` |
| A7 | Second visitor without the cookie | Gets the form, never the text | Pass |
| A8 | Commenter with a pending comment | No public hit on that post; the pending comment never reaches another visitor | **Pass.** The pending-comment link page was `no-cache` for the commenter and for an anonymous request |
| A9 | Commenter name and email | No stored public entry contains them | **Pass.** 0 of 5 stored entries |
| A10 | Logout | The next anonymous request gets no page that shows the user | Pass |
| A11 | Two users from one client IP | Neither sees the other's name, admin bar or nonce | Pass |
| A12 | `wp-admin`, `wp-login.php`, `POST`, preview links | Never cached | Pass. An anonymous preview URL got a stored 404 page with no draft text |
| A13 | Other sites | No cache file in their storage or in the shared default storage; probes pass | Pass |
| A14 | Page cache turned off | The next 2 anonymous requests get no `hit` | **Pass with the opt-out.** The plugin option alone kept the hits; after the opt-out, no `hit`, and the storage was empty. W395: the signed cache-on opt-out, the same result |

The [D-028 revision](../decisions/D-028-delegated-b-row-choices.md#revision-2026-11-12-w336) sets the pass rule. A valid logged-in session never receives the anonymous cached page. No private or user-specific response is stored as public or served to another visitor. Login, admin, preview and POST requests are never served from the cache.

Extra W370 cases:

| Case | Result |
| --- | --- |
| A site that is not opted in sends `X-LiteSpeed-Cache-Control: public` | No `X-LiteSpeed-Cache` header and 0 entries in the shared default storage, before and after the opt-in of another site, and after the opt-out |
| Opt-out with purge, twice | `succeeded`. The vhost has the module off, the storage folder is empty, the plugin is inactive, the lock file is unchanged |
| Re-enable | `succeeded` with no unpack job; the tree and the lock file passed the checks |
| An opt-in interrupted in its plugin step (executor killed) | The helper finished the step and the plugin was active. `reconcile` recorded `needs_attention`. `compensate --admin-helper` restored the predecessor, deactivated the plugin and emptied the storage: `failed_compensated`. A new opt-in of the same site then succeeded with the tree reused |
| Opt-out of a site not opted in, and of a site already opted out | `PRECONDITION_CHANGED`, exit 4, no row |

## What the failures need

W370 closed each [W368](../validation/S10-W368/README.md#b08-acceptance-results) failure:

| W368 failure | W370 closure |
| --- | --- |
| A8, A9: the pending-comment link page was stored public | `cache-exc_qs` in the fixed and locked settings |
| A14: stored entries stayed hits after `cache` 0 | The opt-out renders the module off and runs the removal step |
| A6: the unlocked visitor got the cached form | The vhost `modcache:0` rule for a post-password cookie without a login cookie |
| Shared parent storage | `ls_enabled 0` for every vhost that is not opted in |
| Dashboard changes to the settings | The lock file constants |
| An interrupted plugin step left the plugin active | The removal step after every restore of a page-cache change |

## Residual items

- A site's own PHP can fill its own cache storage while the site is opted in. The storage is outside the site's disk quota.
- A site administrator can deactivate the plugin in the dashboard. The plugin then sends a purge in that response. The site stays opted in for Rustiron until an opt-out.
- A visitor with any post-password cookie bypasses the cache on every page of that site.
- A failed opt-out leaves the site opted in with the plugin inactive and the storage emptied. Retry the opt-out.
- Lab policy `ols.lscache` sites and adopted lab vhosts keep the parent model; the product has neither.
- Journal schema 19 (W395) needs `rustiron-executor migrate` on any host with an older journal, including the lab VM `almalinux10` (journal v14).
- The `X-LiteSpeed-Vary` defect in OLS 1.9.4 stays. A later OLS release can change the post-password result; rerun A6 after an OLS update.

## Not in scope

- A direct switch between the two recipes while a site is opted in.
- A new plugin version or new settings without a new recipe, a new manifest digest and an approved plan.
- Any change to the OLS parent configuration.
- Cache for logged-in users, ESI, QUIC.cloud and object cache.

## Sources

- [OLS LSCache configuration](https://docs.openlitespeed.org/config/lscache/)
- [OLS v1.9.4 cache module source](https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/modules/cache/cache.cpp), [`httpsession.cpp`](https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/http/httpsession.cpp), [`modulemanager.cpp`](https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/lsiapi/modulemanager.cpp), [`lsiapilib.cpp`](https://github.com/litespeedtech/openlitespeed/blob/v1.9.4/src/lsiapi/lsiapilib.cpp)
- [OLS v1.9.3 cache module source](https://github.com/litespeedtech/openlitespeed/blob/v1.9.3/src/modules/cache/cache.cpp)
- [OLS forum: cache module settings with the plugin](https://forum.openlitespeed.org/threads/cache-module-not-caching-all-the-time.4091/)
- [LSCWP Cache screen](https://docs.litespeedtech.com/lscache/lscwp/cache/)
- LiteSpeed Cache 7.9.3 from WordPress.org: `src/conf.cls.php`, `src/base.cls.php`, `src/root.cls.php`, `src/control.cls.php`, `src/vary.cls.php`, `src/htaccess.cls.php`, `src/activation.cls.php`
- [WordPress.org plugin API for `litespeed-cache`](https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=litespeed-cache)
- [CyberPanel at the D-028 commit](https://github.com/usmannasir/cyberpanel/tree/277cc4cacf18d286b2ebe1aab1b10d0281b0f91e)
