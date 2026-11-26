# Turn the page cache on

Updated: 2026-11-13, America/Toronto.
This procedure turns the page cache on for one WordPress site of an enrolled product host, and off again.
[W395](../validation/S10-W395/README.md) is the lab evidence. [D-044](../decisions/D-044-cache-on-recipe.md) is the decision. [PAGE-CACHE](../technical/PAGE-CACHE.md) is the contract.

A production signer stays a human checkpoint. In the lab, the signer is `lab_agent` (`policy_3`).

## What the recipe does

The recipe `litespeed_cache_793_cache_on_v1` installs or reuses LiteSpeed Cache 7.9.3 as the site account, with no network.
It stores and locks fixed settings with the page cache on for anonymous visitors. Logged-in users, commenters, the login page, REST, ESI, the object cache, CDN and optimization stay off.
The activation ends every login session of the site. Users must log in again.
After the activation, the executor requires an anonymous `GET /` to be stored and then served as a public `hit`. Otherwise it deactivates the plugin and restores the previous generation.

Nothing here edits a file by hand. Do not change the lock file `wp-content/mu-plugins/rustiron-page-cache.php`: the next opt-in refuses a changed lock.

## Before the change

1. The host journal is version 19. On a host with an older journal, stop the coordinator and executor services and run `rustiron-executor migrate` first.
2. The recipe store holds the prepared plugin archive and checksum list ([product enrollment](09-PRODUCT-ENROLLMENT.md); `packaging/page-cache-recipe.py` checks the WordPress.org pins `8ab0373e…36d7` and `41dc8e79…d982`).
3. No OLS operation is unresolved. Use `rustiron-executor status OP` for the last activation.
4. The site is not opted in. If it is opted in with `litespeed_cache_793_v1`, opt it out first (step 3 below, with that recipe).
5. Read the live generation and digest with the services stopped:

   ```sh
   systemctl stop rustiron-coordinator.service rustiron-executor.service
   systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor ols-status --admin-helper
   systemctl start rustiron-executor.service rustiron-coordinator.service
   ```

## Procedure

1. Prepare a `config_activate` schema 2 plan that lists every served site and names the site in `page_cache`:
   - `recipe_id`: `litespeed_cache_793_cache_on_v1`;
   - `recipe_digest`: `3665c57f288174dddba0be23a5b43a554c11a226ec681171f79334e5c1dad767`.

   In the lab, `lab/s04/make_ols_request.py --page-cache-site SITE --page-cache-recipe litespeed_cache_793_cache_on_v1 --page-cache-recipe-sha256 <digest>` writes it.
2. Review the plan with `rustiron plan inspect`. The effects line says "page cache ON for anonymous visitors". Sign the grant, then apply the plan through the coordinator (`rustiron plan apply-file`). The state must be `succeeded`.
3. To turn the cache off, apply a schema 3 plan with `page_cache_opt_out` for the site and the same `recipe_id`. The site's vhost renders the cache module off, the plugin is deactivated as the site, and the site's cache storage is emptied.

## Check

- `rustiron-executor observe` states `"page_cache": "cache_on"` for the site after step 2 and `"opted_out"` after step 3. The console shows "Opted in · page cache on for anonymous visitors".
- The lock file has SHA-256 `6a299e0b2e178b1cd861e7759afd1467bf85762762f149bfbfac631bb490045d`.
- Two anonymous requests for `/` answer `X-LiteSpeed-Cache: hit` after step 2, and no `X-LiteSpeed-Cache` header after step 3.

## Refusals

| Refusal | Cause | Action |
| --- | --- | --- |
| `FIXTURE_BINDING_DENIED` | The plan's `recipe_digest` is not the executor's pin | Use the digest above |
| `PRECONDITION_CHANGED` | The site is opted in already, is not served, or the opt-out names another recipe than the opt-in | Read the site state with `observe`; opt out with the opt-in's recipe |
| `failed_compensated` | The plugin step or the cache check failed; the previous generation is back, the plugin is inactive and the storage is empty | Read the helper log (`step_failure`). A `pinned artifact digest mismatch` means the recipe store file changed: prepare it again |
| `needs_attention` | The removal after a restore failed | Retry the opt-out after the cause is fixed |
