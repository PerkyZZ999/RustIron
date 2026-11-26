# Optional per-site Valkey object cache contract (P21 Slice 1)

**Status:** Slice 1 workload-justification & isolation verifier lab verified ([W622](../validation/S10-W622/README.md)); live Valkey RPM packaging and disposable VM cache-invalidation proof follow post-v1.0 owner package approval.
**Scope:** Strictly read-only P21 boundary verifier in `rustiron-control --verify-valkey-plan`.

## Purpose

Object caching is NOT mandatory for every WordPress site (`mandatory_for_all_sites: false`). Under P21, a site may add isolated Valkey object caching ONLY when:

1. **Repeatable workload benefit is measured** (`>= 10%` improvement across `>= 5` randomized repeats against an already-tuned baseline, linked to P12/P22 evidence); otherwise enablement stops (`NO_MATERIAL_BENEFIT_STOP`).
2. **Strict per-site isolation holds** (`shared_multi_tenant_instance_allowed: false`, `tcp_listener_allowed: false`):
   - `tcp_port = 0` (private Unix socket under `/run/rustiron-site-valkey/rs_<site_id>/valkey.sock`);
   - Unique non-root UID, unique SELinux MCS category, unique mode `0400`/`0600` per-site ACL credentials file, and unique `rs_<site_id>:` namespace prefix.
3. **Explicit resource and eviction limits hold**:
   - Per-site `maxmemory_mib` within `16..=512 MiB` and sum across sites `<= host_valkey_memory_budget_mib`;
   - Safe eviction policy (`allkeys-lru`, `volatile-lru`, or `allkeys-lfu`; `noeviction` refused).
4. **Operational safety checks are verified**:
   - Graceful outage bypass (site serves without fatal 500 when Valkey stops);
   - Staleness/invalidation behavior verified;
   - Clean disable verified (zero broken drop-in or `wp-config.php` residue);
   - Private, authenticated, cart, and checkout caching remains strictly uncached/isolated.

## Command interface

```sh
rustiron-control --verify-valkey-plan <valkey-plan.json> [--human]
```
