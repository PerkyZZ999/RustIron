# Multi-tenant delegation & tenancy contract (CP07 Slice 1)

**Status:** Slice 1 tenancy model, billing boundary, and ACL/quota verifier are lab verified ([W623](../validation/S10-W623/README.md)).
Multi-tenancy follows v1.0 under [D-094](../decisions/D-094-cp07-after-v1.md) and requires a separate threat review.
**Scope:** Strictly read-only CP07 boundary verifier in `rustiron-control --verify-delegation`.

## Purpose

Multi-user hosting panels frequently collapse admin, reseller, and end-user roles into shared OS accounts or unrestricted daemon APIs. Under CP07, delegation MUST preserve Rustiron's per-site isolation and separate custody:

- **Three explicit roles only**: `admin`, `reseller`, `tenant_user`.
- **Separate OS tenancy**: every site keeps its own unique non-root Unix UID (`rs_<site_id>`), SELinux MCS category, quota, and database identity.
- **No cross-account access**: A `tenant_user` accesses ONLY sites it owns. A `reseller` accesses ONLY sites owned by its direct child accounts. Cross-tenant access is denied by default.
- **Strict quota conservation**: sub-account quotas sum to `<=` reseller package quota; per-account site quotas sum to `<=` account quota; total site quotas sum to `<= host_disk_budget_mib`.
- **Bounded service controls**: non-admin accounts may invoke ONLY the closed allowlist (`site_php_restart`, `app_restart`, `site_cron_trigger`), never root shells or arbitrary `systemctl` units.
- **Dual-approved ownership transfers**: transferring a site between accounts requires both `current_owner_approved` and an `admin_signed_grant_present` executor grant.
- **Billing-integration inventory (`built_in_billing_engine: false`)**: External billing tools (such as WHMCS or FOSSBilling) integrate only through scoped webhooks or adapters. Rustiron builds no internal billing ledger.

## Command interface

```sh
rustiron-control --verify-delegation <delegation-policy.json> [--human]
```
