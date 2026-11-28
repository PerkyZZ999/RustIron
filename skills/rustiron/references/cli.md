# RustIron CLI

The `rustiron` CLI runs on the server and talks to the local coordinator. Add `--output json` for machine-readable output.

## Read

| Command | What it shows |
| --- | --- |
| `rustiron doctor` | OS and host state |
| `rustiron site list` | Sites in the coordinator inventory |
| `rustiron site inspect <site_id>` | One site |
| `rustiron operation status <operation_id>` | The recorded state of one change |
| `rustiron evidence export <operation_id>` | The recovery receipt of one change |
| `rustiron plan review-file <path>` | Every field of a plan file, offline |
| `rustiron plan inspect <plan_id>` | One stored plan |
| `rustiron-plan envelope <plan.json>` | The blast radius of a plan file (changes, reloads), offline |

## Prepare a plan

`rustiron plan create <verb> ...` prints the canonical plan for offline review. It signs, submits, and changes nothing. Run `rustiron plan create <verb> --help` for the inputs of a verb.

| Verb | Purpose |
| --- | --- |
| `site-provision` | Create a site account and database (no traffic yet) |
| `config-activate` | Choose the sites that an OpenLiteSpeed generation serves |
| `product-backup-capture` | Back up one site |
| `product-standing-capture` | A standing (scheduled) backup |
| `product-restore-probe` | Test a restore in an isolated sandbox |
| `site-credential-rotate` | Change a site's database password (no secret in the plan) |
| `dns-zone-import` | Import a DNS zone |
| `dns-change` | Change DNS records |
| `app-provision` | Create a Node.js or Bun app |
| `app-deploy` | Deploy a prebuilt app release |
| `app-lifecycle` | Start, stop, or restart an app |
| `site-eject` | Hand one site's vhost outside RustIron (nothing is deleted) |

## Apply a signed plan

After the human signs the plan and its grant offline:

```sh
rustiron plan apply-file --plan-file plan.json --grant-file grant.json \
  --signature-file grant.json.sig --operation-id <operation_id> --idempotency-key <key>
```

Only the human runs this, after reading the review.
