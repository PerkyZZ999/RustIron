# Product store enrollment

This procedure enrolls one product backup destination on an enrolled product host.
Do it after [product enrollment](09-PRODUCT-ENROLLMENT.md) and the first site provision.
After this procedure, the host accepts signed product captures for the enrolled sites ([D-029](../decisions/D-029-product-write-gate.md)).

[W371](../validation/S10-W371/README.md) records the first run on a fresh AlmaLinux 10.2 product host with the HTTPS lab store.
That run wrote the schema 2 policy by hand. [W374](../validation/S10-W374/README.md) adds the schema 2 output to `packaging/enrollment-policy.py`.

## Scope and authority

The procedure enrolls one destination for each host: one S3 store, one bucket, and one repository for each enrolled site.
The pin in `policy.json` schema 2 names the reviewed projection. The [binding contract](../technical/PRODUCT-BACKUP-BINDING.md#product-executor-enrollment) defines the pin.
The [transport candidate](../technical/PRODUCT-S3-TRANSPORT.md) defines the projection, the principals, and the repository initialization.

The procedure is provider neutral ([D-027](../decisions/D-027-provider-neutral-integrations.md)).
A store qualifies by its capabilities, not by its provider. The lab MinIO store is the reference implementation.
Before Rustiron claims support for another store, record a compatibility check for that store.

The store choice is a trust decision:

- In the lab, the store is the [W344](../validation/S10-W344/README.md) HTTPS lab store on the operator PC. This store is not an independent copy ([D-026](../decisions/D-026-defer-offsite-and-escrow.md)).
- For production, the choice of the storage account is a human checkpoint ([off-site copy](02-OFFSITE-COPY.md)). An agent does not choose a production store or create a production account.

These items stay on the operator PC. They never go to the host, a log, the evidence, or chat:

- the store administration key;
- the secret of each principal, except the two key files that step 9 sends;
- the recovery copy of each repository password.

The host never holds an identity that can write the repository identity (`config` and `keys/`).
Restic `init` runs on the operator PC, not on the host.
Send each secret through SSH standard input only. Never put a secret in an argument.

Product restore probes stop after their repository check (W320). This procedure does not enable a product restore.

## Roles

| Role | Does |
| --- | --- |
| Store administrator (operator PC) | Holds the store administration key. Makes and removes the principals, initializes each repository, and keeps the recovery copies |
| Operator (operator PC) | Writes the projection and computes its digest |
| Operator (root on the host) | Installs the projection, the CA, the credentials, and the policy. Labels the port and enables the store units |
| `rustiron plan destination-digest` | Validates a projection file and prints `destination_id` and `destination_policy_digest`. It reads one local file and opens no network connection |
| `packaging/enrollment-policy.py` | Writes `policy.json` schema 2 from explicit values. It reads no private key and no projection |
| Signer (operator PC) | Signs each capture grant for the enrolled destination ID and digest |

## Store prerequisites

D-027 names the capabilities that the store needs. Refuse a store that does not have each capability.

| Capability | Requirement | Rustiron check |
| --- | --- | --- |
| S3 API | HTTPS with SigV4, path-style addressing, an explicit region | Every store action uses path-style URLs and the enrolled region |
| Endpoint | One IPv4 address and one TCP port. Port 443 by default. A private address needs an enrolled off-host route | The projection validator refuses loopback, link-local, multicast, and reserved addresses |
| CA | A PEM CA bundle that the operator pins. The server certificate has the endpoint address in its SAN | The projection holds the SHA-256 of the exact CA bytes. Each action compares the installed file with it |
| Versioning | Bucket versioning is `Enabled` | The capture `lock` action reads `GetBucketVersioning` before and after the write |
| Object Lock | The default retention is COMPLIANCE for at least `retention_days` (30–3650) | The capture `lock` action reads `GetObjectLockConfiguration` before and after the write |
| Object retention | The capture principal can read `GetObjectRetention` in its own prefix | The `lock` postcheck reads the retention of each object that the capture wrote |
| Per-site principals | One capture, one fetch, and one init principal for each site. No principal is shared between sites or phases | The projection holds each principal ID and the digest of its reviewed policy. The backend review proves the scope |
| Identity write denial | The capture principal cannot write or delete `config` or `keys/*` of its prefix. An explicit Deny overrides the prefix Allow | The backend authority check (W365) |

The capture `lock` action is the Rustiron check for versioning and the default retention.
It runs at each capture, so a wrong bucket setting refuses the first capture with `RETENTION_LOCK_UNVERIFIED`.
Check the bucket settings before the first capture with the store administration tool. For the lab store, run `sh lab/s10/w344_tls_store.sh status` and read `version info` and `retention info --default`.

## Per-site principals

Make three principals for each site. Use the site account `rs_<site>` as the prefix name: `sites/rs_<site>/`.

| Principal | Credential slot | Allowed | Denied | Lifetime |
| --- | --- | --- | --- | --- |
| Capture | `aws` | List the site prefix. Read and write objects in it. Read `GetObjectRetention`, `GetBucketVersioning`, and `GetBucketObjectLockConfiguration`. Delete only `locks/*` | Write or delete `config` and `keys/*`. Delete versions. Change retention or legal hold. Bucket administration. Every other prefix | While the site is enrolled |
| Fetch | `fetch-aws` | List the site prefix. Read objects in it | Every write and delete. Retention changes. Bucket administration. Every other prefix | While the site is enrolled |
| Init | None on the host | List the site prefix. Read and write `config` and `keys/*` only | Every delete. Retention changes. Bucket administration. Every other object | Only during step 5 |

The lab policy templates are [`w344-capture-policy.json.in`](../../lab/s10/w344-capture-policy.json.in), [`w344-fetch-policy.json.in`](../../lab/s10/w344-fetch-policy.json.in), and [`w344-init-policy.json.in`](../../lab/s10/w344-init-policy.json.in).
The `authorization_sha256` of a principal in the projection is the SHA-256 of its reviewed policy document.
If a principal policy changes, the projection digest changes. Then enroll the new digest again.

## Values to choose and measure

| Value | Example (W371) | How to get it |
| --- | --- | --- |
| `site_id` and account | `w371a`, `rs_w371a` | The provisioned site. The account is `rs_` and the site ID |
| `destination_id` | `w371_tls_lab_9443` | Operator choice: 1–64 of `A-Z a-z 0-9 _ -` |
| `store_id` | `w344_tls_store` | Operator choice for the storage authority, same grammar |
| `endpoint_ipv4`, `port` | `192.168.122.1`, `9443` | The store endpoint. The host must reach it |
| `region`, `bucket` | `us-east-1`, `rustiron-lab-tls` | The store configuration |
| `egress_profile` | `ipv4_tcp_port_v1` | `ipv4_tcp_443_v1` for port 443. `ipv4_tcp_port_v1` for each other port |
| `retention_days` | `30` | Not more than the bucket default retention |
| `ca_sha256` | `f2919c22…4041` | `sha256sum CA.pem` of the exact CA file |
| `repository_id` | `0aed77ff…ec03` | Step 5 |
| Principal IDs and `authorization_sha256` | `cap_rs_w371a`, `f87c216c…e22a` | Steps 3 and 4 |

## Procedure

Do steps 1–7 on the operator PC from the repository root. Do steps 8–15 as root on the host.
The lab commands use [`w344_tls_store.sh`](../../lab/s10/w344_tls_store.sh). For another store, do the same steps with its administration tool.

1. **Confirm the site.** Confirm that the host is enrolled, the site is provisioned, and the site account is correct.
   If the account or an existing repository is ambiguous, stop before you make a principal.
2. **Check the prefix.** Make sure that `sites/<account>/` has no `config` object and no `keys/` object in any version.
   If one exists, stop. Do not initialize the repository again.
3. **Capture principal and repository password.** Lab: `sh lab/s10/w344_tls_store.sh site <account>`.
   The script makes `cap-<account>`, its policy, the `aws` file, and a new `repo.password`. Each file is 0600 under `~/.config/rustiron-lab/tls-store/sites/<account>/`.
4. **Fetch principal.** Lab: `sh lab/s10/w344_tls_store.sh fetch <account>`. The script makes `fetch-<account>` and the `fetch-aws` file.
5. **Repository initialization.** Lab: `sh lab/s10/w344_tls_store.sh init <account>`. The script does these steps:
   1. It refuses a prefix that has a `config` or `keys/` object in any version.
   2. The script makes the short-lived `init-<account>` principal with the store administration key.
   3. It runs the pinned restic `init` with the init principal, the CA, `-o s3.bucket-lookup=path`, the region, and `repo.password`.
   4. It removes the init principal, its policy, and its secret.
   5. It reads the repository ID with the fetch principal (`restic cat config --no-lock`).

   The expected output has `init identity removed` and `repository_id=<64 hex digits>`.
   The lab script requires the pinned restic 0.19.1 at `/mnt/data-z/VMs/rustiron-lab/bin/restic`. It refuses a file with another SHA-256.
6. **Projection.** Write the projection JSON. Use the [projection fields](../technical/PRODUCT-S3-TRANSPORT.md#destination-policy-projection) and the values above.
   Include the repository ID of step 5 and the SHA-256 of each principal policy. W371 used [make_projection.py](../validation/S10-W371/make_projection.py) to write [projection-9443.json](../validation/S10-W371/projection-9443.json).
7. **Digest.** Run `rustiron --output json plan destination-digest PROJECTION.json`.
   The output is one JSON object with `destination_id` and `destination_policy_digest`. Record both values for the review and the signer.
8. **Inputs on the host.** Copy the projection and the CA PEM file to a root-only folder on the host. These files hold no secret.
   Run `/usr/bin/rustiron --output json plan destination-digest DIR/backup-destination.json`.
   The output must be equal to the output of step 7. If it is different, stop.
9. **Credentials.** Send `aws`, `fetch-aws`, and `repo.password` through SSH standard input into `/etc/rustiron/credentials/sites/<account>/`.
   Make each folder `root:root` mode 0700 first. Write each file through a 0600 temporary file in the same folder, then rename it.
   Run `restorecon -R /etc/rustiron/credentials`. W371 used [pc-secrets.sh](../validation/S10-W371/pc-secrets.sh).
   Check each file without reading it: `stat -c '%n %U:%G %a links=%h %F'` and `ls -lZ`.
   Each file must be `root:root`, mode 0600, one link, a regular file, and type `rustiron_job_credential_t`.
10. **Stop the services.** Run `systemctl stop rustiron-coordinator.service rustiron-executor.service rustiron-admin-helper.service`.
    Do not change a trust file while the executor runs.
11. **Projection, CA, and endpoint file.**

    ```sh
    install -o root -g root -m 0600 DIR/backup-destination.json /etc/rustiron/backup-destination.json
    install -o root -g root -m 0600 DIR/backup-ca.pem /etc/rustiron/backup-ca.pem
    printf 'RUSTIRON_STORE_ENDPOINT=%s\nRUSTIRON_STORE_PORT=%s\n' IPV4 PORT >/etc/rustiron/store-network.env
    chmod 0644 /etc/rustiron/store-network.env
    ```

    Use the `endpoint_ipv4` and `port` of the projection. The file holds exactly these two lines, in this order.
12. **Policy schema 2.** From the source tree of the installed build, write the policy into a private folder.
    Use the same values as the installed schema 1 policy ([09 step 3](09-PRODUCT-ENROLLMENT.md#procedure)), and add the pin of step 7:

    ```sh
    python3 packaging/enrollment-policy.py policy --out DIR/policy.json \
        --host-id HOST --host-epoch EPOCH --profile-digest HEX \
        --requester rustiron_coordinator --requester-uid "$(id -u rustiron-coordinator)" \
        --issuer ISSUER --signer-policy-epoch SIGNER_EPOCH \
        --verifier-sha256 "$(sha256sum /usr/bin/ssh-keygen | cut -d' ' -f1)" \
        --wordpress-sha256 HEX --uid-range 3001-3099 --category-range 201-299 \
        --quota-block-hard-kib KIB --quota-inode-hard N \
        --ols-listener NAME --ols-address IP:PORT --ols-parent-sha256 HEX --ols-webadmin-port 7080 \
        --product-backup-destination-id DESTINATION_ID --product-backup-digest DIGEST
    ```

    Compare the new file with the installed file. Only `schema_version` and `product_backup` can be different:

    ```sh
    python3 -I -c 'import json,sys; old,new=(json.load(open(p)) for p in sys.argv[1:]); new.pop("product_backup"); new["schema_version"]=1; print(old==new)' \
        /etc/rustiron/policy.json DIR/policy.json
    ```

    The expected output is `True`. If the output is `False`, find the changed value before you continue.
    Then run `install -o root -g root -m 0600 DIR/policy.json /etc/rustiron/policy.json` and `restorecon -R /etc/rustiron`.
13. **Port label.** For port 443, skip this step. The policy label `http_port_t` applies.
    For each other port, run `semanage port -a -t rustiron_store_port_t -p tcp PORT` ([W352](../validation/S10-W352/README.md#selinux)).
    If the base policy gives that single port its own entry, use `-m` in place of `-a`. A base range that includes the port does not prevent `-a`. W371 labeled 9443 inside the `pki_ca_port_t` range `9443-9447`.
    The label applies to the port on the whole host. Choose a port that no other local service uses.
14. **Namespace and relay.** Run `systemctl enable --now rustiron-store-netns.service rustiron-store-relay@PORT.socket`.
    The instance name is the enrolled port. See the [packaging README](../../packaging/README.md#store-namespace-and-relay).
15. **Start the services.** Run `systemctl start rustiron-admin-helper.service rustiron-executor.service rustiron-coordinator.service`.
    The admin helper must start after step 14. A helper that was already running keeps a private mount namespace without the store namespace handle, and each store action is refused with `PRECONDITION_CHANGED` ([W500-F1](../validation/S10-W500/README.md)). Restart the helper after each start or restart of `rustiron-store-netns.service`.
    Do the checks below only after `/run/rustiron/executor.sock` and `/run/rustiron-coordinator/control.sock` exist.

## Checks that prove enrollment

| Check | Expected result |
| --- | --- |
| `systemd-run --wait --pipe --quiet /usr/libexec/rustiron/rustiron-executor observe` | `host.product_backup_enrollment` holds the destination ID and digest of step 7 |
| `systemctl is-active rustiron-store-netns.service rustiron-store-relay@PORT.socket` | `active` for each |
| `semanage port -l \| grep rustiron_store_port_t` (port other than 443) | The enrolled port |
| `ip netns exec rustiron-store nft -s list ruleset` | The output chain accepts only the enrolled address and port. The policy is `drop` |
| `ip netns exec rustiron-store ss -Hltn` | One listener, on the enrolled port |
| `stat` of the three credential files | `root:root`, mode 0600, one link, `rustiron_job_credential_t` |
| Backend authority with the actual principals (lab: `python3 lab/s10/w344_authority.py <account> <other account>`) | Each check passes. The capture principal gets 403 for each write and delete of `config` and `keys/*` |
| `restic cat config --no-lock` with the fetch principal, on the PC | The ID is the `repository_id` of the projection |
| First signed capture through the coordinator | `succeeded`. `capture-status` shows the snapshot ID and `retention_days` |
| `rustiron-executor receipt-export OP`, then `python3 scripts/check_receipt.py` on the PC | `PASS: consistent self-attested receipt` |
| Store object versions of the new snapshot (store administration tool) | Each new object has COMPLIANCE retention until its write time plus `retention_days` |
| `ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts boot` | No denial in the capture, store relay, admin helper, or job credential domains |

Run `receipt-export` through `systemd-run --wait --pipe` and read its standard output through a pipe.
If you send its output to a file under `/root`, PID 1 writes that file and SELinux denies the write (W371).

## Failure and recovery

| Answer | Meaning | Action |
| --- | --- | --- |
| `plan destination-digest` refuses the projection | A projection field fails a rule, for example the port and `egress_profile` do not match | Correct the projection. Do not edit a digest by hand |
| `init` refuses: the prefix `already has a config or keys/ object` | The prefix has a repository identity in some version | Do not initialize again. Find the owner of that repository first |
| `init` fails after it makes the init principal | The script removes the init principal | Read the partial state of the prefix before you try again |
| `EXECUTOR_DEPENDENCY_UNAVAILABLE` when the executor loads the policy | The schema 2 policy is not valid. The projection is malformed, or its ID or digest is not the pin. A lab `backup` section is present, or the build is a lab build | Correct the file. Write the policy again with the tool |
| `EXECUTOR_ACCESS_DENIED` | A trust file or a credential file is missing, is a link, or has a wrong owner, mode, or link count | Correct the shape. Do not relax the mode |
| `INVALID_REQUEST` when the executor loads the policy | The projection is larger than 16 KiB | Write a smaller projection |
| Relay socket fails to start. A `name_bind` denial names another port type | The port has no `rustiron_store_port_t` label | Do step 13, then step 14 |
| `PRECONDITION_CHANGED` before any store request | The endpoint file, the namespace filter, the listener instance, and the projection do not agree. Or the admin helper started before the store namespace, and a `getattr` denial names `/run/netns/rustiron-store` as `ifconfig_var_run_t` (W500-F1) | Make all four name the same address and port. Restart `rustiron-admin-helper.service` while the executor is stopped |
| `PROVISION_STEP_FAILED` at the store check | A store action failed: no route, wrong CA, wrong credential, or another repository ID | Check the route, the CA digest, the credential slot, and the repository ID |
| `RETENTION_LOCK_UNVERIFIED`, capture `failed` with no snapshot | Versioning is off, the default retention is not COMPLIANCE for `retention_days`, or the `aws` slot cannot read them | Correct the bucket or the `aws` file. W371 got this answer with the fetch key in the `aws` slot |
| Capture `running` after the snapshot write started | The outcome is uncertain | Use [capture recovery](../technical/PRODUCT-CAPTURE-EFFECTS.md#operator-settlement-w366). Never mark it `succeeded` |
| Restore probe `failed` with `NOT_ADMITTED_FOR_EFFECT` | The product probe effects are not built (W320) | No action. The probe receipt states each field `not_run` (W374) |

Do not rotate a repository key with this procedure. Key rotation writes `keys/` objects and needs its own reviewed principal.
To retire a site, remove its capture and fetch principals after the host stops using them. The locked object versions stay until their retention ends.
