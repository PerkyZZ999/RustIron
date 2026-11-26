# Product backup transport candidate

Proposed 2026-11-11. Scope B01 and B09.
The first candidate uses restic with one operator-enrolled, off-host HTTPS S3 endpoint.
The host profile binds one dedicated versioned bucket. Each site uses a separate repository and separate upload and fetch principals.
This proposal extends the [product backup binding](PRODUCT-BACKUP-BINDING.md) within the [recovery decision](../decisions/ADR-004-independent-recovery.md).

## Why this candidate

The lab already exercises site-scoped S3 credentials, repository paths, and default Object Lock checks. See [W207](../validation/S10-W207/README.md) and [W228](../validation/S10-W228/README.md).
Restic v0.19.1 supports explicit HTTPS endpoints, path-style bucket lookup, a fixed signing region, and a separate CA pool. See the [S3 backend](https://github.com/restic/restic/blob/v0.19.1/internal/backend/s3/s3.go) and [HTTP transport](https://github.com/restic/restic/blob/v0.19.1/internal/backend/http_transport.go).
The [W307 loopback probe](../validation/S10-W307/README.md) confirms the HTTPS request shape and refusal cases with the staged AlmaLinux binary.

Direct S3 writes leave a visibility gap. Restic's S3 save path does not request conditional creation. The W226 overwrite test created a new current version while preserving the locked original. See the [pinned restic source](https://github.com/restic/restic/blob/v0.19.1/internal/backend/s3/s3.go#L268-L287) and [W226 evidence](../validation/S10-W226/README.md).

An S3 bucket policy that requires conditional creation can reject normal writes from that client. See [S3 conditional write requirements](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html).
The candidate therefore requires a demonstrated recovery path from protected versions after current objects become unusable.

Restic's append-only REST server is an alternative if retained-version recovery fails the acceptance checks. The REST path would need separate locked retention evidence. See [restic retention and append-only guidance](https://restic.readthedocs.io/en/stable/060_forget.html).
A DNS-based service endpoint would need a separate address and trust contract for dynamic routing.

## Destination policy projection

Use the existing v2 destination envelope and the hash domain from the [binding contract](PRODUCT-BACKUP-BINDING.md#root-enrollment-and-the-digest).
The closed transport ID is `s3_https_ipv4_v1`. Reject extra members and missing fields in every object.
W308 implements offline validation and digest calculation. The input limit is 16 KiB.

The following is the exact `transport` object for this candidate.

| Member | Accepted value and effect |
| --- | --- |
| `store_id` | Stable operator-enrolled ID for the independent storage authority. Use the existing `Id` type. |
| `endpoint_ipv4` | Canonical dotted-decimal IPv4 address. Offline validation excludes `0.0.0.0/8`, loopback, link-local, multicast, and `240.0.0.0/4` including limited broadcast. Host validation must also exclude local addresses and directed broadcast on the enrolled route. A private address requires an enrolled off-host route. |
| `port` | Enrolled TCP port, an integer from 1 to 65535. Use `443` by default. |
| `region` | Explicit signing region. One to 63 ASCII lowercase letters, digits, or hyphens. Start and end with a letter or digit. |
| `bucket` | One dedicated bucket. Three to 63 ASCII lowercase letters, digits, or hyphens. Start and end with a letter or digit. The operator verifies backend bucket ownership and naming rules. |
| `repository_root` | Literal `sites`. Derive the final component from the enrolled site account. |
| `ca_sha256` | SHA-256 of the exact enrolled PEM CA bundle |
| `egress_profile` | Literal `ipv4_tcp_443_v1` when `port` is `443`, and literal `ipv4_tcp_port_v1` for each other port. The only permitted IP flow goes to the enrolled peer over TCP on the enrolled port. |
| `retention_mode` | Literal `compliance`. The envelope's `retention_days` is an integer from 30 to 3,650. |
| `repositories` | One or more records within the root policy input bound, sorted by ascending ASCII `site_id`. Each has exactly a validated `site_id` and the expected lowercase 64-hex `repository_id`. Refuse duplicate sites or repository IDs. |

Construct the repository as `s3:https://<endpoint_ipv4>:<port>/<bucket>/sites/<account>` from the same validated record used for the digest.

The repository ID is the decrypted restic configuration ID. A fixed, bounded `restic cat config` check with the scoped read identity must match it before capture, fetch, or reconciliation proceeds. See the [restic configuration](https://github.com/restic/restic/blob/v0.19.1/internal/restic/config.go) and [cat command](https://github.com/restic/restic/blob/v0.19.1/cmd/restic/cmd_cat.go).

Each credential profile contains exactly `profile_id`, `scope`, `credential_slot`, and `principals`.
Use an `Id` for `profile_id`. The capture scope and slot are `site_capture_v1` and `aws`. The fetch values are `site_fetch_v1` and `fetch-aws`.

Each principal record contains exactly `site_id`, `principal_id`, and `authorization_sha256`.
The principal arrays have the same site set and order as `repositories`. Each `principal_id` is an enrolled `Id` that identifies the backend principal in the review evidence. Refuse shared principals between sites or phases.
The authorization digest identifies the independent review artifact for the effective backend scope. Test that scope with the actual principal.

The slot chooses the credential under the product profile's fixed per-site credential directory. Restic receives the separately enrolled `repo.password` from that same site directory. See the [host layout](HOST-LAYOUT.md).

W312 resolves the signed site once against the validated repository and credential rows.
The result supplies the URL, endpoint, region, repository ID, CA digest, retention, and separate capture and fetch enrollments.
Its relative credential paths use the same account name as provisioning.

Grant review displays those settings for the signed site. See the [review contract](OFFLINE-REVIEW.md#product-backup-v2).
The resolver opens no credentials or network connections. The product runner must still load credentials from the compiled root and verify the live preconditions.

CA, principal, scope, and repository changes produce new policy digests. Password and secret bytes stay outside the projection.
Rotate secret bytes under the existing policy only after validating the same principal, authorization, and repository.
The [synthetic projection](../validation/S10-W307/projection.json) supplies a concrete canonical hash vector.

### Enrolled port

An S3 store can listen on a port other than 443. Under [D-027](../decisions/D-027-provider-neutral-integrations.md), the projection therefore enrolls the port. W352 implements this rule.

- Each port has exactly one egress profile literal, so one effect has one digest.
- The validator refuses port `0`, a port above 65535, a non-integer port, and a profile that does not match the port.
- Projections with port `443` keep their exact canonical bytes and digests. The [W307 vector](../validation/S10-W307/projection.json) and the W345 lab projection keep their digests.
- The [W352 vector](../validation/S10-W352/projection-port.json) enrolls port 9443. `scripts/check_canonical_vectors.py` computes both projection digests outside Rust.
- The worker URLs, the restic repository, and the `curl` requests use the enrolled port.
- The endpoint file, the namespace filter, the listener check, and the relay also use it.
- Trust does not change. The rules for the pinned CA, path-style addressing, HTTPS only, and no redirects stay the same.

Port 443 keeps its policy label `http_port_t`. Each other port needs the dedicated `rustiron_store_port_t` label before the relay starts.
The relay can bind and connect only that type and `http_port_t`. The store jobs can connect only to those two types.
Without the label, the relay listener does not start and the executor refuses the job. The [W352 lab proof](../validation/S10-W352/README.md) records the cases and the label refusal.

## Transport and job boundaries

Require TLS 1.2 or later and a certificate with an IP SAN matching the enrolled peer. Pin the exact CA bytes and pass the same verified snapshot to the job through the trusted credential loader.
The restic client uses `--cacert`, `-o s3.bucket-lookup=path`, and the exact enrolled `-o s3.region`.
The chosen client must fail TLS verification with a wrong CA or IP SAN, and refuse redirects. The reviewed client disables redirect following. See [Go certificate verification](https://pkg.go.dev/crypto/x509#Certificate.VerifyHostname) and the [minio-go HTTP client](https://github.com/minio/minio-go/blob/v7.1.0/api.go#L257-L263).

### Repository identity worker

The product `capture-manifest repo-id SITE POLICY_DIGEST` action takes a site ID and the admitted policy digest.
The launcher must supply four files through systemd credentials. Use `destination` for the projection and `ca` for the enrolled PEM bundle.
Use `aws` for the selected site's fetch credential and `password` for its repository password.

The worker verifies the projection digest and CA digest. It accepts one static `[default]` AWS profile with an access key and secret.
The pinned client can execute `credential_process`. The worker refuses extra keys and profiles before starting restic. See the [MinIO credential provider](https://github.com/minio/minio-go/blob/v7.1.0/pkg/credentials/file_aws_credentials.go#L86-L125).

The worker passes sealed, nonexecutable snapshots of the CA and credentials to restic through inherited descriptors.
The subprocess runs `cat config` with `--no-lock`, no cache, and a cleared environment.
The worker allows 15 seconds and at most 4 KiB of output.
Success requires the expected configuration ID. The worker returns a silent exit 0 on match and exit 2 on refusal.

The [W313 proof](../validation/S10-W313/README.md) uses the staged restic binary and a synthetic HTTPS store in an isolated network namespace.

W314 derives the four `LoadCredential=` properties after product request verification.
It uses `backup-destination.json` and `backup-ca.pem` under the trusted product policy directory.
It selects `fetch-aws` and `repo.password` from the signed site's fixed credential directory.

The executor checks owner, mode, link count, regular-file type, and size without reading the secrets.
PID 1 supplies the job copies. The worker checks the projection and CA digests again before networking.
W315 binds the worker launch to the verified store namespace and runs the worker in `rustiron_capture_t`. See the network section below.

### Network and phase separation

Run only the fixed backup and fetch commands from scoped unprivileged jobs. Rebuild their environment from an allowlist inside the fixed runner.
Use one bounded static credential file and a fixed empty configuration directory. Reject credential profile overrides and metadata or proxy access.

The restic SDK has environment, file, and IAM credential providers. The network guard must deny fallback traffic even when an expected credential is absent. See the [credential chain](https://github.com/restic/restic/blob/v0.19.1/internal/backend/s3/s3.go#L95-L124).

Restrict store jobs to the IPv4 address family. Use `IPAddressDeny=any` and a single `IPAddressAllow` host address. These controls filter by address.

The [W314 guest probe](../validation/S10-W314/README.md) found that an nftables cgroup match kept the old cgroup identity after the slice restarted.
The stale rule allowed another port on the enrolled address. The product must reject this guard shape.

The next candidate uses a dedicated job network namespace with a namespace-wide nftables output chain.
Its default drops all output. The sole permitted IP flow goes to the enrolled peer over TCP on the enrolled port.
The W314 filter kept blocking alternate ports after slice recreation.

Before launch, the product must verify the root-owned namespace, the enrolled off-host route, and the effective filter.
W315 implements these checks in the [store network module](../../crates/executor/src/store_network.rs) for the fixed handle `/run/netns/rustiron-store`.
The executor requires an `nsfs` handle and the exact `nft -s list ruleset` text of one `inet rustiron_store` table.
It also requires a non-loopback unicast route to the endpoint.
It then starts the worker in the namespace as the site account in `rustiron_capture_t`.
The [W315 guest proof](../validation/S10-W315/README.md) records a matching repository ID.
It also records refusals with no store request.
The capture domain gives the worker's memfd snapshots their own tmpfs type.

The executor verifies the namespace but does not create it.

W316 proposes a relay for the off-host path. The namespace keeps loopback only, with the endpoint address on `lo`.
A socket unit listens on the endpoint inside the namespace. The stock `systemd-socket-proxyd` relays each connection from the host namespace to the same fixed endpoint, in the candidate `rustiron_store_relay_t` domain.
The relay needs no IP forwarding, NAT, or firewalld change. TLS stays end to end.
The [W316 guest proof](../validation/S10-W316/README.md) passed under Enforcing, including a firewalld reload and namespace replacement.
A routed veth with masquerade was not selected because it needs forwarding on the uplink.
The owner selected the relay on 2026-11-12.

W317 adapts the launch checks to the relay and adds fixed host units. See the [product staging guide](../../packaging/README.md#store-namespace-and-relay).
`rustiron-store-netns.service` creates the namespace at boot from `/etc/rustiron/store-network.env`. The relay socket is bound to the namespace and restarts with it.

W352 makes the relay units templates. The instance name of `rustiron-store-relay@PORT.socket` is the listener port, and the relay connects to the address and port in the endpoint file.
Before each store job, the executor requires these conditions:

- The endpoint file names the enrolled address and port.
- The namespace contains only `lo`, with the endpoint as a local address.
- The ruleset includes the reply rule.
- Exactly one IPv4 listener is bound on the enrolled port in the current namespace.

The [W317 guest proof](../validation/S10-W317/README.md) passed after a reboot, a firewalld reload, and a namespace restart.
[W318](../validation/S10-W318/README.md) runs the same launch in the admin helper domain. PID 1 writes the namespace readers' output to the helper runtime directory.
The real off-host store and backend permissions remain to be proved.

The [capture effects design](PRODUCT-CAPTURE-EFFECTS.md) and [D-025](../decisions/D-025-product-capture-effects.md) define the write path.
[D-029](../decisions/D-029-product-write-gate.md) enables product writes in product builds ([W371](../validation/S10-W371/README.md)).
See [systemd IP controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IPAddressAllow=) and the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).

Dump, import, and restored application checks keep their existing no-egress boundaries. Mount repository and CA credentials only for store phases.

The W228 lock checker uses cleartext HTTP. This candidate first proposed a pinned AWS CLI v2 subprocess for the product lock reader.
[D-025](../decisions/D-025-product-capture-effects.md) item 1 replaced that proposal with the OS `curl` and its SigV4 option. [D-027](../decisions/D-027-provider-neutral-integrations.md) keeps provider tools out of core paths.

The reader uses the same explicit endpoint, CA snapshot, region, and scoped capture credentials. It fixes path-style addressing and constrains the environment, output, and runtime.
The S3 operations it reads are defined in the S3 API reference. See [GetObjectLockConfiguration](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-lock-configuration.html) and [GetBucketVersioning](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-bucket-versioning.html).

## Backend authority and acceptance

The capture principal may list and read its own repository and write data, index, snapshot, and lock objects there. Restrict deletes to ordinary deletion of its own lock objects.
Fetch can list and read its own repository. Deny writes and deletes. Deny history deletion, version deletion, retention changes, bucket administration, and cross-site access to both principals.
Creation and replacement of repository config and key objects belong to the separately controlled storage authority ([initialization](#repository-initialization)).

Object Lock applies to versions. Simple deletes can place delete markers, and an overwrite can hide the protected version. See [Object Lock behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).

Require versioning and the enrolled default COMPLIANCE retention before capture. Recheck after upload and before recording success. Preserve uncertainty after a possible write if this check fails.
The separate retention authority must demonstrate the protection interval for the snapshot and its required repository objects, including shared older packs.

Exercise default-lock drift during the capture window. Default settings sampled twice do not prove that each required version received the intended lock. See [W228](../validation/S10-W228/README.md) and [S3 retention queries](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-retention.html).

| Proof | Required observation |
| --- | --- |
| Policy binding | Change each effect-bearing field under the same host profile pin. The original signed request fails before intent. Change the field after intent and the helper or reconciliation refuses before repository use. |
| Transport | Capture and fetch use only the approved IPv4 address and TCP port. Wrong CA, wrong SAN, redirects, different ports, proxy, metadata, and extra addresses fail. Reboot and firewall reload preserve the boundary. |
| Authority | Use actual worker keys. Refuse cross-site list/read/write, history delete, protected version delete, config/key writes, retention changes, and fetch-side mutation. Verify lock cleanup under the chosen backend. |
| Retained versions | Replace an object with the capture identity in a disposable repository. Restore the approved snapshot from retained versions using independently held recovery access on a clean host without Rustiron. |
| Full recovery | Recover files, database, and application health with independently recovered keys. Measure the D-010 RPO and RTO. Test interruption, credential rotation, retained shared objects, and cleanup. |

### Repository initialization

The repository identity is the `config` object and the `keys/` objects of the site prefix. The capture principal must not write or delete them.
The capture policy has an explicit Deny of `s3:PutObject` and `s3:DeleteObject` on `sites/<account>/config` and `sites/<account>/keys/*`.
The Deny overrides the Allow of `s3:PutObject` on the site prefix. On the lab MinIO store, it also refuses a copy and a multipart upload to these keys ([W365](../validation/S10-W365/README.md#item-1-repository-identity)).

After the initialization, no capture operation writes the repository identity. W365 recorded the store requests of these operations. None wrote `config` or `keys/`:

- `restic backup`, `restic check` with a lock, and `restic unlock` of a stale lock, with the capture principal.
- `restic check`, `snapshots`, and `cat config` with the fetch principal and `--no-lock`.
- Two gated product captures through the worker actions `repo-id`, `lock`, `backup`, `check`, `snapshot-tag`, and `manifest`.

Initialize each site repository one time, at enrollment, on the operator workstation. That workstation holds the store administration key and the recovery copy of the repository password.

1. Make sure that the site prefix has no `config` object and no `keys/` object in any version. If an object exists, stop. Do not initialize again.
2. With the store administration key, make a short-lived init principal for the site. Its policy allows a listing of the site prefix. It also allows `s3:PutObject` and `s3:GetObject` on `config` and `keys/*` of the site. It denies deletes, version deletes, retention changes, and bucket administration.
3. Run `restic init` with the init principal, the enrolled CA, `-o s3.bucket-lookup=path`, the enrolled region, and the site's `repo.password`.
4. Remove the init principal and its policy. Delete its secret.
5. Read the repository ID with the fetch principal: `restic cat config --no-lock`. Write that ID in the destination projection.

Restic and the site host never receive the store administration key.
The site host never holds an identity that can write the repository identity.
A per-site init principal limits a defect in restic or in the procedure to the identity objects of one site.

For the lab store, [`w344_tls_store.sh`](../../lab/s10/w344_tls_store.sh) `init ACCOUNT` does steps 1 to 5. The [lab enrollment procedure](../operator/06-LAB-BACKUP-ENROLLMENT.md#https-lab-store) gives the commands.

Key rotation (`restic key add`, `key passwd`, and `key remove`) also writes or deletes `keys/` objects. This candidate does not define key rotation. A rotation procedure needs its own reviewed principal.

### Recovery from retained versions

The capture principal can replace the current version of any object in its own prefix except `config` and `keys/`. W363 replaced the snapshot, index, and pack objects of an approved snapshot. After that, `restic check` and `restic restore` failed. Each earlier version stayed locked ([evidence](../validation/S10-W363/README.md#case-3-retained-versions)).

Restic names each object in `data/`, `index/`, `snapshots/`, and `keys/` with the SHA-256 of the stored bytes. Restic writes each of these objects only one time. Thus a key in these directories with more than one version, or with a delete marker, changed after restic wrote it. The correct version is the version whose SHA-256 is equal to the key name.

The procedure uses the store root key on the operator PC. Do not put the root key on the site host. [`restore_versions.py`](../validation/S10-W363/restore_versions.py) runs steps 2 to 5 for the lab store.

1. Stop the captures of the site. Record the approved snapshot ID from its saved receipt.
2. List all versions in the site prefix (`mc ls --recursive --versions --json`). Select the keys in `data/`, `index/`, `snapshots/`, and `keys/` that have more than one version or a delete marker.
3. Read each version of a selected key (`mc cat --version-id`) and calculate its SHA-256. Select the earliest version that matches the key name. If no version matches, stop: the object cannot be recovered from this store.
4. If the current version already matches, make no change. Otherwise, copy the selected version to the same key (`mc cp --version-id`). The copy is a new current version, and the bucket default lock applies to it.
5. Read the new current version and compare its SHA-256 with the key name.
6. With the fetch key and `--no-lock`, run `restic check --read-data`. Then restore the approved snapshot and compare it with the receipt.

The procedure deletes no version and changes no retention. The replaced versions stay locked for their full retention period and use storage until that period ends.
The procedure does not repair `config` or `locks/`. Restic does not name these objects by content hash.

Since W365, the capture principal cannot replace `config` or `keys/` objects.
Each restic command that loads a replaced index fails, as `restic check` did in W363. Repair the repository before the next capture.

Review this candidate, the effective network boundary, and the backend permission model before enabling product effects.
Provider accounts, keys, spending, and production exposure remain separate [human checkpoints](../AUTONOMY.md#critical-checkpoints).
