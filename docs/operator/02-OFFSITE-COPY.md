# Step 2 — Off-site backup copy (Backblaze B2 with object lock)

> **Deferred to G4 (D-011, 2026-10-26).** Not needed for the lab MVP.
Do this > before the first real site.

Account/cost approval remains a critical owner checkpoint.
This is a dated B2 procedure, not a new provider selection.
Check official pricing and supported CLI compatibility before account work.
R11/R13/S09 require physical independence, not this specific provider.

The original lab checkpoint stored backups in MinIO on your PC, next to the clean host and the keys ([S07 summary](../validation/S07-ACCEPTANCE/README.md)).
This step adds a physically independent copy that the site host and the PC copy job cannot delete.

## Dated provider comparison

Git retains the dated provider comparison at `49e0c7b:docs/operator/02-OFFSITE-COPY.md`.
Recheck current official pricing, retention, account, and permission behavior before selection.
The no-delete acceptance test governs the destination choice.

B2's key capabilities map one to one onto the no-delete design that the lab already proved with MinIO ([S07-W031](../validation/S07-W031/README.md)): `writeFiles` can upload and hide.
Only `deleteFiles` can destroy a version, and no Rustiron key gets it.
Source: Backblaze [key capabilities](https://www.backblaze.com/docs/cloud-storage-application-key-capabilities) and [S3-compatible key mapping](https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys).

## Design (what you are building)

```text
VM (site host) --capture key--> PC MinIO (locked, 1 day lab) --copier key--> B2 bucket (locked, compliance 30 d)
                                                                          ^
clean host / reviewer ------------------- read-only fetch key ------------+
```

- **Copier key** (lives on the PC): list, read, upload and hide under
  `sites/`.
It cannot delete versions, change retention or touch the bucket.
- **Fetch key** (one per site, read-only, under `sites/<account>/`): used by
  recovery drills, the clean host and the reviewer.
- **Master key** (retention authority): only in your escrow (step 3) and your
  B2 login.
Never on the VM, never in the repo, never in chat.
- The copy job is encrypted end to end: it copies restic's already encrypted
  objects byte for byte, so B2 never sees plaintext and the copier needs no repository password.

## A. Create the account (web, about 5 min, an estimate)

1. Sign up at <https://www.backblaze.com/sign-up/cloud-storage>.
2. **Region:** the sign-up page asks once and it cannot be changed. Any
   region works.
The point is a different building from your PC.
Pick the closest one offered (for example Canada or US East).
3. Turn on **two-factor authentication** (Account → Security). Write the
   recovery codes on the paper sheet from [step 3](03-KEY-CUSTODY.md).
Do not store them on the PC.
4. B2 Cloud Storage → **Application Keys** → **Generate New Master Application
   Key**.
Keep that page open.
You need the key ID and key in step B.3.
It is shown only once.

## B. Create the bucket and scoped keys (terminal, about 10 min, an estimate)

Run these in a terminal on the PC, from the repository root `/mnt/data-z/MyProjects/Rustiron`.

1. Install the official B2 CLI (tested syntax: v5.0.2):

   ```sh
   sudo pacman -S --needed python-pipx   # CachyOS/Arch; skip if pipx exists
   pipx install b2      # or: uv tool install b2
   b2 version
   ```

2. Decide the retention days from [step 1](01-RECOVERY-OBJECTIVES.md)
   (default **30**).
**Compliance mode cannot be shortened or removed**, by you or by Backblaze, until each version's period ends.

3. Authorize with the master key. The CLI **prompts**. Paste the key ID and
   key there, not on the command line:

   ```sh
   b2 account authorize
   ```

4. Create the bucket (locked, encrypted at rest, private). The script picks a
   unique name `rustiron-offsite-<random>` and writes only the non-secret endpoint/bucket to `~/.config/rustiron-lab/offsite/offsite.env`:

   ```sh
   sh lab/operator/offsite_b2_setup.sh bucket 30
   ```

5. Create the copier key and the blog13 fetch key. Secrets go straight from
   the CLI into `0600` files.
Only the key IDs are printed:

   ```sh
   sh lab/operator/offsite_b2_setup.sh keys
   ```

   For each extra site you want drilled: `sh lab/operator/offsite_b2_setup.sh fetch rs_blog9`.

6. Check, then remove the master key from the PC:

   ```sh
   b2 key list --long          # rustiron-copier and rustiron-fetch-rs-blog13; no deleteFiles
   b2 bucket get "$(. ~/.config/rustiron-lab/offsite/offsite.env; echo "$B2_BUCKET")"
                               # fileLockConfiguration: enabled, compliance, your days
   sh lab/operator/offsite_b2_setup.sh show
   b2 account clear
   ```

Result on the PC (all `0600` except `offsite.env`):

```text
~/.config/rustiron-lab/offsite/
  offsite.env              B2_BUCKET, B2_S3_ENDPOINT, B2_REGION, B2_RETENTION_DAYS (not secret)
  copier-aws               copier key, AWS credentials format
  fetch-rs_blog13-aws      read-only key for sites/rs_blog13/
```

### Manual fallback (if the script reports unexpected output)

Create the keys with the CLI by hand, and copy each printed `keyID key` pair into the file yourself with an editor.
Do not paste them into chat.

```sh
b2 key create --bucket BUCKET --name-prefix sites/ rustiron-copier \
  listBuckets,listAllBucketNames,readBuckets,readBucketRetentions,listFiles,readFiles,readFileRetentions,writeFiles
b2 key create --bucket BUCKET --name-prefix sites/rs_blog13/ rustiron-fetch-rs-blog13 \
  listBuckets,listAllBucketNames,readBuckets,listFiles,readFiles
```

File format (`umask 077` first):

```ini
[default]
aws_access_key_id = <keyID>
aws_secret_access_key = <key>
```

Do **not** use the web "Add a New Application Key" form for the copier: its "Read and Write" option includes `deleteFiles`.

## C. Hand over to the agent

Send in the project chat: `Off-site ready`. the implementing agent reads the files from `~/.config/rustiron-lab/offsite/` on the PC directly.
It never needs their contents in chat.

## What the implementing agent does next

1. **Rights test** against B2, as W031 did for MinIO (credentials from 0600
   files, never argv).
Expected: copier and fetch keys cannot delete a version, change retention, delete the bucket or set lifecycle.
Fetch cannot write; copier "delete" only hides.
The master key cannot delete a locked version either.
2. **Copy job** on the PC: copy each site's encrypted restic objects from
   MinIO to `sites/<account>/` in B2 with the copier key, never deleting at the destination, then compare object lists and hashes.
Scheduled right after each capture (RPO from step 1).
3. **S07 rerun**: capture blog13, copy, and record a receipt whose destination
   says **off-site B2 (independent provider)**.
4. **S09 rerun** (after [step 3](03-KEY-CUSTODY.md)): W037-style clean-host
   VM recovery fetching from **B2** with keys taken from the **escrow USB**, timed against RPO/RTO.
`independent_copy_confirmed` can only pass then.
5. Update the S07/S09 acceptance pages and the S10 audit.

## Limits to keep in mind

- The clean host the implementing agent uses is still on your PC. B2 makes the **copy**
  independent.
The restore host still needs independence evidence.
D-018 permits an agent recovery runner.
Another human guide follower is optional.
- The copy depends on the PC being up. If the PC dies first, B2 still holds
  everything up to the last copy.
- The B2 account itself is now a common dependency. Your escrow holds its
  master key and 2FA recovery codes.
