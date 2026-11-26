# Scheduled capture

Updated: 2026-11-13, America/Toronto.
This procedure enables the daily product capture of [D-035](../decisions/D-035-scheduled-capture.md) on an enrolled product host.
The host must have an enrolled backup destination ([10-PRODUCT-STORE-ENROLLMENT](10-PRODUCT-STORE-ENROLLMENT.md)).
A production signer stays a human checkpoint.

## What the standing grant allows

One signed standing grant authorizes `backup_capture` only. The grant names the sites and the enrolled destination digest.
The grant also names a window series with these values:

- The first window start.
- The period.
- The window length.
- The number of windows, at most 35.

The executor admits one run for each site in each window and refuses every other request.
See [D-035](../decisions/D-035-scheduled-capture.md#bounds) for the bounds and the refusal codes.

## Prepare the plan

1. Choose the window. For the D-010 schedule, use `--period-seconds 86400` and `--window-seconds 7200`. Set `--first-window-start` to 06:55 UTC of the first day. That window holds 03:00 Toronto time in EST and in EDT.
2. Get the destination ID and digest from the reviewed projection: `rustiron --output json plan destination-digest PROJECTION`.
3. Create the plan on the operator workstation:

   ```sh
   rustiron plan create product-standing-capture --plan-id PLAN_ID \
       --host-id HOST --host-epoch EPOCH --profile-digest PROFILE --requester rustiron_coordinator \
       --site-id SITE --destination-id DEST_ID --destination-policy-digest DEST_DIGEST \
       --recipe-id site_files_db_v1 --first-window-start START --period-seconds 86400 \
       --window-seconds 7200 --max-runs 35 --valid-from START --expires-at END >plan.json
   ```

   Repeat `--site-id` for each site, at most 16. `END - START` is at most 3,024,000 s.
4. Review the plan: `rustiron --output json plan review-file plan.json`. The `standing_windows` list shows each window.
5. Write the schema 3 grant. Copy the sites, destination, schedule, validity, and plan digest from the plan.
6. Sign the grant with the operator key ([05-OPERATOR-KEY](05-OPERATOR-KEY.md)).
7. Review the signed grant offline with `rustiron-review --destination-policy PROJECTION`. The review shows `standing_capture` with each site's repository, every window, and `max_captures`.

## Install the signed files

1. Make the folder as root:

   ```sh
   install -d -o rustiron-coordinator -g rustiron-coordinator -m 0700 /var/lib/rustiron-coordinator/standing/current
   ```

2. Copy `plan.json`, `grant.json`, and `grant.json.sig` into the folder. Set the owner to `rustiron-coordinator` and the mode to 0600.
3. List the runs offline:

   ```sh
   runuser -u rustiron-coordinator -- rustiron --output json schedule runs \
       --dir /var/lib/rustiron-coordinator/standing/current
   ```

   The command shows each window and the derived operation ID of each site. Success is exit 0.
4. Enable both timers:

   ```sh
   systemctl enable --now rustiron-scheduled-capture.timer rustiron-scheduled-capture-check.timer
   ```

5. Confirm the next start: `systemctl list-timers 'rustiron-scheduled-capture*'`.

## Read the result

| Command or unit | Result |
| --- | --- |
| `journalctl -u rustiron-scheduled-capture.service` | One JSON report for each run: the window, each submission and its exit, and the status |
| `journalctl -u rustiron-scheduled-capture-check.service` | One JSON status report each hour |
| `systemctl --failed` | A failed scheduled unit shows an alert or a refusal |

The status report has these fields:

- `windows`: each window with `phase` (`pending`, `open`, or `closed`) and the state of each run. A closed window with no capture is `missed`.
- `missed` and `failed`: the window and site of each missed or failed run.
- `sites`: the newest succeeded snapshot of each site, its age in seconds, and `rpo_met`.
- `alerts`: `newest_closed_window_missed`, `newest_closed_window_failed`, `rpo_exceeded`, `grant_exhausted`, or `status_unknown`.

| Exit | Meaning |
| --- | --- |
| 0 | Each run of the open window succeeded or was already recorded, and no alert |
| 3 | No window is open. The command submitted nothing |
| 5 | The report alerts |
| Other | The exit of the first failed submission ([SPEC](../technical/SPEC.md) exit table) |

## Renew the grant

Sign the next grant before the last window closes. `remaining_windows` in the status shows the windows left.
Replace the three files in `current` with the new ones. The status then reads only the new grant's windows.
To revoke every outstanding grant, change `signer_policy_epoch` or the host epoch in the host policy.

## Independent checks

The scheduled units run as the coordinator account. A compromised coordinator can hide its own missed runs.
Check the newest capture independently:

- As root: `rustiron-executor capture-status OPERATION_ID` for the newest derived operation ID.
- On the operator workstation: list the site's snapshots with the fetch key ([10-PRODUCT-STORE-ENROLLMENT](10-PRODUCT-STORE-ENROLLMENT.md)).

[W386](../validation/S10-W386/README.md) proves this procedure on a throwaway product host with a compressed schedule.
