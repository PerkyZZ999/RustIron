# Alert check-in to Uptime Kuma

This procedure connects one Rustiron host to the owner's Uptime Kuma monitor ([D-083](../decisions/D-083-alert-delivery.md)). Kuma mails the owner when a check-in reports a failure or when check-ins stop. Rustiron holds no mail password.

## What it sends

Every two minutes, `rustiron-alert-checkin.timer` runs the read-only [diagnoses](../technical/HEALTH-DIAGNOSES.md) with the executor's journal observation and pushes one result:

- `up` with the message `ok` when no finding alerts.
- `down` when a finding fails, or when one of these checks warns: backup, certificate, capture, storage, support. The message lists `state check subject` for each, failures first, cut at 300 characters.
- `down` with `diagnosis unavailable` when the observation or the diagnosis cannot be made.

A finding that is `unknown` does not alert by itself. The message holds only check names, states, and subjects; no file content, command text, or secret.

## Connect a host

1. In Uptime Kuma, add a monitor of type **Push** for the host, with a heartbeat interval of **300 seconds** and the Gmail notification on. The timer pushes at least twice in each interval.
2. Copy its push URL. The part from `?status=` on is not needed.
3. On the host, save it as root without putting it in an argument list. Run this, paste the URL, press Enter, then Ctrl+D:

   ```sh
   install -m 0600 /dev/null /etc/rustiron/alert-push.url && cat > /etc/rustiron/alert-push.url
   ```

4. Run one check-in and read its result: `systemctl start rustiron-alert-checkin.service; journalctl -u rustiron-alert-checkin.service -n 5`. The line `alert-checkin: status=up&msg=ok` means the push left. Kuma shows the monitor as up.
5. Enable the timer: `systemctl enable --now rustiron-alert-checkin.timer`.

The service runs only when `/etc/rustiron/alert-push.url` exists. A link that is not a Kuma push link is refused, and nothing is pushed.

## When a mail arrives

- **Down with findings.** Run `rustiron-control --merge-observation FILE --diagnose --human` as the operator account (the [diagnoses](../technical/HEALTH-DIAGNOSES.md) page) and follow each finding's action. Kuma sends one mail when the state changes and one when it is up again. A failure that stays keeps the monitor down.
- **Down with `diagnosis unavailable`.** Read `journalctl -u rustiron-alert-checkin.service`. The executor observation or the diagnosis failed.
- **No heartbeat.** The host, its timer, or the network path to the homelab is down. Check that the host answers SSH, then `systemctl status rustiron-alert-checkin.timer`.

## Pause or remove

- Pause: `systemctl disable --now rustiron-alert-checkin.timer`, then pause the monitor in Kuma, or Kuma mails about the silence.
- Change the link: repeat step 3.
- Remove: disable the timer, then `rm /etc/rustiron/alert-push.url`. The uninstaller deletes the link before it archives `/etc/rustiron`, and removes the units.

## Limits

The lab host reaches Kuma on the homelab network. A production host needs its own route to the homelab, such as a VPN, before this check-in can work there. Kuma itself is the single notifier; if the homelab is down, no mail is sent, and the manual check is the [diagnoses](../technical/HEALTH-DIAGNOSES.md) command.
