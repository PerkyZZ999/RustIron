# Apply the Rustiron firewall zone

This procedure makes the `rustiron` firewalld zone the host's default zone, and puts `public` back ([D-095](../decisions/D-095-cp08-v1-scope.md), [firewall design](../technical/FIREWALL.md)). [W559](../validation/S10-W559/README.md) rehearsed it on a lab copy.

The zone allows only SSH on the enrolled port, HTTP, HTTPS, DNS when the `dns` section is enrolled, and DHCPv6 replies when enrolled. Every other incoming connection is rejected, including Cockpit and any port that a service opened in `public`.

## Before you start

- Keep a second way into the host, such as the provider's console, until step 4 passes.
- Find the SSH port: `ss -Htlnp | grep sshd`. The tool refuses unless `sshd` listens on the enrolled port.
- Find whether the provider gives IPv6 by DHCPv6. If unsure, enroll `--firewall-dhcpv6-client`: it allows only DHCPv6 replies to the host.
- The default zone must be `public` (the AlmaLinux default) or `rustiron`. The tool does not take over another zone.
- The host must run a build with W559. An older executor refuses a policy with a `firewall` section.

## Step 1: enroll the section

For a new host, add `--firewall-ssh-port PORT` (and `--firewall-dhcpv6-client` if needed) to the `policy` command of [page 9](09-PRODUCT-ENROLLMENT.md). For an enrolled host, as root, from the source tree of the installed build:

```sh
install -d -m 0700 /root/firewall-update
python3 packaging/enrollment-policy.py firewall --policy /etc/rustiron/policy.json \
    --out /root/firewall-update/policy.json --firewall-ssh-port 22 --firewall-dhcpv6-client
systemctl stop rustiron-executor.service
install -o root -g root -m 0600 /root/firewall-update/policy.json /etc/rustiron/policy.json
restorecon -R /etc/rustiron
systemctl start rustiron-executor.service
```

The tool prints the old and the new section and changes nothing else.

## Step 2: read the plan

```sh
python3 packaging/firewall-zone.py
```

It prints the zone file and the plan, and changes nothing. Check the services and the SSH port.

## Step 3: apply

```sh
python3 packaging/firewall-zone.py --apply
```

The last line is `verified: <interfaces> in zone rustiron; allowed ...`. On `REFUSED`, nothing stays changed: a refusal before the write changes nothing, and a failed step or check after it sets `public` as the default zone again and removes the file. Without the zone, the host is back on `public` rules.

| Refusal | Meaning |
| --- | --- |
| `sshd does not listen on TCP port N` | Enroll the port that `sshd` uses |
| `the default zone is 'X'` | Another default zone is set. Find out why before you change it |
| `X is bound to zone 'Y' permanently` | An interface is bound to another zone in firewalld. Remove the binding, or stop |
| `verification failed` | The zone did not hold the interface or the exact set; `public` is the default again |

## Step 4: check access

From another terminal, open a new SSH session. Request a site over HTTP and HTTPS. Keep the first session open until both work.

Run the command of step 3 again after a policy change. It prints `unchanged` when the zone already matches.

## Check for drift

```sh
python3 packaging/firewall-zone.py --check
```

It changes nothing. Each difference from the enrolled zone prints as a `drift:` line and the exit is 1: a zone file edited by hand, a service or port added at runtime, another default zone, or an interface in another zone. Run step 3 again to repair it; a runtime addition also goes away with `firewall-cmd --reload`. `verified:` and exit 0 mean the host matches the policy.

## Put `public` back

```sh
python3 packaging/firewall-zone.py --restore
python3 packaging/firewall-zone.py --restore --apply
```

The first command prints the plan; the second sets `public` as the default zone, removes `/etc/firewalld/zones/rustiron.xml`, and reloads. Do this before the [uninstaller](12-UNINSTALL.md).
