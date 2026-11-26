# CP08 firewall: one Rustiron zone in firewalld

This guide is the design of the firewall part of [D-095](../decisions/D-095-cp08-v1-scope.md). [W558](../validation/S10-W558/README.md) adds it. [W559](../validation/S10-W559/README.md) implements slice 1 and proves it on a lab copy; the [operator page](../operator/28-FIREWALL-ZONE.md) gives the procedure.

## Lab facts

A short-lived overlay copy of `w508-retire` (AlmaLinux 10.3) showed ([facts](../validation/S10-W558/lab/00-firewall-facts.log)):

- `firewalld` 2.4.3 with nftables is enabled and running. The default zone is `public`, and it holds the one interface `enp1s0`. It allows the services `cockpit`, `dhcpv6-client`, and `ssh`; `cockpit.socket` is inactive.
- `sshd` uses port 22. OLS listens on loopback in the lab (8090 and 8443); a product host serves 80 and 443.
- MariaDB listens on `0.0.0.0:3306` and `[::]:3306`: `bind-address` is commented out. The firewall drops it, but it should not listen beyond the host (W558-F1).
- OLS holds a UDP socket on `0.0.0.0:49219`. The firewall drops it; its purpose is not yet explained (W558-F2).

## Boundary

- Rustiron owns one zone, `rustiron`, and sets it as the default zone, so every interface without an explicit zone uses it. It never edits the system zones.
- The zone allows only fixed services, from the enrolled policy. No plan and no request opens a port.
- `packaging/firewall-zone.py` applies the zone, run as root by the operator after enrolling the section. The installer and the updater do not call it: the zone depends only on the policy, which they do not change, and a separate step keeps the lockout check in front of the operator. The executor and the admin helper do not change the firewall.
- The diagnosis reads the firewall and reports drift.

## Enrollment

A new `firewall` section of the enrolled policy holds:

| Field | Meaning |
| --- | --- |
| `ssh_port` | The port `sshd` listens on; the zone allows it, so the operator keeps access |
| `dhcpv6_client` | Whether the host needs DHCPv6 replies (some providers configure IPv6 that way) |

The zone allows SSH on `ssh_port`, HTTP, and HTTPS, plus DNS on port 53 (UDP and TCP) when the `dns` section of [D-091](../decisions/D-091-cp05-v1-scope.md) is enrolled, plus `dhcpv6-client` when enrolled. Its target is the firewalld default, which rejects everything else.

## Apply

`packaging/firewall-zone.py --apply`:

1. Renders `/etc/firewalld/zones/rustiron.xml` from the policy. When the file, the default zone, and the allowed set already match, it reports `unchanged`.
2. Checks that firewalld runs, that the default zone is `public` or `rustiron`, that no permanent binding holds an interface with a default route in another zone, and that `sshd` listens on `ssh_port`. If not, it stops before any change, so the operator cannot be locked out.
3. Writes the file, runs `restorecon` and `firewall-cmd --check-config`, reloads, and sets `rustiron` as the default zone.
4. Checks that each interface with a default route is in the zone and that the zone allows exactly the enrolled set: services, ports, and no protocols, source ports, forward ports, rich rules, sources, ICMP blocks, or masquerade. A failed step or check sets `public` as the default zone again and removes the file.

Without `--apply` it prints the zone and the plan. `--restore --apply` is the way back: `public` as the default zone, the file removed, and a reload. The operator runs it before the uninstaller.

## Drift

[W568](../validation/S10-W568/README.md): the unprivileged diagnosis cannot ask firewalld (polkit refuses it) or read `/etc/firewalld` (root-only), nor the policy. So `packaging/firewall-zone.py --check`, run as root, reports drift instead:

- a zone file that differs from the render, or a zone that is not loaded;
- another default zone, or an interface in another zone;
- anything allowed beyond the enrolled set.

It changes nothing. When it cannot read firewalld, the diagnosis's `firewall` finding names this check.

## Findings to fix

- **W558-F1 (fixed, [W569](../validation/S10-W569/README.md)).** MariaDB listens on loopback only, through `/etc/my.cnf.d/zz-rustiron-loopback.cnf`. The installer and the updater restart MariaDB and refuse other listeners. The diagnosis reports `MariaDB network`.
- **W558-F2 (explained, W569).** The UDP socket is OLS's asynchronous DNS resolver (`Adns`), an outgoing client on an ephemeral port that no setting binds elsewhere; the zone drops unsolicited traffic to it.

## Slices

1. Done ([W559](../validation/S10-W559/README.md)): the `firewall` policy section, the zone tool, and its tests; lab proof on an overlay, including SSH kept, a wrong port refused, a reboot, and `public` restored.
2. Done ([W568](../validation/S10-W568/README.md)): drift, checked as root by `firewall-zone.py --check`.
3. Done ([W569](../validation/S10-W569/README.md)): W558-F1 fixed and W558-F2 explained.
