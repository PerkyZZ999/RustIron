# Run DNS: PowerDNS, signed zone imports, and record changes

This procedure installs PowerDNS Authoritative on an enrolled host, imports a zone with a signed `dns_zone_import`, and changes its records with a signed `dns_change` ([D-091](../decisions/D-091-cp05-v1-scope.md), [D-092](../decisions/D-092-powerdns-source.md), [DNS design](../technical/DNS.md)). It was rehearsed on lab hosts: [W560](../validation/S10-W560/README.md) covered the source, service, and TSIG transfers, [W564](../validation/S10-W564/README.md) the import, and [W566](../validation/S10-W566/README.md) the record changes.

Real DNS is the owner's: the registrar's name server records, the secondary provider (ClouDNS today), and the mail records of a cutover ([D-093](../decisions/D-093-cp06-v1-scope.md)). Change them only with the owner's go-ahead.

## Before you start

- The host runs a Rustiron build with W566 or later. Earlier builds cannot import or change zones.
- Choose the values of the `dns` section:

| Value | Meaning |
| --- | --- |
| Listen addresses | The host's public addresses for port 53, at most 4 |
| Name servers | The zone's NS host names, 2 to 4; the first is the SOA primary |
| Hostmaster | The SOA mailbox as a host name, for example `hostmaster.example.com` |
| Secondaries | The secondary provider's transfer addresses, at most 8; empty turns transfers and NOTIFY off |
| TSIG key name | For example `rustiron-axfr` |
| SOA timers | `REFRESH,RETRY,EXPIRE,NEGATIVE_TTL` within the RFC 1912 ranges, for example `10800,3600,604800,3600` |

- Run every command as root, from the source tree of the installed build.

## Step 1: install PowerDNS from the pinned source

```sh
cd /etc/pki/rpm-gpg
curl -fsS -o RPM-GPG-KEY-powerdns-FD380FBB https://repo.powerdns.com/FD380FBB-pub.asc
sha256sum -c ~/src/packaging/repos/powerdns-keys.sha256
install -o root -g root -m 0644 ~/src/packaging/repos/rustiron-powerdns-auth-51.repo /etc/yum.repos.d/
restorecon /etc/pki/rpm-gpg/RPM-GPG-KEY-powerdns-FD380FBB /etc/yum.repos.d/rustiron-powerdns-auth-51.repo
dnf install pdns pdns-backend-sqlite pdns-tools
```

- The key check must print `OK`. Otherwise, stop and remove the file.
- dnf must show the fingerprint `9FAA A557 7E8F CF62 093D 036C 1B0C 6205 FD38 0FBB` when it imports the key.
- Afterwards, `dnf repoquery --installed --qf '%{from_repo} %{name} %{evr}' pdns pdns-backend-sqlite pdns-tools` names `rustiron-powerdns-auth-51` for all three, at 5.1.5 or later.

## Step 2: enroll the `dns` section

```sh
install -d -m 0700 /root/dns-enroll
python3 packaging/enrollment-policy.py dns --policy /etc/rustiron/policy.json \
    --out /root/dns-enroll/policy.json --dns-listen 203.0.113.10 \
    --dns-name-servers ns1.example.com,ns2.example.com --dns-hostmaster hostmaster.example.com \
    --dns-secondaries 198.51.100.53 --dns-tsig-key rustiron-axfr --dns-soa 10800,3600,604800,3600
systemctl stop rustiron-coordinator.service rustiron-executor.service
install -o root -g root -m 0600 /root/dns-enroll/policy.json /etc/rustiron/policy.json
restorecon -R /etc/rustiron
systemctl start rustiron-executor.service rustiron-coordinator.service
```

The tool prints the new section and changes nothing else. Use your own values.

## Step 3: configure and start PowerDNS

```sh
/usr/libexec/rustiron/rustiron-executor dns-config > /root/dns-enroll/pdns.conf
install -o root -g pdns -m 0640 /root/dns-enroll/pdns.conf /etc/pdns/pdns.conf
python3 -c "import sqlite3; db = sqlite3.connect('/var/lib/pdns/pdns.sqlite3'); db.executescript(open('/usr/share/doc/pdns-backend-sqlite/schema.sqlite3.sql').read()); db.commit()"
chown pdns:pdns /var/lib/pdns/pdns.sqlite3
chmod 0640 /var/lib/pdns/pdns.sqlite3
restorecon -R /etc/pdns /var/lib/pdns
systemctl enable --now pdns.service
install -d -o root -g root -m 0700 /var/lib/rustiron/dns-intake
```

- Read the rendered file before you install it. It turns off the HTTP API, the web server, and PowerDNS's security-status query. It allows transfers only with the zone's TSIG key.
- `ss -Hulnp 'sport = :53'` and `ss -Htlnp 'sport = :53'` must show `pdns_server` on the listen addresses.
- Never edit `/etc/pdns/pdns.conf` by hand: any change is drift. Change the policy and render the file again.

## Step 4: the TSIG key and the firewall

```sh
runuser -u pdns -- pdnsutil tsigkey generate rustiron-axfr hmac-sha256
```

The command prints the key's secret once:

- Enter it at the secondary provider with the key name and `hmac-sha256`.
- Do not paste it into a ticket, a chat, or a file outside PowerDNS, then clear the terminal's scrollback.

Rustiron never reads or logs the secret.

Apply the firewall zone again so that it allows DNS ([page 28](28-FIREWALL-ZONE.md)): `python3 packaging/firewall-zone.py --apply`. The zone allows `dns` because the `dns` section is now enrolled.

## Import a zone

The two DNS builders produce the existing schema 1 `lab_only` plans. They read local input and write canonical plan bytes to stdout.

1. Write the zone as a canonical zone file: one record per line, `<owner.> <ttl> IN <TYPE> <rdata>`, sorted bytewise, unique, ending in a newline, with one SOA and the apex NS set. The grammar is in the [DNS design](../technical/DNS.md#as-implemented-w551).
   - From a PowerDNS listing (for example, CyberPanel's): `pdnsutil zone list example.com | python3 packaging/dns-zone-sets.py canonical > zone.txt`.
   - The tool handles root-origin names and legacy TXT formatting in PowerDNS 5.0 listings. Compare the canonical export with authoritative source answers before signing. [W581](../validation/S10-W581/README.md) shows the comparison.
   - The import replaces the SOA's names and timers and the apex NS set with the enrolled values. The file's serial is kept and then raised.
2. Copy it to the host as root, without any group or other access, at `/var/lib/rustiron/dns-intake/<zone>/zone.txt` (folder 0700, file 0600).
3. Build the plan on the operator PC. Replace the capitalized placeholders with the enrolled scope and a valid Unix-second window.

   ```sh
   rustiron plan create dns-zone-import --zone example.com --zone-file zone.txt \
       --plan-id PLAN --host-id HOST --host-epoch EPOCH --profile-digest DIGEST \
       --requester REQUESTER --valid-from START --expires-at END > plan.json
   ```

4. Compare the zone, file SHA-256, and record-set count in `rustiron-plan inspect plan.json` with the reviewed export.
5. Sign the separate grant and submit the request. The executor refuses before intent if the file differs.
6. Read the result:

| Result | Meaning |
| --- | --- |
| `succeeded` | The zone is loaded, `primary`, signed for transfers with the TSIG key, published, and read back equal to the file set by set |
| `failed`, `PRECONDITION_CHANGED` | The zone was already on the server; nothing changed |
| `failed`, another code | The import stopped after it started. The zone may be on the server, unpublished or incomplete. `journalctl -u rustiron-admin-helper` names the step's error |

After a failed import, `dns-import-status OPERATION` (coordinator and executor stopped) prints the record. Before a new signed import of the zone, check that no done import owns it, then delete the partial zone:

```sh
runuser -u pdns -- pdnsutil zone delete example.com
runuser -u pdns -- pdns_control rediscover
```

An import left `intent` by a stopped executor is settled with `rustiron-executor dns-import-reconcile OPERATION --admin-helper`, with the coordinator and executor stopped. If the zone is already on the server, the reconcile records `failed` and changes nothing; clean up as above.

## Change records

1. Read the current sets of the owned zone on the host (read only):

   ```sh
   runuser -u pdns -- pdnsutil zone list example.com | python3 packaging/dns-zone-sets.py sets example.com
   runuser -u pdns -- pdnsutil zone list example.com | python3 packaging/dns-zone-sets.py set example.com www.example.com. A
   ```

   Each set has its SHA-256; a set that does not exist is `absent`. Mail sets (MX, the apex TXT, `_domainkey`, `_dmarc`) are marked `[MAIL]`.
2. Write a JSON array in `operations.json` with 1 to 16 operations. Each contains `owner`, `type`, `expected`, and `action`. Use the digest from step 1 or `absent` for the expectation. A `replace` includes `ttl` and sorted `records` in the canonical grammar. A `remove` omits these two fields. The allowed types are A, AAAA, CNAME, MX, TXT, SRV, and CAA.

   ```json
   [{"owner":"www.example.com.","type":"A","expected":"absent","action":"replace","ttl":300,"records":["203.0.113.10"]}]
   ```

3. Build the plan on the operator PC with the same enrolled scope fields.

   ```sh
   rustiron plan create dns-change --zone example.com --operations-file operations.json \
       --plan-id PLAN --host-id HOST --host-epoch EPOCH --profile-digest DIGEST \
       --requester REQUESTER --valid-from START --expires-at END > plan.json
   ```

4. Review the output with `rustiron-plan inspect plan.json`. The review marks mail sets `[MAIL]`. A mail change needs the owner's go-ahead.
5. Sign the separate grant and submit the request.
6. Read the result:

| Result | Meaning |
| --- | --- |
| `succeeded` | Every set is the intended one; the serial rose and the changed names left PowerDNS's cache |
| Refused, `PRECONDITION_CHANGED`, no state | A set is no longer what the plan expected, or the zone is not owned or has an open change. Read the sets again and sign a new plan |
| `failed` | The change stopped after it started. `dns-change-status OPERATION` prints each set before and after |

7. Resolvers keep an old answer for its TTL, and a new name's absence for the negative TTL. The secondary follows after PowerDNS's NOTIFY, or at the zone's refresh interval.

A change left `intent` is settled with `rustiron-executor dns-change-reconcile OPERATION --admin-helper`, with the coordinator and executor stopped. It applies the change again only if every set is still as read before intent. If every set already is the intended one, it records `done` and changes nothing; otherwise it records `failed`.

## Delegate to the host

These are the owner's steps, after a zone is imported and the secondary transfers it:

1. At the secondary provider, set the primary to the host's listen address and the TSIG key. Check that the provider holds the zone with the current serial.
2. At the registrar, set the zone's name servers to the enrolled names. Add glue addresses if the names are inside the zone.
3. Check from outside: `dig +norecurse @<listen address> example.com SOA`, the same at the secondary, and `dig example.com NS` once the registrar's change is visible.

## Limits

- No DNSSEC and no provider API in v1.0 ([D-091](../decisions/D-091-cp05-v1-scope.md)).
- A transfer needs the zone's TSIG key from any address; the enrolled secondary addresses receive NOTIFY but do not restrict transfers (W560-F2, [D-091 revision](../decisions/D-091-cp05-v1-scope.md#revision-2026-11-21-w560)). The firewall allows port 53 to everyone, as an authoritative server must.
- Each NOTIFY makes two SELinux denials from `pdns_t` (W560-F3). The NOTIFY still goes out.
