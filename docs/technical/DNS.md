# CP05 DNS: PowerDNS zones and signed record changes

This guide is the design of the DNS integration that [D-091](../decisions/D-091-cp05-v1-scope.md) sets for v1.0. [W548](../validation/S10-W548/README.md) adds it. Each slice below gets its own tests and lab proof; the sections "As implemented" record what exists.

## Boundary

- PowerDNS Authoritative answers queries. Rustiron installs it, enrolls it, and changes its zones only through signed plans. Website and DNS traffic never pass through Rustiron.
- The executor admits and journals every zone import and record change. The admin helper alone runs the fixed PowerDNS tools as root, with every value from the journal.
- No zone text, `pdnsutil` argument, or file path comes from a request. A plan names values in a closed grammar; the helper builds each command from the journaled values.
- The registrar's name server records and the external secondary (ClouDNS today) are the owner's. Rustiron prints the values to set.

## Package and confinement

The lab facts ([repository query](../validation/S10-W548/lab/00-pdns-repoquery.log), [layout](../validation/S10-W548/lab/01-pdns-layout.log)) are:

- EPEL 10 ships `pdns` and `pdns-backend-sqlite` 5.0.7 (`pdns-5.0.7-1.el10_3`), the same release as the owner's CyberPanel host. The 5.0 train gets critical updates only and ends about March 2027, so v1.0 takes the 5.1 train from PowerDNS's own repository, pinned by its signing key and limited to three packages ([D-092](../decisions/D-092-powerdns-source.md), [W549](../validation/S10-W549/README.md)). An update goes through the stack update procedure ([P06](../planning/ROADMAP.md#p06--rehearse-stack-and-product-upgrades-safely)).
- The AlmaLinux 10 policy has a `pdns` module: `pdns_server` runs as `pdns_t`, its data is `pdns_var_lib_t`, its configuration `pdns_conf_t`, and `pdns_control` runs as `pdns_control_t`. Rustiron adds no PowerDNS policy; the lab proof counts the denials.
- The service is the packaged `pdns.service`. Rustiron writes `/etc/pdns/pdns.conf` from the enrolled policy and nothing else.

## Enrollment

A new `dns` section of the enrolled policy holds:

| Field | Meaning |
| --- | --- |
| `listen` | The public addresses PowerDNS listens on, port 53, UDP and TCP |
| `name_servers` | The zone's name server host names, in order; the first is the SOA primary |
| `hostmaster` | The SOA mailbox, as a host name |
| `secondaries` | The addresses that may transfer zones and receive NOTIFY |
| `tsig_key` | The name of the TSIG key that signs transfers; the secret stays in PowerDNS's database |
| `soa` | Refresh, retry, expire, and negative TTL, each within fixed bounds |

The rendered `pdns.conf` sets `launch=gsqlite3` with the database at `/var/lib/pdns/pdns.sqlite3`, `primary=yes`, `local-address` from `listen`, and `also-notify` and `only-notify` from `secondaries`. It turns off the HTTP API, the web server, and the security-status query. `allow-axfr-ips` is empty, so only a transfer signed with the zone's TSIG key passes (W560-F2). Port 53 opens through the firewalld integration of [CP08](../planning/ROADMAP.md#cp08--operations-and-apps). The operator generates the TSIG key once on the host with `pdnsutil generate-tsig-key` and enters the secret at the secondary provider; it never enters a plan, an argument list, or a log.

## Zone ownership and the journal

A new journal version records:

- `dns_zones`: each zone Rustiron owns, by the operation that imported or created it.
- `dns_changes`: each signed record change, with its zone, plan and grant digests, and state (`intent`, `done`, `failed`).
- `dns_change_sets`: for each change, every record set's name, type, the digest it expected, its contents before, and its contents after.

A zone that is on the server but not in `dns_zones` is never changed. The journal keeps the imported zone file's digest, and the zone files stay in the intake archive, so a zone can be rebuilt from its import and its changes.

## Zone import

A signed `dns_zone_import` names the zone (an IDNA-normalised lowercase name), the SHA-256 of a canonical zone file, and its record-set count. A real zone does not fit the 8 KiB bound on signed plan bytes ([D-045](../decisions/D-045-signed-admission-bytes.md)), so the file itself goes into a root-owned intake folder, as the update recipe does: `<DNS_INTAKE_DIR>/<zone>/zone.txt`.

The executor checks before intent:

- the file's digest and count;
- each line in a closed grammar: owner name inside the zone, class `IN`, a TTL within bounds, and type SOA, NS (at the apex only), A, AAAA, CNAME, MX, TXT, SRV, or CAA, with the type's own value grammar;
- one SOA and at least one NS at the apex, and no CNAME beside other data at the same name;
- the zone is not owned and not on the server.

The helper then creates the zone as `primary`, loads the record sets, sets the SOA and the apex NS set from the enrolled policy, sets the zone's transfer and NOTIFY metadata, and checks the zone with `pdnsutil check-zone`. The mail record sets (MX, the apex TXT, `_domainkey`, `_dmarc`) are compared before and after the load.

A dry run on the PC compares a CyberPanel zone export with the live answers before the M6 import; it is part of the migration tools.

### As implemented (W551)

[W551](../validation/S10-W551/README.md) adds the contract and the zone grammar ([`zone.rs`](../../crates/contracts/src/approval/zone.rs), [`dns_import.rs`](../../crates/contracts/src/approval/dns_import.rs)):

- A canonical zone file has one record per line, `<owner.> <ttl> IN <TYPE> <rdata>`, sorted bytewise and unique, ending in a newline, at most 1 MiB and 20,000 lines of at most 4,096 bytes. Names are absolute and lowercase, with letters, digits, `-`, and `_`; a `*` may be the whole leftmost owner label. TTLs are 60 to 604,800 s. Each type has a canonical rdata grammar; TXT and CAA strings are printable ASCII with `\"` and `\\` as the only escapes, 255 bytes each.
- The SOA (exactly one) and the NS set are at the apex only, a CNAME stands alone at its owner and never at the apex, and each record set has one TTL.
- A record set's digest is the SHA-256 of its canonical lines; `dns_change` will name it. A set is a mail set when it is MX, the apex TXT, a `_domainkey` name, or `_dmarc`.
- The `dns_zone_import` plan names the zone, the file's SHA-256, and its record-set count (1 to 20,000), with fixed effects: it creates the zone and answers queries, and changes no other zone and no delegation. The grant names exactly that zone, the digest, the verb, and one operation. `rustiron-plan inspect` describes it.

### Source and service (W560)

[W560](../validation/S10-W560/README.md) proves slice 1 on a lab copy, with each step run by hand:

- PowerDNS 5.1.5 installs from [`rustiron-powerdns-auth-51.repo`](../../packaging/repos/rustiron-powerdns-auth-51.repo), and only the three named packages come from it. The key is pinned by SHA-256 and fingerprint `9FAA A557 7E8F CF62 093D 036C 1B0C 6205 FD38 0FBB`.
- `enrollment-policy.py dns` adds the section to an enrolled host's policy, and `rustiron-executor dns-config` prints the file, installed `root:pdns` 0640.
- The SQLite database comes from the packaged `schema.sqlite3.sql`. `pdns` runs as `pdns_t`, answers authoritatively, and refuses recursion.
- A lab secondary transferred with TSIG after NOTIFY; an unsigned transfer and one from an unlisted address were refused.
- 5.1 `pdnsutil` commands are `zone create`, `rrset replace ZONE NAME TYPE TTL CONTENT...` (full names), `zone increase-serial`, `tsigkey generate|activate`, and `metadata get|set`. A new zone needs `pdns_control rediscover`, and each changed name needs `pdns_control purge NAME$`.
- `pdnsutil` is `bin_t` and runs in its caller's domain, as the `pdns` user in the lab. The helper's step needs its own SELinux decision before slice 2 runs on a host.
- Open: W560-F3 (`pdns_t` denied a search of `/proc/sys/net` on `pdns_control notify`); the helper avoids `notify` (W561). PowerDNS joined the support matrix in [W562](../validation/S10-W562/README.md).

### Journal (W552)

[W552](../validation/S10-W552/README.md) adds journal v38 with `dns_imports` ([`dns.rs`](../../crates/journal/src/dns.rs)): each signed import with its zone, file digest, record-set count, and state. One import per zone may be open or done; a done import owns the zone, and a failed one frees it for a new signed import. Imports count toward the admission mark, the consumed IDs, and the signed intents. [W554](../validation/S10-W554/README.md) adds journal v39 with `dns_changes` and `dns_change_sets`: a change names an owned zone, one change per zone may be open, and each set records what it expected, what the executor read before intent (which must agree), and what it read back after.

## Record change

A signed `dns_change` names one owned zone and at most 16 record-set operations. Each operation names the owner name, the type (A, AAAA, CNAME, MX, TXT, SRV, or CAA), the TTL, the new records (at most 32, in the type's grammar) or removal, and the SHA-256 of the canonical record set it expects now, or `absent`. Plan review marks every operation on a mail record set.

Before intent, the executor reads each record set through the helper and compares its digest. The helper then, per operation, runs `pdnsutil replace-rrset` or `delete-rrset`, then `pdnsutil increase-serial` and `pdns_control purge` for each changed name, and reads the sets back. PowerDNS sends NOTIFY to the secondaries after the serial changes. A record set that changed since review refuses the whole change before intent; a failure after intent leaves the change `failed` with the record sets read back in the journal, and a signed change can restore them.

### As implemented (W553)

[W553](../validation/S10-W553/README.md) adds the contract ([`dns_change.rs`](../../crates/contracts/src/approval/dns_change.rs)). Each operation is a named object with `owner`, `type`, `expected` (a 64-hex digest or `absent`), `action` (`replace` or `remove`), and, for a replacement only, `ttl` and `records`. A replacement's records are in the type's canonical grammar, sorted and unique, 1 to 32 of them, and a CNAME has exactly one and is never at the apex. A removal of an `absent` set is refused, as is a repeated owner and type. The fixed effects change records only, never an SOA or NS set, another zone, or a delegation. `rustiron-plan inspect` lists each operation and marks mail sets `[MAIL]`.

## Helper steps (W561)

[W561](../validation/S10-W561/README.md) fixes how the admin helper runs PowerDNS's tools, from the [W560](../validation/S10-W560/README.md) facts. Nothing in it is implemented yet.

### Identity

The helper runs `pdnsutil` in a transient unit, as the certbot step of [D-059](../decisions/D-059-certificates.md) runs certbot:

- `systemd-run --wait --pipe --collect` with `User=pdns`, `Group=pdns`, `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet`, `ProtectSystem=strict`, `ReadWritePaths=/var/lib/pdns`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateNetwork=yes`, `RuntimeMaxSec=120`, and `MemoryMax=256M`.
- The argument list is fixed per step; the zone, names, types, TTLs, and records come from the journal in their canonical grammar.
- The unit runs `pdnsutil` (`bin_t`) as `unconfined_service_t` with the `pdns` user, so the database and its `-wal` and `-shm` files stay `pdns:pdns` and `pdns_var_lib_t`. The `pdns` user and the sandbox are its confinement. `pdns_t` cannot be entered from `bin_t`, and letting `rustiron_admin_t` write `pdns_var_lib_t` would give the helper's own domain the DNS database; both are rejected.
- Zone text goes on standard input (`zone load ZONE /dev/stdin`), so no file path reaches the unit.
- As built after [W564](../validation/S10-W564/README.md): no `--pipe` (F1). Standard output goes to a file in `/run/rustiron-admin`, and standard input comes from a 0644 copy of the checked bytes in that 0700 folder (F2). `pdns_control` runs in its own unit as `pdns`, the control socket's owner, without `NoNewPrivileges`, which would block its transition to `pdns_control_t`. It has no capabilities and no set-ID, and its output goes to `null` (F3, F4).

The helper runs `pdns_control` for `rediscover` after a new zone and `purge NAME$` for each changed name. It never runs `notify`, but PowerDNS's own NOTIFY makes the W560-F3 denial anyway (W564). A primary zone whose serial rose is notified by PowerDNS's own check (`xfr-cycle-interval`, 60 s by default).

### Import steps

[W563](../validation/S10-W563/README.md) implements these steps, unit-tested against a fake PowerDNS. [W564](../validation/S10-W564/README.md) proves them on a lab host: a signed import served all 13 sets with the policy's SOA and NS, a zone already on the server and a changed intake file were refused before any effect, and a replay ran nothing. After a failed import that left the zone on the server, the operator deletes it (`pdnsutil zone delete` as `pdns`, then `pdns_control rediscover`) before a new signed import. W564-F5 is fixed in W566; W560-F3 stays open.

W560 ran `zone create`, `zone set-kind`, `rrset replace`, `zone check`, `zone increase-serial`, `zone list`, and `tsigkey activate`, and saw `zone list-all` in the 5.1 help. `zone load`, `zone delete`, `rrset list`, and `rrset delete` are the expected 5.1 names, not yet run; the implementation's lab proof confirms each name before it is fixed in code.


1. **Check** (before intent): `zone list-all` must not name the zone.
2. **Load**: `zone load` from the intake file's bytes, then `zone set-kind ZONE primary`.
3. **Authority**: the apex SOA and NS sets from the enrolled policy (`rrset replace`), and `tsigkey activate ZONE KEY primary` when secondaries are enrolled.
4. **Publish**: `zone check`, `zone increase-serial`, `pdns_control rediscover`.
5. **Read back**: `zone list ZONE`, converted to canonical lines. Each set must equal the intake file's, apart from the SOA and NS sets, which must equal the policy's. The mail sets are compared one by one.

A failure after step 2 leaves the import `failed` with the zone on the server; a signed `dns_zone_import` is refused until the operator deletes it (`zone delete`), which the runbook names.

### Change steps

[W565](../validation/S10-W565/README.md) implements them, unit-tested: the read is the helper step `dns_zone_read` under the zone's done import, and the change step re-checks the stored signed plan, refuses unless every set is still what was read before intent (or settles when every set already is the intended one), and reads back. [W566](../validation/S10-W566/README.md) proves it on a lab host: replacements, an addition, and removals of mail sets took effect at once despite the cache, a stale expectation was refused before intent, a chained change and a replay worked, and the sets before and after were recorded. The zone listing crosses the helper's one-line reply as JSON (W566-F1), and `rustiron_admin` 0.5.4 fixes W564-F5.

`rrset list ZONE NAME TYPE` (or the whole `zone list`) gives each set before intent; the executor compares its digest with `expected`. The effect is `rrset replace` or `rrset delete` per operation, then `zone increase-serial`, `pdns_control purge NAME$` per changed name, and the read-back of every named set.

### Support matrix

PowerDNS is in the [support matrix](SUPPORT-MATRIX.md): series 5.1, minimum 5.1.5, end of life 2028-01-01 ([D-092](../decisions/D-092-powerdns-source.md)). [W562](../validation/S10-W562/README.md) marks it `when_installed`: the preflight, the updater, and the diagnosis check it only where the `pdns` package is installed. The diagnosis runs as the operator, who cannot read the root-only policy, so the package stands in for the enrolled section; it is never weaker, because an installed `pdns` is always checked.

## Observation

The executor observation lists each owned zone with its serial, record-set count, and the digest of its record sets, and each zone on the server that Rustiron does not own.

## Slices

1. Done ([W560](../validation/S10-W560/README.md)): the D-092 repository file and key pin, enrollment, `pdns.conf`, and service start on a lab copy; transfers to a lab secondary with TSIG.
2. Journal version, the `dns_zone_import` contract, intake checks, and the import step; lab proof with a copy of a CyberPanel zone.
3. The `dns_change` contract, the compare-and-set step, and the observation; lab proof with mail records and a secondary.
4. The [runbook](../operator/29-DNS.md) ([W567](../validation/S10-W567/README.md)) and the [M6 dry run](../validation/S10-W581/README.md) of one CyberPanel export are complete. [W583](../validation/S10-W583/README.md) adds both offline CLI plan builders.
