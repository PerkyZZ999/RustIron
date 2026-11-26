#!/usr/bin/env python3
"""Show a zone's record sets and their digests for a signed dns_change (W567).

Reads `pdnsutil zone list ZONE` output or a canonical zone file, as the admin
helper reads it back (crates/executor/src/dns_import.rs, canonical_listing):
tabs become single spaces, the `$ORIGIN` line goes, and records are sorted
bytewise and unique. For PowerDNS 5.0 listings, make root-origin names
absolute, quote bare TXT values, and keep each quoted string in a wrapped
TXT record. The executor checks the full grammar and the record-set digests.

  dns-zone-sets.py sets ZONE [FILE]       one line per set: owner type sha256 [MAIL]
  dns-zone-sets.py set ZONE OWNER TYPE [FILE]
                                          the set's canonical lines and digest,
                                          or `absent`
  dns-zone-sets.py canonical [FILE]       the canonical zone text

FILE defaults to standard input. On the host, as root:

  runuser -u pdns -- pdnsutil zone list example.com | python3 dns-zone-sets.py sets example.com

Exit 0 prints the result; exit 1 is a refusal; exit 2 is a usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import sys

MAX_BYTES = 1024 * 1024


class Refused(ValueError):
    pass


def canonical_record(record: str, root_origin: bool) -> str:
    fields = record.split(" ", 4)
    if len(fields) != 5 or fields[2] != "IN":
        return record

    kind, value = fields[3:]
    if root_origin:
        fields[0] = fields[0].removesuffix(".") + "."
        if kind in ("NS", "CNAME", "MX", "SRV"):
            value = value.removesuffix(".") + "."
        elif kind == "SOA":
            names_and_timers = value.split(" ")
            if len(names_and_timers) == 7:
                for index in (0, 1):
                    names_and_timers[index] = names_and_timers[index].removesuffix(".") + "."
                value = " ".join(names_and_timers)

    if kind == "TXT" and not value.startswith('"'):
        if (not 1 <= len(value) <= 255 or '"' in value or "\\" in value
                or any(not " " <= char <= "~" for char in value)):
            raise Refused("unquoted TXT value is ambiguous or outside the supported grammar")
        value = f'"{value}"'
    fields[4] = value
    return " ".join(fields)


def canonical(text: str) -> str:
    listing = text.splitlines()
    root_origin = listing[:1] == ["$ORIGIN ."]
    records: list[list[str]] = []
    for line in listing[1:] if root_origin else listing:
        if not line:
            continue
        if line.startswith("$"):
            raise Refused("unsupported directive in PowerDNS listing")
        if not line.startswith((" ", "\t")):
            records.append([line.replace("\t", " ")])
            continue

        fields = records[-1][0].split(" ", 4) if records else []
        fragment = line.strip(" \t").replace("\t", " ")
        if (len(fields) != 5 or fields[2:4] != ["IN", "TXT"] or not fields[4].startswith('"')
                or len(fragment) < 2 or fragment[0] != '"' or fragment[-1] != '"'):
            raise Refused("unexpected PowerDNS record continuation")
        records[-1].append(fragment)

    lines = sorted({canonical_record(" ".join(record), root_origin) for record in records})
    return "".join(line + "\n" for line in lines)


def apex(zone: str) -> str:
    return zone.rstrip(".") + "."


def record_sets(text: str) -> dict[tuple[str, str], str]:
    """Canonical lines grouped by owner and type, in canonical order."""
    sets: dict[tuple[str, str], str] = {}
    for line in canonical(text).splitlines():
        fields = line.split(" ", 4)
        if len(fields) != 5 or fields[2] != "IN":
            raise Refused(f"not a record line: {line[:80]}")
        key = (fields[0], fields[3])
        sets[key] = sets.get(key, "") + line + "\n"
    return sets


def digest(lines: str) -> str:
    return hashlib.sha256(lines.encode()).hexdigest()


def is_mail(owner: str, kind: str, zone: str) -> bool:
    """RecordSet::is_mail in crates/contracts/src/approval/zone.rs."""
    return (kind == "MX" or (kind == "TXT" and owner == apex(zone))
            or "._domainkey." in owner or owner.startswith("_dmarc."))


def read(path: str | None) -> str:
    if path is None:
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
    else:
        with open(path, "rb") as source:
            data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise Refused("the zone is larger than 1 MiB")
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        raise Refused("the zone is not ASCII") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    sets_parser = commands.add_parser("sets")
    sets_parser.add_argument("zone")
    sets_parser.add_argument("file", nargs="?")
    set_parser = commands.add_parser("set")
    for name in ("zone", "owner", "type"):
        set_parser.add_argument(name)
    set_parser.add_argument("file", nargs="?")
    canonical_parser = commands.add_parser("canonical")
    canonical_parser.add_argument("file", nargs="?")
    args = parser.parse_args(argv)
    try:
        text = read(args.file)
        if args.command == "canonical":
            print(canonical(text), end="")
            return 0
        sets = record_sets(text)
        if args.command == "sets":
            for (owner, kind), lines in sets.items():
                mark = " [MAIL]" if is_mail(owner, kind, args.zone) else ""
                print(f"{owner} {kind} {digest(lines)}{mark}")
            return 0
        lines = sets.get((args.owner, args.type.upper()))
        if lines is None:
            print("absent")
        else:
            print(lines, end="")
            print(digest(lines))
        return 0
    except (Refused, OSError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
