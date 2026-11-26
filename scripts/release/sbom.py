#!/usr/bin/env python3
"""P09 SBOM: a CycloneDX 1.6 JSON document built from the locked Cargo graph.

  sbom.py generate OUT.json   write the SBOM (cargo metadata --locked --offline)
  sbom.py check SBOM.json     match unique Cargo identities and checksums to
                              Cargo.lock, and SQLite to native/sqlite.toml
  sbom.py selftest            exercise missing, added, changed and duplicate inputs

The output is deterministic: there is no timestamp or random serial
number. It records the native SQLite input from native/sqlite.toml, and no
new tool is needed.
"""
import copy
import hashlib
import json
import pathlib
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def lock_packages():
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    return {(p["name"], p["version"]): p.get("checksum") for p in lock["package"]}


def sqlite_component():
    pin = tomllib.loads((ROOT / "native/sqlite.toml").read_text())
    return {
        "type": "library", "bom-ref": f"native/sqlite@{pin['version']}",
        "name": "sqlite", "version": pin["version"],
        "licenses": [{"license": {"name": "blessing (public domain)"}}],
        "hashes": [{"alg": "SHA3-256", "content": pin["archive_sha3_256"]}],
        "externalReferences": [{"type": "distribution", "url": pin["url"]}],
        "properties": [{"name": "rustiron:source", "value": "native/sqlite.toml"}],
    }


def generate():
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)
    sums = lock_packages()
    comps = []
    for p in sorted(meta["packages"], key=lambda p: (p["name"], p["version"])):
        c = {"type": "library", "bom-ref": f"pkg:cargo/{p['name']}@{p['version']}",
             "name": p["name"], "version": p["version"],
             "purl": f"pkg:cargo/{p['name']}@{p['version']}"}
        if p.get("license"):
            c["licenses"] = [{"expression": p["license"]}]
        s = sums.get((p["name"], p["version"]))
        if s:
            c["hashes"] = [{"alg": "SHA-256", "content": s}]
        if p.get("source") is None:
            c["type"] = "application" if any(t["kind"] == ["bin"] for t in p["targets"]) else "library"
            c["properties"] = [{"name": "rustiron:source", "value": "workspace"}]
        comps.append(c)
    comps.append(sqlite_component())
    lock_sha = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": "rustiron",
                                       "version": meta["packages"] and next(
                                           p["version"] for p in meta["packages"] if p["name"] == "rustiron-core")},
                         "properties": [{"name": "rustiron:cargo_lock_sha256", "value": lock_sha}]},
             "components": comps}


def check_components(components):
    errs = []
    want = lock_packages()
    got = set()
    native = []
    for component in components:
        if not isinstance(component, dict):
            errs.append("component must be an object")
            continue
        purl = component.get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:cargo/"):
            native.append(component)
            continue
        name, version = component.get("name"), component.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            errs.append("Cargo component needs a name and version")
            continue
        identity = (name, version)
        expected_reference = f"pkg:cargo/{name}@{version}"
        if purl != expected_reference or component.get("bom-ref") != expected_reference:
            errs.append("Cargo component reference differs from its identity")
        if identity in got:
            errs.append("duplicate Cargo component identity")
        got.add(identity)
        checksum = want.get(identity)
        hashes = [{"alg": "SHA-256", "content": checksum}] if checksum else []
        if component.get("hashes", []) != hashes:
            errs.append("Cargo component checksums differ from Cargo.lock")
    for name, version in sorted(set(want) - got):
        errs.append(f"missing from SBOM: {name} {version}")
    if got - set(want):
        errs.append("SBOM contains components not in Cargo.lock")
    if native != [sqlite_component()]:
        errs.append("expected exactly the pinned SQLite component and no other native components")
    return errs


def check_lock_provenance(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("properties"), list):
        return ["missing Cargo.lock provenance"]
    properties = metadata["properties"]
    if not all(isinstance(prop, dict) for prop in properties):
        return ["invalid Cargo.lock provenance"]
    name = "rustiron:cargo_lock_sha256"
    matches = [prop for prop in properties if prop.get("name") == name]
    lock_sha = hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()
    if matches != [{"name": name, "value": lock_sha}]:
        return ["expected one matching Cargo.lock provenance property"]
    return []


def check(bom):
    if not isinstance(bom, dict):
        return ["SBOM must be an object"]
    errs = []
    if (bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.6"
            or type(bom.get("version")) is not int or bom["version"] != 1):
        errs.append("unsupported SBOM format or version")
    components = bom.get("components")
    if not isinstance(components, list):
        errs.append("components must be an array")
    else:
        errs.extend(check_components(components))
    errs.extend(check_lock_provenance(bom.get("metadata")))
    return errs


def selftest():
    good = generate()
    cases = [("generated", good, False)]
    b = copy.deepcopy(good); b["components"] = [c for c in b["components"] if c["name"] != "sha2"]
    cases.append(("dropped sha2", b, True))
    b = copy.deepcopy(good); b["components"].append({"name": "evil", "version": "1.0.0", "purl": "pkg:cargo/evil@1.0.0"})
    cases.append(("added evil", b, True))
    b = copy.deepcopy(good)
    for c in b["components"]:
        if c.get("hashes") and c.get("purl", "").startswith("pkg:cargo/"):
            c["hashes"][0]["content"] = "0" * 64; break
    cases.append(("altered checksum", b, True))
    b = copy.deepcopy(good)
    b["components"] = [c for c in b["components"] if c["name"] != "sqlite"]
    cases.append(("dropped SQLite", b, True))
    b = copy.deepcopy(good)
    b["components"][-1]["hashes"][0]["content"] = "0" * 64
    cases.append(("altered SQLite checksum", b, True))
    b = copy.deepcopy(good)
    b["components"].append(copy.deepcopy(b["components"][0]))
    cases.append(("duplicate Cargo component", b, True))
    bad = 0
    for name, bom, want_fail in cases:
        errs = check(bom); ok = bool(errs) == want_fail; bad += not ok
        print(f"{'ok ' if ok else 'BAD'} {name}: {'FAIL' if errs else 'PASS'} {errs[:1]}")
    return bad == 0


def main(a):
    if len(a) == 3 and a[1] == "generate":
        pathlib.Path(a[2]).write_text(json.dumps(generate(), indent=1, sort_keys=True) + "\n")
        return 0
    if len(a) == 3 and a[1] == "check":
        try:
            errs = check(json.loads(pathlib.Path(a[2]).read_text()))
        except (OSError, UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError, RecursionError):
            errs = ["cannot read SBOM JSON or trusted input pins"]
        for e in errs: print("FAIL:", e)
        print("sbom check:", "FAIL" if errs else "PASS"); return 1 if errs else 0
    if len(a) == 2 and a[1] == "selftest":
        return 0 if selftest() else 1
    print(__doc__); return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
