# Pinned CycloneDX 1.6 schemas

These are unmodified official JSON schemas from the Apache-2.0 licensed
[CycloneDX specification](https://github.com/CycloneDX/specification), release
[1.6.2](https://github.com/CycloneDX/specification/releases/tag/1.6.2), commit
`e833d732337dd33aceb45ff1991f896796f1e5e7`.
The upstream license is preserved in [LICENSE](LICENSE).

| File | Official source |
| --- | --- |
| `bom-1.6.schema.json` | [BOM](https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/bom-1.6.schema.json) |
| `spdx.schema.json` | [SPDX](https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/spdx.schema.json) |
| `jsf-0.82.schema.json` | [JSF](https://raw.githubusercontent.com/CycloneDX/specification/e833d732337dd33aceb45ff1991f896796f1e5e7/schema/jsf-0.82.schema.json) |

[pin.toml](pin.toml) records release, commit and each schema's SHA-256.
`sbom_schema.py` verifies those hashes before using the schemas. Do not reformat
the vendored files. Their canonical resource IDs are registered locally; no
external reference retrieval is permitted.

1.6.2 is the latest schema correction release for the generator's existing
`specVersion: "1.6"` profile, although newer specification profiles exist.
Revisit this selection when explicitly changing the generated profile. For
an update, review the official release and references, preserve raw bytes and
license, update hashes, resolve the isolated validator lock if needed, and
rerun schema, format, reference, mutation and full project gates. See the
[tool guide](../../README.md) for setup and limitations.
