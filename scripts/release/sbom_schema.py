#!/usr/bin/env python3
"""Validate a bounded SBOM against pinned official CycloneDX 1.6 schemas offline."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tomllib


SCHEMAS = Path(__file__).resolve().parent / "schemas/cyclonedx-1.6"
ROOT_SCHEMA = "bom-1.6.schema.json"
SCHEMA_URI = "http://cyclonedx.org/schema/" + ROOT_SCHEMA
MAX_BOM_BYTES = 4 * 1024 * 1024


class SchemaSetupError(Exception):
    """Pinned schemas or required validator capabilities are unavailable."""


class InvalidBom(Exception):
    """Input is not a supported, schema-valid SBOM."""


def load_schemas(directory=SCHEMAS):
    pin = tomllib.loads((SCHEMAS / "pin.toml").read_text())
    documents = {}
    for name, expected in pin["sha256"].items():
        content = (directory / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != expected:
            raise SchemaSetupError("pinned schema checksum differs")
        documents[name] = json.loads(content)
    return documents


def formats_in(value):
    if isinstance(value, dict):
        if isinstance(value.get("format"), str):
            yield value["format"]
        for child in value.values():
            yield from formats_in(child)
    elif isinstance(value, list):
        for child in value:
            yield from formats_in(child)


def schema_registry(documents):
    from referencing import Registry, Resource
    from referencing.exceptions import NoSuchResource

    def refuse_retrieval(uri):
        raise NoSuchResource(ref=uri)

    resources = ((schema["$id"], Resource.from_contents(schema)) for schema in documents.values())
    return Registry(retrieve=refuse_retrieval).with_resources(resources)


def make_validator():
    from jsonschema import Draft7Validator, FormatChecker
    from jsonschema.exceptions import SchemaError

    documents = load_schemas()
    try:
        for schema in documents.values():
            Draft7Validator.check_schema(schema)
    except SchemaError as error:
        raise SchemaSetupError("invalid pinned schema") from error
    formats = set(formats_in(list(documents.values())))
    if not formats.issubset(FormatChecker().checkers):
        raise SchemaSetupError("required format checker is missing")
    return Draft7Validator(
        documents[ROOT_SCHEMA], registry=schema_registry(documents),
        format_checker=FormatChecker(formats=sorted(formats)),
    )


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise InvalidBom("duplicate JSON member")
        result[name] = value
    return result


def reject_number(_value):
    raise InvalidBom("non-finite JSON number")


def load_document(path):
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise InvalidBom("input must be a regular file without symlinks")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise InvalidBom("input must be a regular file")
            content = source.read(MAX_BOM_BYTES + 1)
        if len(content) > MAX_BOM_BYTES:
            raise InvalidBom("input exceeds the 4 MiB limit")
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_number)
    except (OSError, UnicodeError, ValueError, RecursionError) as error:
        raise InvalidBom("expected a readable UTF-8 JSON SBOM") from error


def validate(document):
    from referencing.exceptions import Unresolvable

    if (not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX"
            or document.get("specVersion") != "1.6"):
        raise InvalidBom("expected CycloneDX specVersion 1.6")
    declared = document.get("$schema")
    if declared is not None and declared not in (SCHEMA_URI, SCHEMA_URI.replace("http:", "https:")):
        raise InvalidBom("document declares an unsupported schema")
    try:
        error = next(make_validator().iter_errors(document), None)
    except Unresolvable as error:
        raise SchemaSetupError("schema reference is not pinned") from error
    if error is not None:
        location = json.dumps(list(error.absolute_schema_path), ensure_ascii=True)
        raise InvalidBom(f"schema rule {error.validator} at schema path {location}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    arguments = parser.parse_args()
    try:
        validate(load_document(arguments.sbom))
    except InvalidBom as error:
        print("INVALID: " + str(error))
        return 1
    except (SchemaSetupError, ImportError, OSError, ValueError, KeyError, TypeError, RecursionError):
        print("ERROR: schema or validator setup invalid; follow scripts/release/README.md setup", file=sys.stderr)
        return 2
    print("PASS: pinned CycloneDX 1.6 schema and all declared formats")
    return 0


if __name__ == "__main__":
    sys.exit(main())
