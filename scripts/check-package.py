#!/usr/bin/env python3
"""Structure check of datapackage.json against the data files (no network, standard library only).

Checks the descriptor's required properties, that every resource file exists, that the declared field names equal
the CSV header, and that every cell satisfies its field's type and constraints (required, enum, pattern, unique),
primaryKey and uniqueKeys. This is a sanity check written for this repository, not the Frictionless validator.
"""
import csv
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def main():
    errors = []
    with open(os.path.join(ROOT, "datapackage.json"), encoding="utf-8") as fh:
        dp = json.load(fh)
    for key in ("name", "resources", "licenses", "version", "title", "description"):
        if key not in dp:
            errors.append("descriptor lacks %s" % key)
    if not re.fullmatch(r"[a-z0-9._-]+", dp.get("name", "")):
        errors.append("package name is not lower case url-safe")
    for res in dp["resources"]:
        path = os.path.join(ROOT, res["path"])
        if not os.path.exists(path):
            errors.append("%s: file missing" % res["name"])
            continue
        schema = res["schema"]
        names = [f["name"] for f in schema["fields"]]
        if len(set(names)) != len(names):
            errors.append("%s: duplicate field names" % res["name"])
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            header = next(reader)
            rows = list(reader)
        if header != names:
            errors.append("%s: header %s differs from the declared fields %s" % (res["name"], header, names))
            continue
        if schema.get("missingValues", [""]) != []:
            errors.append("%s: this check expects missingValues [] (empty strings are values)" % res["name"])
        seen = {f["name"]: set() for f in schema["fields"]}
        keys = {}
        for n, row in enumerate(rows, 2):
            if len(row) != len(names):
                errors.append("%s line %d: %d cells" % (res["name"], n, len(row)))
                continue
            for field, cell in zip(schema["fields"], row):
                con = field.get("constraints", {})
                t = field["type"]
                if t == "boolean" and cell not in ("true", "false"):
                    errors.append("%s line %d %s: %r is not a boolean" % (res["name"], n, field["name"], cell))
                if t == "array":
                    try:
                        value = json.loads(cell)
                        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                            raise ValueError
                    except ValueError:
                        errors.append("%s line %d %s: not a JSON array of strings" % (res["name"], n, field["name"]))
                if con.get("required") and cell == "" and t != "string":
                    errors.append("%s line %d %s: required but empty" % (res["name"], n, field["name"]))
                if "enum" in con and cell not in con["enum"]:
                    errors.append("%s line %d %s: %r not in enum" % (res["name"], n, field["name"], cell))
                if "pattern" in con and not re.search(con["pattern"], cell):
                    errors.append("%s line %d %s: %r does not match %s" % (res["name"], n, field["name"], cell, con["pattern"]))
                if con.get("unique"):
                    if cell in seen[field["name"]]:
                        errors.append("%s line %d %s: %r not unique" % (res["name"], n, field["name"], cell))
                    seen[field["name"]].add(cell)
            record = dict(zip(names, row))
            for kind, keyset in (("primaryKey", [schema.get("primaryKey")]), ("uniqueKeys", schema.get("uniqueKeys", []))):
                for key in keyset:
                    if not key:
                        continue
                    k = (kind, tuple(key), tuple(record[c] for c in key))
                    if k in keys:
                        errors.append("%s line %d: duplicate %s %s" % (res["name"], n, kind, record_key(key, record)))
                    keys[k] = n
        print("%s: %d rows, %d fields checked" % (res["name"], len(rows), len(names)))
    if errors:
        for e in errors[:30]:
            print("FAIL", e)
        print("FAIL: %d error(s)" % len(errors))
        return 1
    print("PASS: datapackage.json is consistent with the data files")
    return 0


def record_key(key, record):
    return {c: record[c] for c in key}


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
