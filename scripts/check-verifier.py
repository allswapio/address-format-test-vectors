#!/usr/bin/env python3
"""Mutation check of verify.py: flips ten spec_valid labels (one at a time, in both the CSV and the JSON file)
and requires verify.py to fail on each. The ten rows are chosen with a fixed seed.

    python3 scripts/check-verifier.py
"""
import csv
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
SEED = 20261126
COUNT = 10


def main():
    with open(os.path.join(DATA, "address-vectors.json"), encoding="utf-8") as fh:
        rows = json.load(fh)
    with open(os.path.join(DATA, "address-vectors.csv"), encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        csv_rows = list(reader)
    col = header.index("spec_valid")
    picks = random.Random(SEED).sample(range(len(rows)), COUNT)
    failures = 0
    for k, i in enumerate(picks, 1):
        tmp = tempfile.mkdtemp(prefix="verifier-check-")
        try:
            for name in os.listdir(DATA):
                shutil.copy(os.path.join(DATA, name), tmp)
            j2 = json.loads(json.dumps(rows))
            j2[i]["spec_valid"] = not j2[i]["spec_valid"]
            with open(os.path.join(tmp, "address-vectors.json"), "w", encoding="utf-8") as fh:
                json.dump(j2, fh, ensure_ascii=False, indent=1)
            c2 = [list(r) for r in csv_rows]
            c2[i][col] = "false" if c2[i][col] == "true" else "true"
            with open(os.path.join(tmp, "address-vectors.csv"), "w", encoding="utf-8", newline="") as fh:
                w = csv.writer(fh, lineterminator="\n")
                w.writerow(header)
                w.writerows(c2)
            proc = subprocess.run([sys.executable, "-B", os.path.join(HERE, "verify.py"), "--data", tmp], capture_output=True, text=True)
            caught = proc.returncode == 1 and ("spec_valid mismatch: %s " % rows[i]["id"]) in proc.stdout
            print("%2d. %s flipped %s -> %s: verify.py %s" % (k, rows[i]["id"], rows[i]["spec_valid"], j2[i]["spec_valid"], "FAILED as required" if caught else "DID NOT FAIL"))
            failures += 0 if caught else 1
        finally:
            shutil.rmtree(tmp)
    print("PASS: verify.py failed on all %d flipped labels" % COUNT if not failures else "FAIL: %d flipped labels went undetected" % failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
