"""Rows where the specification says valid and the library says invalid, grouped by the library's stated policy.
Reads only the dataset (its library column was checked against the real library by scripts/compare.mjs).
Stdlib only. Usage: python3 a4_spec_vs_library.py [path-to-address-format-test-vectors]"""
import json, os, re, sys, collections

root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = json.load(open(os.path.join(root, "data/address-vectors.json")))
LIB = "multichain_memo_address_validator_1_0_0"

diff = [r for r in rows if r["spec_valid"] != r[LIB]]
print("rows:", len(rows), "| rows where spec_valid != library:", len(diff))
print("  spec true, library false:", sum(r["spec_valid"] and not r[LIB] for r in diff))
print("  spec false, library true:", sum((not r["spec_valid"]) and r[LIB] for r in diff))

def policy(note):
    # the library's own policy statement follows "Library 1.0.0:" in the notes column; keep its first clause
    clause = note.split("Library 1.0.0:", 1)[1].strip()
    clause = re.split(r";|\.\s(?=[A-Z])", clause)[0].rstrip(".")
    return clause.replace("the library ", "", 1)[:100]

groups = collections.Counter((r["family"], policy(r["notes"])) for r in diff)
print("\nfamily  rows  library policy (first clause after \"Library 1.0.0:\" in the notes column)")
for (fam, pol), n in sorted(groups.items(), key=lambda kv: (-kv[1], kv[0])):
    print(f"{fam:<7} {n:>3}   {pol}")
print("\nrows without a note:", sum(1 for r in diff if not r["notes"]))
