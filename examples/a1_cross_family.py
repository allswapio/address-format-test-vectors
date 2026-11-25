"""Which strings in the dataset are well formed under more than one family?
Stdlib only. Usage: python3 a1_cross_family.py [path-to-address-format-test-vectors]"""
import json, sys, collections, os
root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = json.load(open(os.path.join(root, "data/address-vectors.json")))

by_string = collections.defaultdict(set)
for r in rows:
    if r["spec_valid"]:
        by_string[r["address"]].add(r["family"])
multi = {a: sorted(f) for a, f in by_string.items() if len(f) > 1}
print("rows:", len(rows), "| spec_valid=true rows:", sum(r["spec_valid"] for r in rows),
      "| distinct valid strings:", len(by_string))
print("strings with spec_valid=true under more than one family row:", len(multi))
for a, f in sorted(multi.items(), key=lambda kv: len(kv[1]), reverse=True):
    print(f"  {a[:46]:<46} {','.join(f)}")

# Rows whose reason is other_family: a valid address of one family given to another
of = [r for r in rows if r["reason"] == "other_family"]
print("\nrows rejected only because the string belongs to another family:", len(of))
print("  by the family that rejects it:", dict(collections.Counter(r["family"] for r in of)))

# The dataset's own ambiguity table, for comparison
amb = json.load(open(os.path.join(root, "data/cross-family-ambiguities.json")))
print("\ncross-family-ambiguities.json:", len(amb), "entries;",
      dict(collections.Counter(a["kind"] for a in amb)))
