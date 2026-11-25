"""Single-character edit rows of the dataset: how many stay valid, by family.
The eight rules below are the generic one-character edits (substitute, insert, drop, swap, extend, truncate).
Counts are rows chosen by the dataset's build rules (at most 3 per rule and family), not a random sample.
Stdlib only. Usage: python3 a6_mutation_rows.py [path-to-address-format-test-vectors]"""
import json, os, re, sys, collections
root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = json.load(open(os.path.join(root, "data/address-vectors.json")))
RULES = {"extend_one_char", "substitute_last_char", "substitute_payload_char", "swap_adjacent_chars",
         "truncate_last_char", "insert_char", "drop_first_payload_char", "substitute_first_payload_char"}
tot, ok = collections.Counter(), collections.Counter()
for r in rows:
    m = re.match(r"Mutation rule (\w+)", r["source"])
    if r["origin"] == "mutation" and m and m.group(1) in RULES:
        tot[r["family"]] += 1
        ok[r["family"]] += r["spec_valid"]
print("family  rows  still valid")
for f in sorted(tot):
    print(f"{f:<8}{tot[f]:>4}  {ok[f]:>4}")
print(f"total   {sum(tot.values()):>4}  {sum(ok.values()):>4}")
print("mutation rows overall:", sum(1 for r in rows if r["origin"] == "mutation"),
      "| of them spec_valid:", sum(1 for r in rows if r["origin"] == "mutation" and r["spec_valid"]))
