// Run every distinct spec-valid string of the dataset through the library for all 12 families.
// The library is stricter than the specifications (README, "Where the library differs"), so this
// finds the overlaps that survive that stricter filter. Usage: node a1b_library_cross_check.mjs [dataset-dir]
import { readFileSync } from "node:fs";
import { inspectAddress } from "multichain-memo-address-validator";
const root = process.argv[2] ?? new URL("../", import.meta.url).pathname;
const rows = JSON.parse(readFileSync(`${root}/data/address-vectors.json`, "utf8"));
const families = ["evm", "btc", "ltc", "doge", "bch", "zec", "sol", "tron", "near", "ton", "xrp", "stellar"];
const strings = [...new Set(rows.filter((r) => r.spec_valid).map((r) => r.address))];
const overlaps = new Map();
for (const s of strings) {
  const ok = [];
  for (const f of families) if ((await inspectAddress(f, s))?.valid) ok.push(f);
  if (ok.length > 1) overlaps.set(s, ok);
}
console.log("distinct spec-valid strings:", strings.length);
console.log("accepted by the library under more than one family:", overlaps.size);
const kinds = {};
for (const ok of overlaps.values()) kinds[ok.join("+")] = (kinds[ok.join("+")] ?? 0) + 1;
console.log(kinds);
for (const [s, ok] of overlaps) if (ok.includes("near") && !ok.includes("evm")) console.log("  ", s.slice(0, 50), ok.join(","));
