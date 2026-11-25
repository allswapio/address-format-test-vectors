#!/usr/bin/env node
// Compare the "multichain_memo_address_validator_1_0_0" column with the library itself.
//
//   node scripts/compare.mjs <path to the library's src/index.mjs>           check the column, exit 1 on any mismatch
//   node scripts/compare.mjs <path to the library's src/index.mjs> --write   write scripts/library-results.json (input of build.py)
//
// The library is imported by the path given on the command line. Nothing is downloaded.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const libPath = args.find((a) => !a.startsWith("--"));
const write = args.includes("--write");
if (!libPath) {
  console.error("usage: node compare.mjs <path to src/index.mjs> [--write]");
  process.exit(2);
}
const abs = resolve(libPath);
const lib = await import(pathToFileURL(abs).href);
let version = "unknown";
const pkg = join(dirname(dirname(abs)), "package.json");
if (existsSync(pkg)) version = JSON.parse(readFileSync(pkg, "utf8")).version;

const rows = JSON.parse(readFileSync(join(here, "..", "data", "address-vectors.json"), "utf8"));
const COLUMN = "multichain_memo_address_validator_1_0_0";
const results = [];
const inconsistent = [];
const errors = [];
for (const row of rows) {
  let valid = false;
  try {
    const inspected = await lib.inspectAddress(row.family, row.address);
    valid = inspected?.valid === true;
    const direct = await lib.isValidAddress(row.family, row.address);
    if (direct !== valid) inconsistent.push({ id: row.id, address: row.address, inspectAddress: valid, isValidAddress: direct });
  } catch (error) {
    errors.push({ id: row.id, address: row.address, error: String(error) });
  }
  results.push({ family: row.family, address: row.address, valid });
}
const diverging = rows.filter((row, i) => row.spec_valid !== results[i].valid);
console.log(`library ${version}: ${rows.length} rows, ${diverging.length} differ from spec_valid, ${inconsistent.length} inspectAddress/isValidAddress inconsistencies, ${errors.length} exceptions`);
for (const e of errors.slice(0, 10)) console.log("exception", e);
for (const e of inconsistent.slice(0, 10)) console.log("inconsistent", e);

if (write) {
  const out = { library: "multichain-memo-address-validator", version, rows: results.length, results };
  writeFileSync(join(here, "library-results.json"), JSON.stringify(out) + "\n");
  console.log("wrote scripts/library-results.json");
  process.exit(errors.length || inconsistent.length ? 1 : 0);
}
let bad = 0;
rows.forEach((row, i) => {
  if (row[COLUMN] !== results[i].valid) {
    bad++;
    if (bad <= 20) console.log("column mismatch", row.id, JSON.stringify(row.address), "column", row[COLUMN], "library", results[i].valid);
  }
});
console.log(bad ? `FAIL: ${bad} rows where the ${COLUMN} column differs from the library` : `PASS: the ${COLUMN} column matches the library on all ${rows.length} rows`);
process.exit(bad || errors.length || inconsistent.length ? 1 : 0);
