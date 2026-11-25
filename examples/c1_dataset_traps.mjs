// Eight rows of the dataset, run through the library. Prints what the specification says (spec_valid in the
// dataset) next to what the library returns. Node.js 22. Usage: node c1_dataset_traps.mjs [dataset-dir]
// After `npm install multichain-memo-address-validator` the import below works as written.
import { readFileSync } from "node:fs";
import { inspectAddress } from "multichain-memo-address-validator";

const root = process.argv[2] ?? new URL("../", import.meta.url).pathname;
const rows = new Map(JSON.parse(readFileSync(`${root}/data/address-vectors.json`, "utf8")).map((r) => [r.id, r]));

const ids = ["btc-0013", "bch-0002", "ltc-0013", "evm-0049", "xrp-0008", "ton-0003", "btc-0098", "xrp-0111"];
for (const id of ids) {
  const row = rows.get(id);
  const got = await inspectAddress(row.family, row.address);
  console.log(
    `${id}  ${JSON.stringify(row.address).slice(0, 34).padEnd(34)}  spec: ${String(row.spec_valid).padEnd(5)}  library: ${String(got.valid).padEnd(5)}  pitfall: ${got.pitfall}`,
  );
}
