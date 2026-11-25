// A check written from BIP-173 and BIP-350 (no library code), compared with the dataset's label and with the
// library on every Bitcoin row that starts with bc1 / BC1. Node.js 22.
// Usage: node c2_bech32_spec_check.mjs [dataset-dir]
import { readFileSync } from "node:fs";
import { inspectAddress } from "multichain-memo-address-validator";

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

/** BIP-173 / BIP-350 segwit address for the human-readable part `hrp`. */
export function segwitValid(address, hrp = "bc") {
  if (address !== address.toLowerCase() && address !== address.toUpperCase()) return false; // mixed case
  const s = address.toLowerCase();
  const pos = s.lastIndexOf("1");
  if (pos < 1 || pos + 7 > s.length || s.length > 90 || s.slice(0, pos) !== hrp) return false;
  const data = [...s.slice(pos + 1)].map((c) => CHARSET.indexOf(c));
  if (data.includes(-1)) return false;
  const hrpValues = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat(0, [...hrp].map((c) => c.charCodeAt(0) & 31));
  const residue = polymod([...hrpValues, ...data]);
  const version = data[0];
  if (version > 16) return false;
  if (residue !== (version === 0 ? 1 : 0x2bc830a3)) return false;       // the two constants
  let acc = 0, bits = 0;
  const program = [];
  for (const w of data.slice(1, -6)) {                                   // 5-bit groups to bytes
    acc = (acc << 5) | w; bits += 5;
    if (bits >= 8) { bits -= 8; program.push((acc >> bits) & 255); acc &= (1 << bits) - 1; }
  }
  if (bits >= 5 || acc !== 0) return false;                               // padding rule
  if (program.length < 2 || program.length > 40) return false;
  return version !== 0 || program.length === 20 || program.length === 32;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const root = process.argv[2] ?? new URL("../", import.meta.url).pathname;
  const rows = JSON.parse(readFileSync(`${root}/data/address-vectors.json`, "utf8")).filter(
    (r) => r.family === "btc" && /^bc1/i.test(r.address),
  );
  let specAgree = 0, libAgree = 0;
  const libOnlyFalse = [];
  for (const r of rows) {
    const mine = segwitValid(r.address);
    const lib = (await inspectAddress("btc", r.address)).valid;
    specAgree += mine === r.spec_valid;
    libAgree += lib === r.spec_valid;
    if (mine !== r.spec_valid) console.log("my check differs from the label:", r.id, r.address);
    if (lib !== r.spec_valid) libOnlyFalse.push(`${r.id} (${r.reason || "valid"}; ${r.address.slice(0, 14)}...)`);
  }
  console.log(`rows starting with bc1/BC1: ${rows.length}`);
  console.log(`spec-based check agrees with the dataset label: ${specAgree}/${rows.length}`);
  console.log(`library agrees with the dataset label:          ${libAgree}/${rows.length}`);
  console.log("rows where the library differs from the specification:");
  for (const x of libOnlyFalse) console.log("  " + x);
}
