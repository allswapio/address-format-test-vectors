"""Bech32 (BIP-173) and Bech32m (BIP-350) differ in one constant. This script computes the checksum
residue of the dataset's segwit and TEX rows and shows which constant each string satisfies.
Stdlib only. Usage: python3 a3_bech32_constants.py [path-to-address-format-test-vectors]"""
import json, os, sys

root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = json.load(open(os.path.join(root, "data/address-vectors.json")))

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
BECH32, BECH32M = 1, 0x2BC830A3

def polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if (top >> i) & 1 else 0
    return chk

def residue(s):
    """Return (hrp, data values, residue) or None if s is not a well-formed Bech32 string."""
    if s.lower() != s and s.upper() != s:
        return None                                     # mixed case is never allowed
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90 or any(c not in CHARSET for c in s[pos + 1:]):
        return None
    hrp, data = s[:pos], [CHARSET.index(c) for c in s[pos + 1:]]
    return hrp, data, polymod([ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data)

def verdict(address):
    res = residue(address)
    if res is None:
        return "not Bech32"
    hrp, data, r = res
    const = {BECH32: "Bech32", BECH32M: "Bech32m"}.get(r)
    if const is None:
        return "bad checksum"
    if hrp == "tex":                                    # ZIP-320: no witness version, always Bech32m
        return f"{const} constant, TEX: " + ("ok" if const == "Bech32m" else "WRONG: ZIP-320 needs Bech32m")
    version = data[0]
    want = "Bech32" if version == 0 else "Bech32m"
    note = "ok" if const == want else f"WRONG: witness v{version} needs {want}"
    return f"{const} constant, witness v{version}: {note}"

print(f"Bech32 constant {BECH32:#x}, Bech32m constant {BECH32M:#x}\n")
shown = [r for r in rows if r["reason"] == "wrong_checksum_constant"]
print(f"{len(shown)} dataset rows with reason wrong_checksum_constant:")
for r in shown:
    print(f"  {r['id']}  {r['address'][:44]:<44}  {verdict(r['address'])}")

print("\nThe BIP-173 / BIP-350 valid examples, same function:")
for r in rows:
    if r["family"] in ("btc",) and r["origin"] == "specification" and r["spec_valid"] and r["address"].lower().startswith("bc1"):
        print(f"  {r['id']}  {r['address'][:44]:<44}  {verdict(r['address'])}")
