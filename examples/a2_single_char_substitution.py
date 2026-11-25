"""Exhaustive single-character substitutions of four valid strings from the dataset.
For each string, every position is replaced by every other character of the alphabet and the
result is checked with a small validator written here from the specifications
(Base58, Base58Check, EIP-55 with Keccak-256). Stdlib only.
Usage: python3 a2_single_char_substitution.py [path-to-address-format-test-vectors]"""
import hashlib, json, os, sys

root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = {r["id"]: r for r in json.load(open(os.path.join(root, "data/address-vectors.json")))}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)          # ValueError for a character outside the alphabet
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + raw

def sol_valid(s):                          # Solana: Base58 that decodes to exactly 32 bytes
    try:
        return len(b58decode(s)) == 32
    except ValueError:
        return False

def p2pkh_valid(s):                        # Bitcoin P2PKH: version 0x00, 20-byte hash, double SHA-256 checksum
    try:
        b = b58decode(s)
    except ValueError:
        return False
    return (len(b) == 25 and b[0] == 0 and
            hashlib.sha256(hashlib.sha256(b[:21]).digest()).digest()[:4] == b[21:])

# --- Keccak-256 (the original padding 0x01, not SHA3's 0x06), for EIP-55 ---
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M = (1 << 64) - 1
def rol(x, n): return ((x << n) | (x >> (64 - n))) & M if n else x

def keccak256(data):
    A = [[0] * 5 for _ in range(5)]
    buf = bytearray(data) + b"\x01"
    buf += b"\0" * ((-len(buf)) % 136)
    buf[-1] |= 0x80
    for off in range(0, len(buf), 136):
        for i in range(17):
            A[i % 5][i // 5] ^= int.from_bytes(buf[off + 8 * i: off + 8 * i + 8], "little")
        for rc in RC:
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rol(C[(x + 1) % 5], 1) for x in range(5)]
            A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            Bm = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    Bm[y][(2 * x + 3 * y) % 5] = rol(A[x][y], ROT[x][y])
            A = [[Bm[x][y] ^ (~Bm[(x + 1) % 5][y] & Bm[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            A[0][0] ^= rc
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))[:32]

assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"

HEX = "0123456789abcdef"
def evm_valid(s):                          # 0x + 40 hex; one case only: accepted; mixed case: must equal EIP-55
    if len(s) != 42 or s[:2] != "0x" or any(c not in "0123456789abcdefABCDEF" for c in s[2:]):
        return False
    d = s[2:]
    if d == d.lower() or d == d.upper():
        return True
    h = keccak256(d.lower().encode()).hex()
    return all(c == (c.upper() if int(h[i], 16) >= 8 else c.lower()) for i, c in enumerate(d))

def run(label, s, alphabet, valid):
    assert valid(s), label
    total = ok = 0
    for i, old in enumerate(s):
        for new in alphabet:
            if new == old:
                continue
            total += 1
            ok += valid(s[:i] + new + s[i + 1:])
    print(f"{label:<44} {total:>5} variants, {ok:>4} still valid")

evm55 = rows["evm-0001"]["address"]
run("Solana " + rows["sol-0032"]["id"], rows["sol-0032"]["address"], B58, sol_valid)
run("Bitcoin P2PKH " + rows["btc-0001"]["id"], rows["btc-0001"]["address"], B58, p2pkh_valid)
run("EVM lower case (evm-0001 lowered)", evm55.lower(), HEX, evm_valid)
run("EVM EIP-55 mixed case (evm-0001)", evm55, HEX + HEX.upper(), evm_valid)
# Only the letters of evm-0001 carry checksum information:
print("letters in evm-0001:", sum(c.isalpha() for c in evm55[2:]), "of 40 digits")
