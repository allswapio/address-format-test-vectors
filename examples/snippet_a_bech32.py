# Which Bech32 constant does a string satisfy? (BIP-173 / BIP-350). Stdlib only.
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

def residue(s):
    s = s.lower()
    hrp, data = s[:s.rfind("1")], [CHARSET.index(c) for c in s[s.rfind("1") + 1:]]
    chk = 1
    for v in [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if (top >> i) & 1 else 0
    return chk, data[0]

for s in ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",   # BIP-173 example, witness v0
          "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",  # BIP-350 example, witness v1
          "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd"]: # BIP-350 invalid: v1 with the Bech32 constant
    r, version = residue(s)
    print(f"{s[:20]}...  residue {r:#x}  witness v{version}  ->", {1: "Bech32", 0x2BC830A3: "Bech32m"}.get(r, "no valid checksum"))
