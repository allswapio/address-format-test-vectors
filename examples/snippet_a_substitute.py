# Replace each character of a valid string with every other Base58 character; count what is still valid.
import hashlib
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    return b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")

def solana_ok(s):                       # no checksum: only the decoded length matters
    return len(decode(s)) == 32

def bitcoin_p2pkh_ok(s):                # version 0x00 + 20 bytes + 4 checksum bytes
    b = decode(s)
    return len(b) == 25 and b[0] == 0 and hashlib.sha256(hashlib.sha256(b[:21]).digest()).digest()[:4] == b[21:]

def survivors(s, ok):
    n = sum(ok(s[:i] + c + s[i + 1:]) for i in range(len(s)) for c in B58 if c != s[i])
    return n, len(s) * 57

print("Solana  ", survivors("FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z", solana_ok))
print("Bitcoin ", survivors("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", bitcoin_p2pkh_ok))
