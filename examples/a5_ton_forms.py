"""One TON account, several valid strings. Decodes the documented user-friendly example in both base64
alphabets, checks CRC16-XMODEM, and shows what a changed flag byte does with and without a recomputed CRC.
Strings come from the dataset (ton-0001, ton-0007, ton-0002, ton-0005). Stdlib only.
Usage: python3 a5_ton_forms.py [path-to-address-format-test-vectors]"""
import base64, json, os, sys

root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..")
rows = {r["id"]: r for r in json.load(open(os.path.join(root, "data/address-vectors.json")))}

def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

def decode_friendly(s):
    """Return (flags, workchain byte, 32-byte account id) or None. Accepts base64 and base64url."""
    if len(s) != 48:
        return None
    try:
        raw = base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_"))
    except Exception:
        return None
    if len(raw) != 36 or crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big"):
        return None
    return raw[0], raw[1], raw[2:34]

url, std = rows["ton-0001"]["address"], rows["ton-0007"]["address"]
print("base64url :", url)
print("base64    :", std, "(differs from the line above only where - is +)")
a, b = decode_friendly(url), decode_friendly(std)
print("same flags, workchain and account id in both alphabets:", a == b, "| flags 0x%02x workchain %d" % (a[0], a[1]))
print("account id:", a[2].hex())
print("raw form  :", rows["ton-0005"]["address"], "-> same id:", rows["ton-0005"]["address"].split(":")[1] == a[2].hex())

nb = decode_friendly(rows["ton-0002"]["address"])
print("\nnon-bounceable form ton-0002: flags 0x%02x, same account id: %s" % (nb[0], nb[2] == a[2]))

raw = base64.urlsafe_b64decode(url.replace("+", "-").replace("/", "_"))
changed = bytes([raw[0] ^ 0x80]) + raw[1:]        # set the testnet-only bit, leave the old CRC
print("\nflag byte 0x11 -> 0x91, old CRC kept        : valid =", crc16_xmodem(changed[:34]) == int.from_bytes(changed[34:], "big"))
fixed = changed[:34] + crc16_xmodem(changed[:34]).to_bytes(2, "big")
print("flag byte 0x11 -> 0x91, CRC recomputed      : CRC ok =", crc16_xmodem(fixed[:34]) == int.from_bytes(fixed[34:], "big"),
      "-> a well-formed testnet-only string:", base64.urlsafe_b64encode(fixed).decode())
