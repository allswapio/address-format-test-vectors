#!/usr/bin/env python3
"""Build the "Blockchain address format test vectors" dataset.

Deterministic, Python 3 standard library only, no network access, no randomness.
Every output byte depends only on this file and on scripts/library-results.json
(the optional record of the library column written by scripts/compare.mjs).

Layout of this file
  1. encoders and decoders written from the specifications
  2. classify(): the specification reading of every family (valid / reason / network)
  3. vector tables (published values, deterministic re-encodings, mutation rules)
  4. writers (CSV, JSON, Frictionless metadata, documentation)

spec_valid in the output is a property of the cited specification. The labels of
published vectors are typed in by hand from the cited page; classify() must agree
with them (the build stops otherwise). Labels of derived and mutated rows come from
classify(). scripts/verify.py recomputes every label with a second, independent
implementation.
"""
import base64
import csv
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VERSION = "1.0.0"
RELEASE_DATE = "2026-11-26"
LIB_COLUMN = "multichain_memo_address_validator_1_0_0"
SEED_NOTE = "No randomness is used. Mutation positions are fixed by the rules documented in README.md."

# ---------------------------------------------------------------------------
# 1. encoders and decoders
# ---------------------------------------------------------------------------
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
RB58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BECH32M_CONST = 0x2BC830A3


def b58dec(s, alpha=B58):
    n = 0
    for ch in s:
        i = alpha.find(ch)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip(alpha[0]))
    return b"\x00" * pad + body


def b58enc(b, alpha=B58):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alpha[r] + out
    pad = len(b) - len(b.lstrip(b"\x00"))
    return alpha[0] * pad + out


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_enc(version, payload, alpha=B58):
    raw = bytes(version) + payload
    return b58enc(raw + sha256d(raw)[:4], alpha)


def b58check_dec(s, alpha=B58):
    raw = b58dec(s, alpha)
    if raw is None or len(raw) < 5:
        return None
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        return None
    return raw[:-4]


def convertbits(data, frombits, tobits, pad):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or (v >> frombits):
            return None
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_encode(hrp, words, const):
    values = hrp_expand(hrp) + words
    mod = bech32_polymod(values + [0] * 6) ^ const
    chk = [(mod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH[w] for w in words + chk)


def segwit_encode(hrp, ver, prog, const=None):
    if const is None:
        const = 1 if ver == 0 else BECH32M_CONST
    return bech32_encode(hrp, [ver] + convertbits(list(prog), 8, 5, True), const)


def cash_polymod(values):
    gen = [0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470]
    c = 1
    for d in values:
        c0 = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for i in range(5):
            if (c0 >> i) & 1:
                c ^= gen[i]
    return c ^ 1


CASH_SIZES = {20: 0, 24: 1, 28: 2, 32: 3, 40: 4, 48: 5, 56: 6, 64: 7}


def cash_encode(prefix, typ, h, with_prefix=True):
    ver = (typ << 3) | CASH_SIZES[len(h)]
    words = convertbits([ver] + list(h), 8, 5, True)
    pre = [ord(c) & 31 for c in prefix] + [0]
    mod = cash_polymod(pre + words + [0] * 8)
    chk = [(mod >> 5 * (7 - i)) & 31 for i in range(8)]
    body = "".join(BECH[w] for w in words + chk)
    return (prefix + ":" + body) if with_prefix else body


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def b32dec_strict(s):
    """RFC 4648 base32, upper case, no padding; unused trailing bits must be zero."""
    acc = 0
    bits = 0
    out = bytearray()
    for ch in s:
        i = B32.find(ch)
        if i < 0:
            return None
        acc = (acc << 5) | i
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 255)
            acc &= (1 << bits) - 1
    if acc != 0:
        return None
    return bytes(out)


def b32enc(b):
    acc = 0
    bits = 0
    out = ""
    for byte in b:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out += B32[(acc >> bits) & 31]
            acc &= (1 << bits) - 1
    if bits:
        out += B32[(acc << (5 - bits)) & 31]
    return out


def strkey_enc(vbyte, payload):
    raw = bytes([vbyte]) + payload
    crc = crc16(raw)
    return b32enc(raw + bytes([crc & 255, crc >> 8]))


def _rc_bit(t):
    t %= 255
    if t == 0:
        return 1
    r = 1
    for _ in range(t):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


_KECCAK_RC = [sum(_rc_bit(j + 7 * i) << ((1 << j) - 1) for j in range(7)) for i in range(24)]
_KECCAK_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def keccak256(data):
    rate = 136
    buf = bytearray(data) + b"\x01"
    while len(buf) % rate:
        buf.append(0)
    buf[-1] |= 0x80
    a = [0] * 25
    for off in range(0, len(buf), rate):
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(buf[off + 8 * i: off + 8 * i + 8], "little")
        for rc in _KECCAK_RC:
            c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            a = [a[i] ^ d[i % 5] for i in range(25)]
            b = [0] * 25
            for x in range(5):
                for y in range(5):
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _KECCAK_ROT[x][y])
            a = [b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]) for y in range(5) for x in range(5)]
            a[0] ^= rc
    return b"".join(a[i].to_bytes(8, "little") for i in range(4))


assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def eip55(hex40):
    low = hex40.lower()
    h = keccak256(low.encode("ascii")).hex()
    return "".join(c.upper() if (c.isalpha() and int(h[i], 16) >= 8) else c for i, c in enumerate(low))


# ---------------------------------------------------------------------------
# 2. classify(): the specification reading of every family
#    returns (spec_valid, reason, network); reason is "" when valid.
#    network: mainnet | testnet | none
# ---------------------------------------------------------------------------
REASONS = [
    "empty", "whitespace", "bad_charset", "bad_length", "bad_checksum", "bad_version_byte",
    "bad_prefix", "wrong_network", "mixed_case", "bad_case", "bad_witness_version",
    "bad_program_length", "bad_padding", "wrong_checksum_constant", "uri_wrapped",
    "extra_data", "other_family", "not_address_type", "bad_format",
]


def _pre(s):
    if s == "":
        return "empty"
    if re.search(r"\s", s):
        return "whitespace"
    return None


def _seg_diag(c, s, hrp, net):
    if len(s) > 90:
        return (False, "bad_length", net)
    if s != s.lower() and s != s.upper():
        return (False, "mixed_case", net)
    low = s.lower()
    pos = low.rfind("1")
    data = low[pos + 1:]
    if len(data) < 6:
        return (False, "bad_length", net)
    if any(ch not in BECH for ch in data):
        return (False, "bad_charset", net)
    vals = [BECH.index(ch) for ch in data]
    const = bech32_polymod(hrp_expand(hrp) + vals)
    if const not in (1, BECH32M_CONST):
        return (False, "bad_checksum", net)
    body = vals[:-6]
    if not body:
        return (False, "bad_length", net)
    ver = body[0]
    if ver > 16:
        return (False, "bad_witness_version", net)
    prog = convertbits(body[1:], 5, 8, False)
    if prog is None:
        return (False, "bad_padding", net)
    if ver == 0:
        if len(prog) not in (20, 32):
            return (False, "bad_program_length", net)
    elif not 2 <= len(prog) <= 40:
        return (False, "bad_program_length", net)
    if (ver == 0) != (const == 1):
        return (False, "wrong_checksum_constant", net)
    if net != "mainnet":
        return (False, "wrong_network", net)
    return (True, "", net)


def _b58_diag(s, alpha, vlen, plen, main, test, lookup=None):
    raw = b58dec(s, alpha)
    if raw is None:
        return (False, "bad_charset", "none")
    if len(raw) != plen:
        return (False, "bad_length", "none")
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        return (False, "bad_checksum", "none")
    ver = tuple(raw[:vlen])
    if ver in main:
        return (True, "", "mainnet")
    if ver in test:
        return (False, "wrong_network", "testnet")
    return (False, "bad_version_byte", "none")


BTCLIKE = {
    "btc": dict(hrps=[("bc", "mainnet"), ("tb", "testnet"), ("bcrt", "testnet")],
                main={(0,), (5,)}, test={(0x6F,), (0xC4,)}),
    "ltc": dict(hrps=[("ltc", "mainnet"), ("tltc", "testnet"), ("rltc", "testnet")],
                main={(0x30,), (0x32,), (5,)}, test={(0x6F,), (0xC4,), (0x3A,)}),
    "doge": dict(hrps=[], main={(0x1E,), (0x16,)}, test={(0x71,), (0xC4,), (0x6F,)}),
}


def _btclike(fam, s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    c = BTCLIKE[fam]
    low = s.lower()
    for hrp, net in c["hrps"]:
        if low.startswith(hrp + "1"):
            return _seg_diag(c, s, hrp, net)
    return _b58_diag(s, B58, 1, 25, c["main"], c["test"])


def _evm(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    if not s.startswith("0x"):
        if re.fullmatch(r"[0-9a-fA-F]{40}", s):
            return (False, "bad_prefix", "none")
        if s[:2] in ("0X",):
            return (False, "bad_prefix", "none")
        return (False, "bad_prefix", "none")
    body = s[2:]
    if not re.fullmatch(r"[0-9a-fA-F]*", body):
        return (False, "bad_charset", "none")
    if len(body) != 40:
        return (False, "bad_length", "none")
    has_l = any(ch in "abcdef" for ch in body)
    has_u = any(ch in "ABCDEF" for ch in body)
    if has_l and has_u and body != eip55(body):
        return (False, "bad_checksum", "none")
    return (True, "", "none")


def _bch(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    if ":" not in s and re.match(r"[13]", s) and all(ch in B58 for ch in s):
        return _b58_diag(s, B58, 1, 25, {(0,), (5,)}, {(0x6F,), (0xC4,)})
    if ":" not in s and not all(ch in BECH + BECH.upper() for ch in s):
        return _b58_diag(s, B58, 1, 25, {(0,), (5,)}, {(0x6F,), (0xC4,)})
    if s != s.lower() and s != s.upper():
        return (False, "mixed_case", "none")
    low = s.lower()
    prefix = "bitcoincash"
    net = "mainnet"
    if ":" in low:
        if low.count(":") > 1:
            return (False, "bad_prefix", "none")
        prefix, low = low.split(":")
        if prefix in ("bchtest", "bchreg"):
            net = "testnet"
        elif prefix != "bitcoincash":
            return (False, "bad_prefix", "none")
    if len(low) < 9 or any(ch not in BECH for ch in low):
        return (False, "bad_charset" if any(ch not in BECH for ch in low) else "bad_length", net)
    words = [BECH.index(ch) for ch in low]
    if cash_polymod([ord(c) & 31 for c in prefix] + [0] + words) != 0:
        return (False, "bad_checksum", net)
    raw = convertbits(words[:-8], 5, 8, False)
    if raw is None or not raw:
        return (False, "bad_padding", net)
    ver = raw[0]
    typ = (ver >> 3) & 15
    if ver & 0x80 or typ not in (0, 1):
        return (False, "bad_version_byte", net)
    sizes = {0: 20, 1: 24, 2: 28, 3: 32, 4: 40, 5: 48, 6: 56, 7: 64}
    if len(raw) - 1 != sizes[ver & 7]:
        return (False, "bad_length", net)
    if net != "mainnet":
        return (False, "wrong_network", net)
    return (True, "", net)


def _zec(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    low = s.lower()
    for hrp, net in (("tex", "mainnet"), ("textest", "testnet")):
        if low.startswith(hrp + "1"):
            if len(s) > 90:
                return (False, "bad_length", net)
            if s != low and s != s.upper():
                return (False, "mixed_case", net)
            data = low[len(hrp) + 1:]
            if len(data) < 6 or any(ch not in BECH for ch in data):
                return (False, "bad_charset" if len(data) >= 6 else "bad_length", net)
            vals = [BECH.index(ch) for ch in data]
            const = bech32_polymod(hrp_expand(hrp) + vals)
            if const == 1:
                return (False, "wrong_checksum_constant", net)
            if const != BECH32M_CONST:
                return (False, "bad_checksum", net)
            prog = convertbits(vals[:-6], 5, 8, False)
            if prog is None:
                return (False, "bad_padding", net)
            if len(prog) != 20:
                return (False, "bad_program_length", net)
            return (True, "", "mainnet") if net == "mainnet" else (False, "wrong_network", net)
    return _b58_diag(s, B58, 2, 26, {(0x1C, 0xB8), (0x1C, 0xBD)}, {(0x1D, 0x25), (0x1C, 0xBA)})


def _tron(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    if re.fullmatch(r"41[0-9a-fA-F]{40}", s):
        return (True, "", "mainnet")
    return _b58_diag(s, B58, 1, 25, {(0x41,)}, set())


def _xrp(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    raw = b58dec(s, RB58)
    if raw is None:
        return (False, "bad_charset", "none")
    if len(raw) not in (25, 35):
        return (False, "bad_length", "none")
    if sha256d(raw[:-4])[:4] != raw[-4:]:
        return (False, "bad_checksum", "none")
    if len(raw) == 25:
        return (True, "", "mainnet") if raw[0] == 0 else (False, "bad_version_byte", "none")
    pre = tuple(raw[:2])
    if pre not in ((5, 0x44), (4, 0x93)):
        return (False, "bad_version_byte", "none")
    flag = raw[22]
    tail = raw[23:31]
    if flag == 0:
        ok = tail == b"\x00" * 8
    elif flag == 1:
        ok = tail[4:] == b"\x00" * 4
    else:
        return (False, "bad_format", "none")
    if not ok:
        return (False, "bad_format", "none")
    if pre == (4, 0x93):
        return (False, "wrong_network", "testnet")
    return (True, "", "mainnet")


def _sol(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    raw = b58dec(s, B58)
    if raw is None:
        return (False, "bad_charset", "none")
    if len(raw) != 32:
        return (False, "bad_length", "none")
    return (True, "", "none")


NEAR_RE = re.compile(r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")


def _near(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    if len(s) < 2 or len(s) > 64:
        return (False, "bad_length", "none")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", s):
        return (False, "bad_charset", "none")
    if s != s.lower():
        return (False, "bad_case", "none")
    if not NEAR_RE.match(s):
        return (False, "bad_format", "none")
    return (True, "", "none")


def _ton(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    m = re.fullmatch(r"(-?[0-9]+):([0-9a-fA-F]*)", s)
    if m:
        if len(m.group(2)) != 64:
            return (False, "bad_length", "none")
        if m.group(1) not in ("0", "-1"):
            return (False, "bad_format", "none")
        return (True, "", "none")
    if len(s) != 48:
        if re.fullmatch(r"[A-Za-z0-9_/+=-]*", s):
            return (False, "bad_length", "none")
        return (False, "bad_charset", "none")
    std = re.fullmatch(r"[A-Za-z0-9+/]{48}", s)
    url = re.fullmatch(r"[A-Za-z0-9_-]{48}", s)
    if not (std or url):
        return (False, "bad_charset", "none")
    raw = base64.b64decode(s) if std else base64.urlsafe_b64decode(s)
    if crc16(raw[:34]) != int.from_bytes(raw[34:], "big"):
        return (False, "bad_checksum", "none")
    flag = raw[0]
    if flag in (0x11, 0x51):
        if raw[1] in (0, 255):
            return (True, "", "mainnet")
        return (False, "bad_format", "mainnet")
    if flag in (0x91, 0xD1):
        return (False, "wrong_network", "testnet")
    return (False, "bad_version_byte", "none")


STRKEY_TYPES = {"G": 6 << 3, "M": 12 << 3, "C": 2 << 3}
STRKEY_LEN = {"G": 56, "M": 69, "C": 56}


def _stellar(s):
    p = _pre(s)
    if p:
        return (False, p, "none")
    if any(ch not in B32 for ch in s):
        return (False, "bad_charset", "none")
    first = s[0]
    if first not in "GMCSTXPLBW":
        return (False, "bad_version_byte", "none")
    if first not in STRKEY_TYPES:
        return (False, "not_address_type", "none")
    if len(s) != STRKEY_LEN[first]:
        return (False, "bad_length", "none")
    raw = b32dec_strict(s)
    if raw is None:
        return (False, "bad_padding", "none")
    if crc16(raw[:-2]) != int.from_bytes(raw[-2:], "little"):
        return (False, "bad_checksum", "none")
    if raw[0] != STRKEY_TYPES[first]:
        return (False, "bad_version_byte", "none")
    return (True, "", "mainnet")


CLASSIFY = {
    "evm": _evm, "btc": lambda s: _btclike("btc", s), "ltc": lambda s: _btclike("ltc", s),
    "doge": lambda s: _btclike("doge", s), "bch": _bch, "zec": _zec, "sol": _sol, "tron": _tron,
    "near": _near, "ton": _ton, "xrp": _xrp, "stellar": _stellar,
}
FAMILIES = ["evm", "btc", "ltc", "doge", "bch", "zec", "sol", "tron", "near", "ton", "xrp", "stellar"]


def classify(fam, s):
    return CLASSIFY[fam](s)


# ---------------------------------------------------------------------------
# 3. vector tables
# ---------------------------------------------------------------------------
U = {
    "eip55": "https://eips.ethereum.org/EIPS/eip-55",
    "eip1191": "https://eips.ethereum.org/EIPS/eip-1191",
    "eip1014": "https://eips.ethereum.org/EIPS/eip-1014",
    "eip1820": "https://eips.ethereum.org/EIPS/eip-1820",
    "eip2470": "https://eips.ethereum.org/EIPS/eip-2470",
    "eip4788": "https://eips.ethereum.org/EIPS/eip-4788",
    "eip2935": "https://eips.ethereum.org/EIPS/eip-2935",
    "eip7002": "https://eips.ethereum.org/EIPS/eip-7002",
    "eip7251": "https://eips.ethereum.org/EIPS/eip-7251",
    "eip1967": "https://eips.ethereum.org/EIPS/eip-1967",
    "eip3770": "https://eips.ethereum.org/EIPS/eip-3770",
    "jsonrpc": "https://ethereum.org/en/developers/docs/apis/json-rpc/#hex-encoding",
    "bip13": "https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki",
    "bip49": "https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki",
    "bip84": "https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki",
    "bip86": "https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki",
    "bip173": "https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki",
    "bip350": "https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki",
    "b58c": "https://en.bitcoin.it/wiki/Base58Check_encoding",
    "tech1": "https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses",
    "genesis": "https://en.bitcoin.it/wiki/Genesis_block",
    "btcaddr": "https://en.bitcoin.it/wiki/Address",
    "p2sh": "https://en.bitcoin.it/wiki/Pay_to_script_hash",
    "ltc_cp": "https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp",
    "ltc_key": "https://github.com/litecoin-project/litecoin/blob/master/src/key_io.cpp",
    "doge_cp": "https://github.com/dogecoin/dogecoin/blob/master/src/chainparams.cpp",
    "zec_cp": "https://github.com/zcash/zcash/blob/master/src/chainparams.cpp",
    "zip320": "https://zips.z.cash/zip-0320",
    "cashaddr": "https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md",
    "sol_ids": "https://github.com/anza-xyz/solana-sdk/blob/master/sdk-ids/src/lib.rs",
    "sol_addr": "https://github.com/anza-xyz/solana-sdk/blob/master/address/src/lib.rs",
    "tron": "https://developers.tron.network/docs/account",
    "near_docs": "https://docs.near.org/protocol/accounts-contracts/account-id",
    "near_td": "https://github.com/near/near-account-id-rs/blob/main/src/test_data.rs",
    "near_val": "https://github.com/near/near-account-id-rs/blob/main/src/validation.rs",
    "near_ref": "https://github.com/near/near-account-id-rs/blob/main/src/account_id_ref.rs",
    "ton": "https://docs.ton.org/v3/documentation/smart-contracts/addresses/address-formats",
    "xrpl": "https://xrpl.org/docs/concepts/accounts/addresses",
    "xls5": "https://github.com/XRPLF/XRPL-Standards/blob/master/XLS-0005-tagged-addresses/README.md",
    "sep23": "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md",
    "rfc8032": "https://www.rfc-editor.org/rfc/rfc8032",
}

CK = {
    "eip55": "EIP-55 (Keccak-256 case checksum)",
    "eip55-none": "none (single-case hex; EIP-55 checksum not asserted)",
    "b58c": "Base58Check (double SHA-256, 4 bytes)",
    "rb58c": "Base58Check, XRPL alphabet (double SHA-256, 4 bytes)",
    "bech32": "Bech32 (BCH code, constant 1)",
    "bech32m": "Bech32m (BCH code, constant 0x2bc830a3)",
    "segwit": "Bech32 (witness v0) or Bech32m (witness v1 and higher)",
    "cashaddr": "CashAddr (BCH code, 40 bits)",
    "crc16s": "CRC16-XMODEM (StrKey, little-endian)",
    "crc16t": "CRC16-XMODEM (TON, big-endian)",
    "none": "none",
}

MEMO = {
    "evm": "none", "btc": "none", "ltc": "none", "doge": "none", "bch": "none", "zec": "none",
    "sol": "none", "tron": "none", "near": "memo", "ton": "comment", "xrp": "destination_tag",
    "stellar": "memo",
}

CAIP2 = {
    "evm": "eip155:1", "btc": "bip122:000000000019d6689c085ae165831e93",
    "ltc": "bip122:12a765e31ffd4059bada1e25190f6e98", "doge": "bip122:1a91e3dace36e2be3bf030a65679fe82",
    "bch": "bip122:000000000000000000651ef99cb9fcbe", "zec": "", "sol": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "tron": "tron:728126428", "near": "", "ton": "", "xrp": "xrpl:0", "stellar": "stellar:pubnet",
}

ROWS = []
BYID = {}
SEEN = set()
COUNT = {}
RULECOUNT = {}
MUT_CAP = 3


def _nextid(fam):
    COUNT[fam] = COUNT.get(fam, 0) + 1
    return "%s-%04d" % (fam, COUNT[fam])


def add(fam, addr, form, origin, source, url, ck, valid=None, reason=None, net=None, notes="", rule=None):
    if (fam, addr) in SEEN:
        raise SystemExit("duplicate row %s %r" % (fam, addr))
    v, r, n = classify(fam, addr)
    if valid is not None and valid != v:
        raise SystemExit("label disagrees with classify(): %s %r declared %s got %s %s" % (fam, addr, valid, v, r))
    valid = v
    reason = "" if valid else (reason or r)
    if reason and reason not in REASONS:
        raise SystemExit("unknown reason " + reason)
    net = net or n
    row = {
        "id": _nextid(fam), "family": fam, "chain_caip2": CAIP2[fam], "network": net, "address": addr,
        "encoding_form": form, "checksum_algorithm": CK.get(ck, ck), "spec_valid": valid, "reason": reason,
        "memo_or_tag_convention": MEMO[fam], "origin": origin, "source": source, "source_url": url,
        "notes": notes, "_rule": rule or "",
    }
    if origin == "mutation":
        row["_rule"] = rule or "degenerate_input"
        if not source.startswith("Mutation rule"):
            row["source"] = "Mutation rule %s: %s" % (row["_rule"], source)
    SEEN.add((fam, addr))
    ROWS.append(row)
    BYID[row["id"]] = row
    return row


def pub(fam, addr, form, source, url, ck, valid=True, reason=None, net=None, notes="", origin="specification"):
    return add(fam, addr, form, origin, source, url, ck, valid=valid, reason=reason, net=net, notes=notes)


def derived(fam, addr, form, source, url, ck, valid=None, reason=None, net=None, notes=""):
    return add(fam, addr, form, "derived", source, url, ck, valid=valid, reason=reason, net=net, notes=notes)


def mut(base, rule, new, desc, reason=None, form=None, notes="", url=None, allow_valid=False, net=None):
    """Add a mutation row; returns None when the rule is full or the result is unusable."""
    fam = base["family"]
    if RULECOUNT.get((fam, rule), 0) >= MUT_CAP or new is None or new == base["address"]:
        return None
    if (fam, new) in SEEN:
        return None
    v, r, n = classify(fam, new)
    if v and not allow_valid:
        return None
    RULECOUNT[(fam, rule)] = RULECOUNT.get((fam, rule), 0) + 1
    ck = base["checksum_algorithm"]
    if v:
        notes = (notes + " " if notes else "") + "The changed string breaks no rule of the form (no checksum protects it), so it is again a well-formed address."
    if reason not in ("whitespace", "uri_wrapped", "extra_data", "other_family"):
        reason = None  # the specification reading of classify() decides which reason is reported
    row = add(fam, new, form or base["encoding_form"], "mutation",
              "Mutation rule %s applied to %s: %s" % (rule, base["id"], desc),
              url or base["source_url"], ck, reason=reason, net=net or (n if n != "none" else base["network"]),
              notes=notes, rule=rule)
    row["checksum_algorithm"] = ck
    return row


def valid_rows(fam):
    return [r for r in ROWS if r["family"] == fam and r["spec_valid"] and r["origin"] != "mutation"]


# ---- character-level helpers for mutation rules ---------------------------------------------
ALPHS = [
    "0123456789abcdef", "0123456789ABCDEF",
]


def _alphabets(fam, s):
    if fam == "evm":
        return ALPHS
    if fam in ("btc", "ltc", "zec", "bch"):
        return [B58, BECH, BECH.upper()]
    if fam in ("doge", "sol", "tron"):
        return [B58]
    if fam == "xrp":
        return [RB58]
    if fam == "stellar":
        return [B32]
    if fam == "ton":
        return ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "0123456789abcdef"]
    return ["abcdefghijklmnopqrstuvwxyz0123456789"]


def _start(fam, s):
    """Index of the first character of the checksummed payload (after the prefix)."""
    if fam == "evm":
        return 2 if s.startswith("0x") else 0
    if fam in ("btc", "ltc", "zec"):
        low = s.lower()
        for h in ("bc1", "ltc1", "tex1", "tb1", "tltc1"):
            if low.startswith(h):
                return len(h)
        return 1
    if fam == "bch":
        return s.index(":") + 1 if ":" in s else 0
    if fam == "ton" and ":" in s:
        return s.index(":") + 1
    return 0


def _rot(fam, s, i, step=1):
    alphs = [a for a in _alphabets(fam, s) if s[i] in a]
    if not alphs:
        return None
    a = alphs[0]
    return s[:i] + a[(a.index(s[i]) + step) % len(a)] + s[i + 1:]


def f_subst_last(fam):
    return lambda s: _rot(fam, s, len(s) - 1)


def f_subst_mid(fam):
    def f(s):
        st = _start(fam, s)
        i = st + (len(s) - st) // 2
        return _rot(fam, s, i, 3)
    return f


def f_subst_first(fam):
    def f(s):
        i = _start(fam, s)
        return _rot(fam, s, i, 7)
    return f


def f_swap(fam):
    def f(s):
        st = _start(fam, s)
        i = st + (len(s) - st) // 3
        for j in range(i, len(s) - 1):
            if s[j] != s[j + 1] and s[j].isalnum() and s[j + 1].isalnum():
                return s[:j] + s[j + 1] + s[j] + s[j + 2:]
        return None
    return f


def f_trunc(s):
    return s[:-1]


def f_drop_first(fam):
    def f(s):
        st = _start(fam, s)
        return s[:st] + s[st + 1:]
    return f


def f_extend(fam):
    def f(s):
        a = _alphabets(fam, s)[0]
        return s + a[1]
    return f


def f_insert(fam):
    def f(s):
        st = _start(fam, s)
        i = st + (len(s) - st) // 2
        a = _alphabets(fam, s)[0]
        return s[:i] + a[2] + s[i:]
    return f


def f_ws_lead(s):
    return " " + s


def f_ws_trail(s):
    return s + " "


def f_ws_inner(s):
    i = len(s) // 2
    return s[:i] + " " + s[i:]


def f_ws_ctrl(s):
    return "\t" + s + "\n"


SCHEME = {
    "evm": "ethereum:", "btc": "bitcoin:", "ltc": "litecoin:", "doge": "dogecoin:", "bch": "bch:",
    "zec": "zcash:", "sol": "solana:", "tron": "tron:", "near": "near:", "ton": "ton:", "xrp": "xrpl:",
    "stellar": "stellar:",
}
QUERY = {
    "evm": "?value=1", "btc": "?amount=0.001", "ltc": "?amount=0.001", "doge": "?amount=1", "bch": "?amount=0.001",
    "zec": "?amount=0.001", "sol": "?amount=1", "tron": "?amount=1", "near": "?memo=12345", "ton": "?text=12345",
    "xrp": "?dt=12345", "stellar": "?memo=12345",
}
TAGSUF = {"near": ":12345", "ton": "#12345", "xrp": ":12345", "stellar": ":12345", "evm": "@1", "sol": ":1", "tron": ":1"}


def battery(fam, bases, skip=(), extra_alloweds=()):
    """The generic mutation rules. bases: valid rows of the family to mutate (a different slice per rule)."""
    n = len(bases)
    if n == 0:
        return

    def pick(k, rot):
        return [bases[(rot + j) % n] for j in range(min(n, k + 6))]

    rules = [
        ("substitute_last_char", f_subst_last(fam), "the last character replaced by the next one of its alphabet", None),
        ("substitute_payload_char", f_subst_mid(fam), "a character in the middle of the payload replaced", None),
        ("substitute_first_payload_char", f_subst_first(fam), "the first payload character replaced", None),
        ("swap_adjacent_chars", f_swap(fam), "two adjacent different characters swapped", None),
        ("truncate_last_char", f_trunc, "the last character removed", None),
        ("drop_first_payload_char", f_drop_first(fam), "the first payload character removed", None),
        ("extend_one_char", f_extend(fam), "one character appended", None),
        ("insert_char", f_insert(fam), "one character inserted in the middle", None),
        ("whitespace_leading", f_ws_lead, "a leading space added", "whitespace"),
        ("whitespace_trailing", f_ws_trail, "a trailing space added", "whitespace"),
        ("whitespace_internal", f_ws_inner, "a space inserted in the middle", "whitespace"),
        ("whitespace_control", f_ws_ctrl, "a leading tab and a trailing line feed added", "whitespace"),
        ("uri_scheme_prefix", lambda s: SCHEME[fam] + s, "wrapped with a URI-style scheme prefix", "uri_wrapped"),
        ("query_suffix", lambda s: s + QUERY[fam], "a URI-style query string appended", "extra_data"),
    ]
    if fam in TAGSUF:
        rules.append(("tag_suffix", lambda s: s + TAGSUF[fam], "a tag or chain suffix appended with a separator", "extra_data"))
    for k, (rule, fn, desc, reason) in enumerate(rules):
        if rule in skip:
            continue
        for b in pick(MUT_CAP, k * 2):
            mut(b, rule, fn(b["address"]), desc, reason=reason,
                allow_valid=(rule in extra_alloweds))


# ---- published hash160 values, decoded from published addresses ---------------------------------
def _h(addr):
    raw = b58check_dec(addr)
    assert raw is not None and len(raw) == 21, addr
    return raw[1:]


P2PKH_SRC = [
    ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "the Bitcoin genesis-block coinbase address", U["genesis"]),
    ("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", "the worked example of the Bitcoin Wiki page on version 1 addresses", U["tech1"]),
    ("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "the example address of the Bitcoin Wiki Address page", U["btcaddr"]),
    ("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "the legacy column of the CashAddr specification table", U["cashaddr"]),
    ("1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", "the legacy column of the CashAddr specification table", U["cashaddr"]),
    ("16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb", "the legacy column of the CashAddr specification table", U["cashaddr"]),
]
P2SH_SRC = [
    ("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "the example address of the Bitcoin Wiki Address page", U["btcaddr"]),
    ("342ftSRCvFHfCeFFBuz4xwbeqnDw6BGUey", "an example of the Bitcoin Wiki page on pay-to-script-hash", U["p2sh"]),
    ("3P14159f73E4gFr7JterCCQh9QjiTjiZrG", "an example of the Bitcoin Wiki page on pay-to-script-hash", U["p2sh"]),
    ("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "the legacy column of the CashAddr specification table", U["cashaddr"]),
    ("3LDsS579y7sruadqu11beEJoTjdFiFCdX4", "the legacy column of the CashAddr specification table", U["cashaddr"]),
    ("31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", "the legacy column of the CashAddr specification table", U["cashaddr"]),
]
H_PKH = [(_h(a), "hash160 of " + d + " " + a, u, a) for a, d, u in P2PKH_SRC]
H_SH = [(_h(a), "hash160 of " + d + " " + a, u, a) for a, d, u in P2SH_SRC]
assert H_PKH[1][0].hex() == "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"  # printed on the Bitcoin Wiki page

BIP173_V0_PKH = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")
BIP173_V0_WSH = bytes.fromhex("1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262")
BIP350_V1 = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

RFC8032_KEYS = [
    ("test 1", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
    ("test 2", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
    ("test 3", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
    ("test 1024", "278117fc144c72340f67d0f2316e83 86ceffbf2b2428c9c51fef7c597f1d426e".replace(" ", "")),
    ("test SHA(abc)", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"),
]


def ref_hash(i, sh=False):
    arr = H_SH if sh else H_PKH
    h, d, u, a = arr[i]
    return h, d, u


# ---------------------------------------------------------------------------------------------
def fam_evm():
    f = "evm"
    pubs = [
        ("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "EIP-55 test cases, normal", "eip55"),
        ("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "EIP-55 test cases, normal", "eip55"),
        ("0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "EIP-55 test cases, normal", "eip55"),
        ("0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb", "EIP-55 test cases, normal", "eip55"),
        ("0x3599689E6292b81B2d85451025146515070129Bb", "EIP-1191 test cases, list eth_mainnet (EIP-55 checksum)", "eip1191"),
        ("0x42712D45473476b98452f434e72461577D686318", "EIP-1191 test cases, list eth_mainnet (EIP-55 checksum)", "eip1191"),
        ("0x6549f4939460DE12611948b3f82b88C3C8975323", "EIP-1191 test cases, list eth_mainnet (EIP-55 checksum)", "eip1191"),
        ("0x66f9664f97F2b50F62D13eA064982f936dE76657", "EIP-1191 test cases, list eth_mainnet (EIP-55 checksum)", "eip1191"),
        ("0x88021160C5C792225E4E5452585947470010289D", "EIP-1191 test cases, list eth_mainnet (EIP-55 checksum)", "eip1191"),
        ("0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38", "EIP-1014 examples (address field)", "eip1014"),
        ("0x60f3f640a8508fC6a86d45DF051962668E1e8AC7", "EIP-1014 examples (address field)", "eip1014"),
        ("0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e", "EIP-1014 examples (address field)", "eip1014"),
        ("0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3", "EIP-1014 examples (address field)", "eip1014"),
        ("0xD04116cDd17beBE565EB2422F2497E06cC1C9833", "EIP-1014 examples (address field)", "eip1014"),
        ("0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0", "EIP-1014 examples (address field)", "eip1014"),
        ("0x1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C", "EIP-1014 examples (address field)", "eip1014"),
        ("0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24", "EIP-1820 text (registry address)", "eip1820"),
        ("0xa990077c3205cbDf861e17Fa532eeB069cE9fF96", "EIP-1820 text (deployment address)", "eip1820"),
        ("0xce0042B868300000d44A59004Da54A005ffdcf9f", "EIP-2470 text (singleton factory address)", "eip2470"),
        ("0xBb6e024b9cFFACB947A71991E386681B1Cd1477D", "EIP-2470 text (deployment address)", "eip2470"),
        ("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02", "EIP-4788 text (beacon roots contract)", "eip4788"),
        ("0x0B799C86a49DEeb90402691F1041aa3AF2d3C875", "EIP-4788 text (deployment address)", "eip4788"),
        ("0x0000F90827F1C53a10cb7A02335B175320002935", "EIP-2935 text (history storage contract)", "eip2935"),
        ("0x3462413Af4609098e1E27A490f554f260213D685", "EIP-2935 text (deployment address)", "eip2935"),
        ("0x00000961Ef480Eb55e80D19ad83579A64c007002", "EIP-7002 text (withdrawal request contract)", "eip7002"),
        ("0x8646861A7cF453dDD086874d622b0696dE5b9674", "EIP-7002 text (deployment address)", "eip7002"),
        ("0x0000BBdDc7CE488642fb579F8B00f3a590007251", "EIP-7251 text (consolidation request contract)", "eip7251"),
        ("0x13d1913d623E6a9D8811736359E50fD31Fe54fCA", "EIP-7251 text (deployment address)", "eip7251"),
        ("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "ethereum.org JSON-RPC documentation (example address)", "jsonrpc"),
    ]
    for a, src, u in pubs:
        org = "specification" if u in ("eip55", "eip1191", "eip1014") else "public-well-known"
        body = a[2:]
        has_l = any(c in "abcdef" for c in body)
        has_u = any(c in "ABCDEF" for c in body)
        if has_l and has_u:
            pub(f, a, "EIP-55 mixed-case", src, U[u], "eip55", origin=org)
        elif has_u:
            pub(f, a, "EIP-55, letters all uppercase", src, U[u], "eip55-none", origin=org, notes="Letters are all upper case; this is also the exact EIP-55 encoding of the address.")
        else:
            pub(f, a, "EIP-55, letters all lowercase", src, U[u], "eip55-none", origin=org, notes="Letters are all lower case; this is also the exact EIP-55 encoding of the address.")
    pub(f, "0x52908400098527886E0F7030069857D2E4169EE7", "EIP-55, letters all uppercase", "EIP-55 test cases, all caps", U["eip55"], "eip55-none",
        notes="Also the exact EIP-55 encoding of the address: its only letters are two E digits that the checksum capitalises.")
    pub(f, "0x8617E340B3D01FA5F11F306F4090FD50E238070D", "EIP-55, letters all uppercase", "EIP-55 test cases, all caps", U["eip55"], "eip55-none")
    pub(f, "0xde709f2102306220921060314715629080e2fb77", "EIP-55, letters all lowercase", "EIP-55 test cases, all lower", U["eip55"], "eip55-none")
    pub(f, "0x27b1fdb04752bbc536007a920d24acb045561c26", "EIP-55, letters all lowercase", "EIP-55 test cases, all lower", U["eip55"], "eip55-none")
    pub(f, "0x00000000000000000000000000000000deadbeef", "lowercase hex, no checksum asserted", "EIP-1014 examples", U["eip1014"], "eip55-none")
    pub(f, "0xdeadbeef00000000000000000000000000000000", "lowercase hex, no checksum asserted", "EIP-1014 examples", U["eip1014"], "eip55-none")
    pub(f, "0x0000000000000000000000000000000000000000", "zero address", "EIP-1014 examples and EIP-7702 text (zero address)", U["eip1014"], "eip55-none",
        notes="Well formed. Whether to refuse the zero address as a recipient is application policy, not part of the encoding.")
    pub(f, "0xfffffffffffffffffffffffffffffffffffffffe", "lowercase hex, no checksum asserted", "EIP-4788 text (SYSTEM_ADDRESS)", U["eip4788"], "eip55-none")
    pub(f, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "lowercase hex, no checksum asserted", "EIP-1967 text (example implementation address)", U["eip1967"], "eip55-none")
    mixed = [r for r in ROWS if r["family"] == f and r["encoding_form"] == "EIP-55 mixed-case"]
    for r in mixed[:6]:
        low = r["address"].lower()
        derived(f, low, "lowercase hex, no checksum asserted", "Lowercase form of %s" % r["id"], U["eip55"], "eip55-none")
    for r in mixed[6:9]:
        up = "0x" + r["address"][2:].upper()
        derived(f, up, "uppercase hex, no checksum asserted", "Upper-case hex digits of %s" % r["id"], U["eip55"], "eip55-none")
    # published invalid (EIP-1191 checksum lists: valid under that EIP, not under EIP-55)
    rsk = [
        "0x27b1FdB04752BBc536007A920D24ACB045561c26", "0x3599689E6292B81B2D85451025146515070129Bb",
        "0x42712D45473476B98452f434E72461577d686318", "0x66F9664f97f2B50F62d13EA064982F936de76657",
        "0xD1220A0Cf47c7B9BE7a2e6ba89F429762E7B9adB",
    ]
    for a in rsk:
        pub(f, a, "EIP-1191 checksum, chain id 30 (not EIP-55)", "EIP-1191 test cases, list rsk_mainnet", U["eip1191"], "eip55",
            valid=False, reason="bad_checksum",
            notes="Valid under EIP-1191 for chain id 30; the capitalisation differs from EIP-55, so it fails the EIP-55 checksum.")
    base = [r for r in ROWS if r["family"] == f and r["spec_valid"] and r["encoding_form"] == "EIP-55 mixed-case"]
    # missing prefix (JSON-RPC: addresses are 0x-prefixed)
    for b in base[:3]:
        mut(b, "missing_0x_prefix", b["address"][2:], "the 0x prefix removed", reason="bad_prefix", url=U["jsonrpc"],
            notes="The Ethereum JSON-RPC encoding rules require the 0x prefix for account addresses.")
    # case flips (checksum break)
    for k, b in enumerate(base[3:12]):
        s = b["address"]
        for i in range(2 + k, len(s)):
            if s[i].isalpha():
                mut(b, "flip_case_of_one_letter", s[:i] + s[i].swapcase() + s[i + 1:], "the case of one letter flipped", reason="bad_checksum")
                break
    for b in base[12:16]:
        s = b["address"]
        mut(b, "swapcase_whole_hex", "0x" + s[2:].swapcase(), "the case of every letter flipped", reason="bad_checksum")
    for b in base[16:22]:
        mut(b, "substitute_hex_digit", b["address"][:12] + ("a" if b["address"][12] != "a" else "b") + b["address"][13:], "one hex digit replaced, case pattern kept", reason="bad_checksum")
    for b in valid_rows(f)[:8]:
        if b["encoding_form"] == "EIP-55 mixed-case":
            mut(b, "truncate_last_char", b["address"][:-1], "the last hex digit removed", reason="bad_length")
            mut(b, "extend_one_char", b["address"] + "0", "one hex digit appended", reason="bad_length")
    for k, b in enumerate(base[:3]):
        s = b["address"]
        mut(b, "non_hex_character", s[:8] + "g" + s[9:], "one character replaced by g", reason="bad_charset")
    for b in base[3:6]:
        s = b["address"]
        mut(b, "non_ascii_lookalike", s[:8] + "а" + s[9:], "one character replaced by CYRILLIC SMALL LETTER A", reason="bad_charset")
    lows = [r for r in ROWS if r["family"] == f and r["spec_valid"] and r["encoding_form"].startswith("lowercase")]
    for b in lows[:4]:
        mut(b, "extend_to_32_bytes", b["address"] + b["address"][2:26], "extended to 64 hex digits, the shape of a 32-byte hash", reason="bad_length")
    mut(lows[0], "truncate_last_char", lows[0]["address"][:-1], "the last hex digit removed", reason="bad_length")
    for b in base[6:9]:
        mut(b, "eip3770_short_name_prefix", "eth:" + b["address"], "prefixed with a chain short name", reason="uri_wrapped",
            url=U["eip3770"], notes="EIP-3770 chain-specific address form; the prefix is not part of an EIP-55 address string.")
    pub(f, "0x", "prefix only", "Ethereum JSON-RPC encoding: 0x alone encodes zero bytes, not a 20-byte address", U["jsonrpc"], "none", valid=False, reason="bad_length", origin="mutation")
    pub(f, "", "empty string", "empty string", U["eip55"], "none", valid=False, reason="empty", origin="mutation")
    battery(f, base[8:], skip=("substitute_last_char", "truncate_last_char", "extend_one_char", "substitute_first_payload_char", "drop_first_payload_char", "insert_char"))
    mut(base[2], "substitute_last_char", base[2]["address"][:-1] + ("0" if base[2]["address"][-1] != "0" else "1"), "the last hex digit replaced", reason="bad_checksum")
    mut(base[5], "substitute_last_char", base[5]["address"][:-1] + ("0" if base[5]["address"][-1] != "0" else "1"), "the last hex digit replaced", reason="bad_checksum")
    mut(base[9], "insert_char", base[9]["address"][:20] + "0" + base[9]["address"][20:], "one hex digit inserted", reason="bad_length")
    mut(base[10], "drop_first_payload_char", "0x" + base[10]["address"][3:], "the first hex digit removed", reason="bad_length")
    # other families
    others = ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL",
              "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"]
    for o in others:
        add(f, o, "address of another family", "mutation", "Published address of another family used as input to the EVM format (see its own row)",
            U["eip55"], "none", reason="other_family", rule="other_family")
    # EVM-shaped but 0x + 64 hex (hash)
    add(f, "0x" + "ab" * 32, "32-byte hash shape", "mutation", "0x followed by 64 hex digits: the shape of a transaction hash, not an address",
        U["eip55"], "none", reason="bad_length", rule="hash_shape")
    add(f, "0x" + "0" * 39, "39 hex digits", "mutation", "zero address with one digit removed", U["eip55"], "none", reason="bad_length", rule="hash_shape")


def fam_btc():
    f = "btc"
    for (h, d, u, a), k in zip(H_PKH, range(6)):
        pub(f, a, "P2PKH Base58Check (1...)", "Published address: " + d, u, "b58c")
    for (h, d, u, a) in H_SH:
        pub(f, a, "P2SH Base58Check (3...)", "Published address: " + d, u, "b58c")
    sw = [
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "P2WPKH (witness v0, 20-byte program), upper case", "BIP-350 list of valid segwit addresses", U["bip350"], "bech32"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "P2WPKH (witness v0, 20-byte program)", "BIP-173 examples, Mainnet P2WPKH", U["bip173"], "bech32"),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", "P2WSH (witness v0, 32-byte program)", "BIP-173 examples, Mainnet P2WSH", U["bip173"], "bech32"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "P2TR (witness v1, 32-byte program)", "BIP-350 list of valid segwit addresses", U["bip350"], "bech32m"),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "witness v1, 40-byte program", "BIP-350 list of valid segwit addresses", U["bip350"], "bech32m"),
        ("BC1SW50QGDZ25J", "witness v16, 2-byte program, upper case", "BIP-350 list of valid segwit addresses", U["bip350"], "bech32m"),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "witness v2, 16-byte program", "BIP-350 list of valid segwit addresses", U["bip350"], "bech32m"),
        ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "P2WPKH (witness v0, 20-byte program)", "BIP-84 test vectors, account 0 first receiving address", U["bip84"], "bech32"),
        ("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g", "P2WPKH (witness v0, 20-byte program)", "BIP-84 test vectors, account 0 second receiving address", U["bip84"], "bech32"),
        ("bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", "P2WPKH (witness v0, 20-byte program)", "BIP-84 test vectors, account 0 first change address", U["bip84"], "bech32"),
        ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", "P2TR (witness v1, 32-byte program)", "BIP-86 test vectors, first receiving address", U["bip86"], "bech32m"),
        ("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh", "P2TR (witness v1, 32-byte program)", "BIP-86 test vectors, second receiving address", U["bip86"], "bech32m"),
        ("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7", "P2TR (witness v1, 32-byte program)", "BIP-86 test vectors, first change address", U["bip86"], "bech32m"),
    ]
    for a, form, src, u, ck in sw:
        pub(f, a, form, src, u, ck, notes=("Witness v2 and higher are valid recipients under BIP-350 but are not standard outputs today." if " v1, 40" in form or "v16" in form or "v2" in form else ""))
    # published invalid, with the reason given by the BIP
    inv = [
        ("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", "Invalid human-readable part", "bad_prefix", "bip173"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "Invalid checksum", "bad_checksum", "bip173"),
        ("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", "Invalid witness version", "bad_witness_version", "bip173"),
        ("bc1rw5uspcuh", "Invalid program length (1 byte)", "bad_program_length", "bip173"),
        ("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", "Invalid program length (41 bytes)", "bad_program_length", "bip173"),
        ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "Invalid program length for witness version 0", "bad_program_length", "bip173"),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", "Zero padding of more than 4 bits", "bad_padding", "bip173"),
        ("bc1gmk9yu", "Empty data section", "bad_length", "bip173"),
        ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", "Mixed case", "mixed_case", "bip173"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", "Invalid checksum (Bech32 instead of Bech32m)", "wrong_checksum_constant", "bip350"),
        ("BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", "Invalid checksum (Bech32 instead of Bech32m)", "wrong_checksum_constant", "bip350"),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", "Invalid checksum (Bech32m instead of Bech32)", "wrong_checksum_constant", "bip350"),
        ("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", "Invalid character in checksum", "bad_charset", "bip350"),
        ("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", "Invalid witness version", "bad_witness_version", "bip350"),
        ("bc1pw5dgrnzv", "Invalid program length (1 byte)", "bad_program_length", "bip350"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", "Invalid program length (41 bytes)", "bad_program_length", "bip350"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", "Zero padding of more than 4 bits", "bad_padding", "bip350"),
    ]
    for a, why, reason, u in inv:
        pub(f, a, "segwit address, published invalid", "%s invalid segwit addresses: %s" % (u.upper().replace("BIP", "BIP-"), why), U[u], "segwit", valid=False, reason=reason,
            notes="Reason as given by the BIP." if reason != "bad_charset" else "Reason as given by the BIP (the checksum contains a character outside the Bech32 alphabet).")
    pub(f, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet P2WPKH", "BIP-173 examples, Testnet P2WPKH", U["bip173"], "bech32", valid=False, reason="wrong_network", net="testnet")
    pub(f, "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "testnet P2WSH", "BIP-173 examples, Testnet P2WSH", U["bip173"], "bech32", valid=False, reason="wrong_network", net="testnet")
    pub(f, "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "testnet witness v1", "BIP-350 list of valid segwit addresses (testnet)", U["bip350"], "bech32m", valid=False, reason="wrong_network", net="testnet")
    pub(f, "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2", "testnet P2SH Base58Check (2...)", "BIP-49 test vectors (testnet P2SH-P2WPKH)", U["bip49"], "b58c", valid=False, reason="wrong_network", net="testnet")
    # derived: other forms of published hashes
    for k in (0, 1, 3):
        h, d, u = ref_hash(k)
        derived(f, b58check_enc([0x6F], h), "testnet P2PKH Base58Check (m/n...)", "Version byte 0x6f applied to the " + d, U["b58c"], "b58c", valid=False, reason="wrong_network", net="testnet")
    for k in (0, 3):
        h, d, u = ref_hash(k, True)
        derived(f, b58check_enc([0xC4], h), "testnet P2SH Base58Check (2...)", "Version byte 0xc4 applied to the " + d, U["b58c"], "b58c", valid=False, reason="wrong_network", net="testnet")
    for k in (2, 4):
        h, d, u = ref_hash(k)
        derived(f, b58check_enc([0x30], h), "Litecoin-version P2PKH (L...)", "Version byte 0x30 applied to the " + d, U["b58c"], "b58c", valid=False, reason="bad_version_byte",
                notes="Valid Base58Check, but the version byte belongs to another chain (see the ltc family).")
    h, d, u = ref_hash(1)
    derived(f, b58check_enc([0x80], h), "version byte 0x80", "Version byte 0x80 (the private-key version of the Bitcoin Wiki list) applied to the public " + d, U["b58c"], "b58c", valid=False, reason="bad_version_byte",
            notes="A 20-byte payload with a private-key version byte; no private key is involved.")
    derived(f, b58check_enc([0x00], bytes(20)), "P2PKH of the all-zero hash160", "Version 0x00 followed by 20 zero bytes", U["b58c"], "b58c",
            notes="Well formed; no known key hashes to it (a burn address by convention).")
    derived(f, b58check_enc([0x05], bytes(20)), "P2SH of the all-zero hash160", "Version 0x05 followed by 20 zero bytes", U["b58c"], "b58c")
    for k, ver in ((0, 0x00), (1, 0x00)):
        h, d, u = ref_hash(k)
        derived(f, b58check_enc([ver], h + b"\x00"), "21-byte payload", "Version 0x00 with the %s plus one zero byte" % d, U["b58c"], "b58c", valid=False, reason="bad_length")
    h, d, u = ref_hash(0)
    derived(f, b58check_enc([0x00], h[:19]), "19-byte payload", "Version 0x00 with the %s minus its last byte" % d, U["b58c"], "b58c", valid=False, reason="bad_length")
    # segwit re-encodings
    derived(f, segwit_encode("bc", 0, BIP173_V0_PKH + bytes(12)), "witness v0, 32-byte program", "Program of the BIP-173 P2WPKH example padded with 12 zero bytes, witness v0", U["bip173"], "bech32")
    derived(f, segwit_encode("bc", 1, BIP173_V0_PKH + bytes(12)), "witness v1, 32-byte program", "Program of the BIP-173 P2WPKH example padded with 12 zero bytes, witness v1", U["bip350"], "bech32m")
    derived(f, segwit_encode("bc", 0, BIP173_V0_WSH, BECH32M_CONST), "witness v0 with Bech32m constant", "BIP-173 P2WSH program with the Bech32m constant", U["bip350"], "bech32m", valid=False, reason="wrong_checksum_constant")
    derived(f, segwit_encode("bc", 1, BIP173_V0_WSH, 1), "witness v1 with Bech32 constant", "BIP-173 P2WSH program as witness v1 with the Bech32 constant", U["bip350"], "bech32", valid=False, reason="wrong_checksum_constant")
    derived(f, segwit_encode("bc", 2, BIP350_V1, 1), "witness v2 with Bech32 constant", "BIP-350 P2TR program as witness v2 with the Bech32 constant", U["bip350"], "bech32", valid=False, reason="wrong_checksum_constant")
    derived(f, bech32_encode("bc", [17] + convertbits(list(BIP173_V0_PKH), 8, 5, True), BECH32M_CONST), "witness version 17", "BIP-173 P2WPKH program with witness version 17 and a valid Bech32m checksum", U["bip350"], "bech32m", valid=False, reason="bad_witness_version")
    derived(f, segwit_encode("ltc", 0, BIP173_V0_PKH), "Litecoin HRP, witness v0", "BIP-173 P2WPKH program with HRP ltc", U["bip173"], "bech32", valid=False, reason="bad_prefix",
            notes="Valid Bech32 for HRP ltc (see the ltc family); wrong HRP for Bitcoin.")
    derived(f, segwit_encode("bcrt", 0, BIP173_V0_PKH), "regtest HRP, witness v0", "BIP-173 P2WPKH program with HRP bcrt", U["bip173"], "bech32", valid=False, reason="wrong_network", net="testnet")
    derived(f, segwit_encode("bc", 1, bytes([0x51]) * 41), "witness v1, 41-byte program", "41 bytes 0x51, witness v1", U["bip350"], "bech32m", valid=False, reason="bad_program_length")
    derived(f, segwit_encode("bc", 1, b"\x00"), "witness v1, 1-byte program", "One zero byte, witness v1", U["bip350"], "bech32m", valid=False, reason="bad_program_length")
    derived(f, segwit_encode("bc", 0, bytes(range(1, 17))), "witness v0, 16-byte program", "Bytes 1..16, witness v0", U["bip173"], "bech32", valid=False, reason="bad_program_length")
    # mutation battery
    bases = valid_rows(f)
    b58b = [r for r in bases if r["address"][0] in "13"]
    segb = [r for r in bases if r["address"].lower().startswith("bc1")]
    battery(f, b58b, skip=("tag_suffix",))
    # bech32 mutations
    seg_rules = [
        ("bech32_substitute_last_char", f_subst_last(f), "the last character replaced"),
        ("bech32_substitute_payload_char", f_subst_mid(f), "a payload character replaced"),
        ("bech32_swap_adjacent_chars", f_swap(f), "two adjacent characters swapped"),
        ("bech32_truncate_last_char", f_trunc, "the last character removed"),
        ("bech32_extend_one_char", f_extend(f), "one character appended"),
        ("bech32_insert_char", f_insert(f), "one character inserted in the middle"),
        ("bech32_whitespace_leading", f_ws_lead, "a leading space added"),
        ("bech32_uri_scheme_prefix", lambda s: SCHEME[f] + s, "wrapped with a URI-style scheme prefix"),
    ]
    for j, (rule, fn, desc) in enumerate(seg_rules):
        fixed = {"bech32_whitespace_leading": "whitespace", "bech32_uri_scheme_prefix": "uri_wrapped"}.get(rule)
        for k in range(len(segb)):
            b = segb[(k + j) % len(segb)]
            mut(b, rule, fn(b["address"]), desc, reason=fixed)
    for b in segb[:5]:
        s = b["address"]
        mixed = s[:len(s) // 2].upper() + s[len(s) // 2:].lower() if s == s.lower() else None
        mut(b, "mixed_case", mixed, "the first half upper-cased, the second half left lower case", reason="mixed_case")
    for b in segb[:5]:
        s = b["address"]
        i = s.index("1", 3) if "1" in s[3:] else None
        mut(b, "excluded_char_in_payload", s[:12] + "b" + s[13:], "a payload character replaced by b, which is outside the Bech32 alphabet", reason="bad_charset")
    for b in b58b[:5]:
        s = b["address"]
        mut(b, "non_base58_char", s[:10] + "0" + s[11:], "a character replaced by 0, which is outside the Base58 alphabet", reason="bad_charset")
    for b in b58b[5:10]:
        s = b["address"]
        mut(b, "non_ascii_lookalike", s[:10] + "а" + s[11:], "a character replaced by CYRILLIC SMALL LETTER A", reason="bad_charset")
    for b in b58b[:5]:
        mut(b, "lowercase_whole", b["address"].lower(), "converted to lower case (Base58 is case sensitive)", reason="bad_checksum")
    for b in b58b[5:10]:
        s = b["address"]
        for i in range(5, len(s)):
            if s[i].isalpha():
                mut(b, "flip_case_of_one_letter", s[:i] + s[i].swapcase() + s[i + 1:], "the case of one letter flipped (Base58 is case sensitive)", reason="bad_checksum")
                break
    _other_family(f, U["bip173"], _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", U["b58c"], "none", reason="empty", rule="empty")
    add(f, "1", "single character", "mutation", "the digit 1 alone, the Base58 encoding of one zero byte", U["b58c"], "none", reason="bad_length", rule="degenerate")


def _other_family(f, url, picks):
    for fam2, o in picks:
        if (f, o) in SEEN:
            continue
        add(f, o, "address of another family", "mutation", "Published address of another family (%s) used as input to this format" % fam2, url, "none", reason="other_family", rule="other_family")


OTHER = {
    "btc": ("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), "evm": ("evm", "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"),
    "tron": ("tron", "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL"), "xrp": ("xrp", "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"),
    "stellar": ("stellar", "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"),
    "ton": ("ton", "EQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPrHF"), "sol": ("sol", "Vote111111111111111111111111111111111111111"),
    "bch": ("bch", "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"), "ltc": ("ltc", "LUEweDxDA4WhvWiNXXSxjM9CYzHPJv4QQF"),
    "doge": ("doge", "DEA5vGb2NpAwCiCp5yTE16F3DueQUVivQp"), "near": ("near", "wrap.near"),
}


def _pick_others(f, n=5):
    order = ["btc", "evm", "tron", "xrp", "stellar", "ton", "sol", "bch", "ltc", "doge", "near"]
    return [OTHER[k] for k in order if k != f][:n]


def fam_ltc():
    f = "ltc"
    for i, (h, d, u, a) in enumerate(H_PKH):
        derived(f, b58check_enc([0x30], h), "P2PKH Base58Check (L...)", "Version byte 0x30 (PUBKEY_ADDRESS) applied to the " + d, U["ltc_cp"], "b58c")
    for i, (h, d, u, a) in enumerate(H_SH[:6]):
        derived(f, b58check_enc([0x32], h), "P2SH Base58Check (M...)", "Version byte 0x32 (SCRIPT_ADDRESS2) applied to the " + d, U["ltc_cp"], "b58c")
    for (h, d, u, a) in H_SH[:6]:
        derived(f, a, "legacy P2SH Base58Check (3...)", "Version byte 0x05 (SCRIPT_ADDRESS) with the " + d + "; the string is the published Bitcoin P2SH address", U["ltc_key"], "b58c",
                notes="Litecoin Core's chainparams.cpp defines SCRIPT_ADDRESS 5 next to SCRIPT_ADDRESS2 50 and key_io.cpp decodes both, so a 3... address is well formed under the Litecoin Core source.")
    for (hx, ver, prog, form, src, u) in [
        ("p2wpkh", 0, BIP173_V0_PKH, "P2WPKH (witness v0, 20-byte program)", "BIP-173 mainnet P2WPKH program with HRP ltc", U["bip173"]),
        ("p2wsh", 0, BIP173_V0_WSH, "P2WSH (witness v0, 32-byte program)", "BIP-173 mainnet P2WSH program with HRP ltc", U["bip173"]),
        ("p2tr", 1, BIP350_V1, "P2TR (witness v1, 32-byte program)", "BIP-350 P2TR program with HRP ltc", U["bip350"]),
        ("v16", 16, bytes.fromhex("751e"), "witness v16, 2-byte program", "BIP-350 witness v16 program with HRP ltc", U["bip350"]),
        ("v2", 2, bytes.fromhex("751e76e8199196d454941c45d1b3a323"), "witness v2, 16-byte program", "BIP-350 witness v2 program with HRP ltc", U["bip350"]),
    ]:
        derived(f, segwit_encode("ltc", ver, prog), form, src, u, "bech32" if ver == 0 else "bech32m",
                notes="Litecoin Core's key_io.cpp follows the Bitcoin Core rules: witness versions 1 to 16 with 2 to 40 byte programs decode." if ver > 1 else "")
    for h, d, u, a in H_PKH[:3]:
        derived(f, segwit_encode("ltc", 0, h), "P2WPKH (witness v0, 20-byte program)", "Witness v0 program from the " + d + " with HRP ltc", U["bip173"], "bech32")
    up = [r for r in ROWS if r["family"] == f and r["address"].startswith("ltc1q")][0]
    derived(f, up["address"].upper(), "P2WPKH, upper case", "Upper-case form of " + up["id"], U["bip173"], "bech32", notes="BIP-173 allows all-uppercase Bech32.")
    # published-source invalid and derived invalid
    h, d, u = ref_hash(0)
    derived(f, b58check_enc([0x00], h), "Bitcoin P2PKH version 0x00", "Version byte 0x00 applied to the " + d, U["ltc_cp"], "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x1E], h), "Dogecoin P2PKH version 0x1e", "Version byte 0x1e applied to the " + d, U["ltc_cp"], "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x6F], h), "testnet P2PKH version 0x6f", "Version byte 0x6f (testnet PUBKEY_ADDRESS) applied to the " + d, U["ltc_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    h2, d2, u2 = ref_hash(0, True)
    derived(f, b58check_enc([0xC4], h2), "testnet P2SH version 0xc4", "Version byte 0xc4 (testnet SCRIPT_ADDRESS) applied to the " + d2, U["ltc_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, b58check_enc([0x3A], h2), "testnet P2SH version 0x3a", "Version byte 0x3a (testnet SCRIPT_ADDRESS2) applied to the " + d2, U["ltc_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, segwit_encode("tltc", 0, BIP173_V0_PKH), "testnet P2WPKH, HRP tltc", "BIP-173 P2WPKH program with HRP tltc", U["ltc_cp"], "bech32", valid=False, reason="wrong_network", net="testnet")
    derived(f, segwit_encode("bc", 0, BIP173_V0_PKH), "Bitcoin HRP bc", "BIP-173 P2WPKH program with HRP bc (the BIP-173 example)", U["bip173"], "bech32", valid=False, reason="bad_prefix") if ("ltc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") not in SEEN else None
    derived(f, segwit_encode("ltc", 0, BIP173_V0_PKH, BECH32M_CONST), "witness v0 with Bech32m constant", "P2WPKH program with HRP ltc and the Bech32m constant", U["bip350"], "bech32m", valid=False, reason="wrong_checksum_constant")
    derived(f, segwit_encode("ltc", 1, BIP350_V1, 1), "witness v1 with Bech32 constant", "P2TR program with HRP ltc and the Bech32 constant", U["bip350"], "bech32", valid=False, reason="wrong_checksum_constant")
    derived(f, segwit_encode("ltc", 0, bytes(range(1, 17))), "witness v0, 16-byte program", "Bytes 1..16, witness v0, HRP ltc", U["bip173"], "bech32", valid=False, reason="bad_program_length")
    derived(f, bech32_encode("ltc", [17] + convertbits(list(BIP173_V0_PKH), 8, 5, True), BECH32M_CONST), "witness version 17", "P2WPKH program with witness version 17, HRP ltc", U["bip350"], "bech32m", valid=False, reason="bad_witness_version")
    bases = valid_rows(f)
    b58b = [r for r in bases if r["address"][0] in "LM3"]
    segb = [r for r in bases if r["address"].lower().startswith("ltc1")]
    battery(f, b58b, skip=("tag_suffix",))
    seg_mutations(f, segb)
    b58_extra(f, b58b)
    _other_family(f, U["ltc_cp"], _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", U["ltc_cp"], "none", reason="empty", rule="empty")


def seg_mutations(f, segb):
    seg_rules = [
        ("bech32_substitute_last_char", f_subst_last(f), "the last character replaced"),
        ("bech32_substitute_payload_char", f_subst_mid(f), "a payload character replaced"),
        ("bech32_swap_adjacent_chars", f_swap(f), "two adjacent characters swapped"),
        ("bech32_truncate_last_char", f_trunc, "the last character removed"),
        ("bech32_extend_one_char", f_extend(f), "one character appended"),
        ("bech32_insert_char", f_insert(f), "one character inserted in the middle"),
        ("bech32_whitespace_leading", f_ws_lead, "a leading space added"),
        ("bech32_uri_scheme_prefix", lambda s: SCHEME[f] + s, "wrapped with a URI-style scheme prefix"),
    ]
    for j, (rule, fn, desc) in enumerate(seg_rules):
        fixed = {"bech32_whitespace_leading": "whitespace", "bech32_uri_scheme_prefix": "uri_wrapped"}.get(rule)
        for k in range(len(segb)):
            b = segb[(k + j) % len(segb)]
            mut(b, rule, fn(b["address"]), desc, reason=fixed)
    for b in segb[:5]:
        s = b["address"]
        if s == s.lower():
            mut(b, "mixed_case", s[:len(s) // 2].upper() + s[len(s) // 2:], "the first half upper-cased, the second half left lower case", reason="mixed_case")
    for b in segb[:5]:
        s = b["address"]
        mut(b, "excluded_char_in_payload", s[:14] + "b" + s[15:], "a payload character replaced by b, which is outside the Bech32 alphabet", reason="bad_charset")


def b58_extra(f, b58b):
    for b in b58b[:5]:
        s = b["address"]
        mut(b, "non_base58_char", s[:10] + "0" + s[11:], "a character replaced by 0, which is outside the Base58 alphabet", reason="bad_charset")
    for b in b58b[5:10]:
        s = b["address"]
        mut(b, "non_ascii_lookalike", s[:10] + "а" + s[11:], "a character replaced by CYRILLIC SMALL LETTER A", reason="bad_charset")
    for b in b58b[:5]:
        mut(b, "lowercase_whole", b["address"].lower(), "converted to lower case (Base58 is case sensitive)", reason="bad_checksum")
    for b in b58b[5:10]:
        s = b["address"]
        for i in range(5, len(s)):
            if s[i].isalpha():
                mut(b, "flip_case_of_one_letter", s[:i] + s[i].swapcase() + s[i + 1:], "the case of one letter flipped (Base58 is case sensitive)", reason="bad_checksum")
                break


def fam_doge():
    f = "doge"
    for (h, d, u, a) in H_PKH:
        derived(f, b58check_enc([0x1E], h), "P2PKH Base58Check (D...)", "Version byte 0x1e (PUBKEY_ADDRESS 30) applied to the " + d, U["doge_cp"], "b58c")
    for (h, d, u, a) in H_SH:
        derived(f, b58check_enc([0x16], h), "P2SH Base58Check (9... or A...)", "Version byte 0x16 (SCRIPT_ADDRESS 22) applied to the " + d, U["doge_cp"], "b58c")
    h, d, u = ref_hash(0)
    derived(f, b58check_enc([0x1E], bytes(20)), "P2PKH of the all-zero hash160", "Version 0x1e followed by 20 zero bytes", U["doge_cp"], "b58c")
    derived(f, b58check_enc([0x00], h), "Bitcoin P2PKH version 0x00", "Version byte 0x00 applied to the " + d, U["doge_cp"], "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x30], h), "Litecoin P2PKH version 0x30", "Version byte 0x30 applied to the " + d, U["doge_cp"], "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x71], h), "testnet P2PKH version 0x71", "Version byte 0x71 (testnet PUBKEY_ADDRESS 113) applied to the " + d, U["doge_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, b58check_enc([0x6F], h), "regtest P2PKH version 0x6f", "Version byte 0x6f (regtest PUBKEY_ADDRESS 111) applied to the " + d, U["doge_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    h2, d2, u2 = ref_hash(1, True)
    derived(f, b58check_enc([0xC4], h2), "testnet P2SH version 0xc4", "Version byte 0xc4 (testnet SCRIPT_ADDRESS 196) applied to the " + d2, U["doge_cp"], "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, b58check_enc([0x05], h2), "Bitcoin P2SH version 0x05", "Version byte 0x05 applied to the " + d2, U["doge_cp"], "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x1E], h[:19]), "19-byte payload", "Version 0x1e with the %s minus its last byte" % d, U["doge_cp"], "b58c", valid=False, reason="bad_length")
    derived(f, b58check_enc([0x1E], h + b"\x01"), "21-byte payload", "Version 0x1e with the %s plus one byte" % d, U["doge_cp"], "b58c", valid=False, reason="bad_length")
    derived(f, segwit_encode("bc", 0, BIP173_V0_PKH), "Bitcoin Bech32 (Dogecoin has no segwit addresses)", "BIP-173 P2WPKH example", U["doge_cp"], "bech32", valid=False, reason="bad_charset",
            notes="chainparams.cpp of Dogecoin defines no bech32 prefix; the string contains characters outside the Base58 alphabet.") if ("doge", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") not in SEEN else None
    bases = valid_rows(f)
    battery(f, bases, skip=("tag_suffix",))
    b58_extra(f, bases)
    _other_family(f, U["doge_cp"], _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", U["doge_cp"], "none", reason="empty", rule="empty")
    add(f, "D", "single character", "mutation", "one character", U["doge_cp"], "none", reason="bad_length", rule="degenerate")


def fam_bch():
    f = "bch"
    ca = U["cashaddr"]
    table = [
        ("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", 0),
        ("bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy", "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR", 0),
        ("bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r", "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb", 0),
        ("bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq", "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", 1),
        ("bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e", "3LDsS579y7sruadqu11beEJoTjdFiFCdX4", 1),
        ("bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37", "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw", 1),
    ]
    for c, leg, t in table:
        pub(f, c, "CashAddr " + ("P2KH (q...)" if t == 0 else "P2SH (p...)") + ", 20-byte hash", "CashAddr specification, Examples of address translation", ca, "cashaddr")
        pub(f, leg, "legacy Base58Check " + ("P2PKH (1...)" if t == 0 else "P2SH (3...)"), "CashAddr specification, Examples of address translation (legacy column)", ca, "b58c",
            notes="The legacy format of the specification is byte-identical to the Bitcoin address of the same hash.")
    large = [
        ("bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", 20), ("bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0", 24),
        ("bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz", 28),
        ("bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake", 32),
        ("bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz", 40),
        ("bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl", 48),
        ("bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f", 56),
        ("bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w", 64),
    ]
    for c, n in large:
        pub(f, c, "CashAddr P2KH (q...), %d-byte hash" % n, "CashAddr specification, Larger Test Vectors (type 0, %d-byte payload)" % n, ca, "cashaddr",
            notes="" if n == 20 else "The specification defines hash sizes from 160 to 512 bits.")
    pub(f, "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t", "CashAddr P2SH, testnet prefix", "CashAddr specification, Larger Test Vectors (bchtest prefix)", ca, "cashaddr", valid=False, reason="wrong_network", net="testnet")
    pub(f, "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5", "CashAddr P2SH, custom prefix pref", "CashAddr specification, Larger Test Vectors (pref prefix)", ca, "cashaddr", valid=False, reason="bad_prefix",
        notes="Well-formed CashAddr, but not under the mainnet prefix bitcoincash.")
    pub(f, "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6", "CashAddr P2SH 32-byte hash, testnet prefix", "CashAddr specification, Larger Test Vectors (bchtest prefix, 32-byte payload)", ca, "cashaddr", valid=False, reason="wrong_network", net="testnet")
    pub(f, "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn", "checksum test string, not an address", "CashAddr specification, checksum test vectors ('do not have a valid payload on purpose')", ca, "cashaddr", valid=False, reason="bad_length",
        notes="The checksum is correct; the payload is not a version byte plus a hash of a defined size.")
    base = [r for r in ROWS if r["family"] == f and r["address"].startswith("bitcoincash:q") and r["spec_valid"]]
    for b in base[:6]:
        derived(f, b["address"][len("bitcoincash:"):], "CashAddr without prefix", "Prefix removed from " + b["id"], ca, "cashaddr", notes="The specification allows omitting the prefix when presented to users.")
    for b in base[:5]:
        derived(f, b["address"].upper(), "CashAddr, all upper case", "Upper-case form of " + b["id"], ca, "cashaddr", notes="The specification accepts all-uppercase CashAddr.")
    for b in base[:3]:
        s = b["address"][len("bitcoincash:"):].upper()
        derived(f, s, "CashAddr without prefix, upper case", "Upper-case, prefix-less form of " + b["id"], ca, "cashaddr")
    # re-encodings of published hash160 values
    for (h, d, u, a) in H_PKH[1:3]:
        derived(f, cash_encode("bitcoincash", 0, h), "CashAddr P2KH (q...), 20-byte hash", "CashAddr encoding of the " + d, ca, "cashaddr")
    for (h, d, u, a) in H_SH[:3]:
        derived(f, cash_encode("bitcoincash", 1, h), "CashAddr P2SH (p...), 20-byte hash", "CashAddr encoding of the " + d, ca, "cashaddr")
    hh = bytes.fromhex("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9")
    derived(f, cash_encode("bitcoincash", 1, hh), "CashAddr P2SH (p...), 20-byte hash", "Type 1 with the payload of the 20-byte test vector of the specification (the specification lists this payload with prefixes bchtest and pref)", ca, "cashaddr")
    derived(f, cash_encode("bitcoincash", 1, bytes.fromhex("3173EF6623C6B48FFD1A3DCC0CC6489B0A07BB47A37F47CFEF4FE69DE825C060")), "CashAddr P2SH, 32-byte hash", "Type 1 with the 32-byte payload of the specification's test vector", ca, "cashaddr")
    derived(f, cash_encode("bitcoincash", 1, bytes.fromhex("D0F346310D5513D9E01E299978624BA883E6BDA8F4C60883C10F28C2967E67EC77ECC7EEEAEAFC6DA89FAD72D11AC961E164678B868AEEEC5F2C1DA08884175B")), "CashAddr P2SH, 64-byte hash", "Type 1 with the 64-byte payload of the specification's test vector", ca, "cashaddr")
    derived(f, cash_encode("bchtest", 0, hh), "CashAddr P2KH, testnet prefix", "Type 0 with the 20-byte test payload under prefix bchtest", ca, "cashaddr", valid=False, reason="wrong_network", net="testnet")
    derived(f, cash_encode("bchreg", 0, hh), "CashAddr P2KH, regtest prefix", "Type 0 with the 20-byte test payload under prefix bchreg", ca, "cashaddr", valid=False, reason="wrong_network", net="testnet")
    derived(f, cash_encode("bitcoincash", 2, hh), "CashAddr with undefined type 2", "Version byte with type bits 2 and the 20-byte size code, valid checksum", ca, "cashaddr", valid=False, reason="bad_version_byte",
            notes="The specification defines type 0 (P2KH) and 1 (P2SH); further types are reserved.")
    # size code does not match
    ver = (0 << 3) | CASH_SIZES[24]
    words = convertbits([ver] + list(hh), 8, 5, True)
    pre = [ord(c) & 31 for c in "bitcoincash"] + [0]
    mod = cash_polymod(pre + words + [0] * 8)
    body = "".join(BECH[w] for w in words + [(mod >> 5 * (7 - i)) & 31 for i in range(8)])
    derived(f, "bitcoincash:" + body, "size code 24 bytes with a 20-byte hash", "Version byte declaring a 24-byte hash followed by 20 bytes, valid checksum", ca, "cashaddr", valid=False, reason="bad_length")
    derived(f, "bitcoincash:" + cash_encode("bitcoincash", 0, hh), "double prefix", "bitcoincash: written twice", ca, "cashaddr", valid=False, reason="bad_prefix",
            notes="The specification says the address must not be double prefixed.")
    mixed = base[0]["address"][:20] + base[0]["address"][20:].upper()
    derived(f, mixed, "mixed case", "First half lower case, second half upper case", ca, "cashaddr", valid=False, reason="mixed_case", notes="The specification: a mixture of lower and upper case must be rejected.")
    legacy = [r for r in ROWS if r["family"] == f and r["address"][0] in "13" and r["spec_valid"]]
    for (h, d, u, a) in H_PKH[:1]:
        derived(f, b58check_enc([0x6F], h), "legacy testnet P2PKH (m/n...)", "Version byte 0x6f applied to the " + d, ca, "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, b58check_enc([0x30], H_PKH[0][0]), "Litecoin-version Base58Check", "Version byte 0x30 applied to the " + H_PKH[0][1], ca, "b58c", valid=False, reason="bad_version_byte")
    # mutation battery on cashaddr and legacy
    cashb = [r for r in valid_rows(f) if r["address"].lower().startswith("bitcoincash:")]
    legb = [r for r in valid_rows(f) if r["address"][0] in "13"]
    battery(f, cashb, skip=("tag_suffix",))
    b58_rules = [
        ("legacy_substitute_last_char", f_subst_last(f), "the last character replaced", None),
        ("legacy_substitute_payload_char", f_subst_mid(f), "a payload character replaced", None),
        ("legacy_truncate_last_char", f_trunc, "the last character removed", None),
        ("legacy_extend_one_char", f_extend(f), "one character appended", None),
    ]
    for j, (rule, fn, desc, rr) in enumerate(b58_rules):
        for k in range(len(legb)):
            b = legb[(k + j) % len(legb)]
            mut(b, rule, fn(b["address"]), desc, reason=rr)
    for b in cashb[:5]:
        s = b["address"]
        mut(b, "excluded_char_in_payload", s[:20] + "b" + s[21:], "a payload character replaced by b, which is outside the CashAddr alphabet", reason="bad_charset")
    for b in cashb[5:10]:
        mut(b, "wrong_prefix_text", "bitcoin" + b["address"][len("bitcoin"):].replace("cash:", "cash1:", 1), "the prefix text changed", reason="bad_prefix")
    for b in cashb[10:15]:
        mut(b, "prefix_only_checksum_reuse", "bchtest:" + b["address"][len("bitcoincash:"):], "the prefix replaced by bchtest with the payload unchanged (the checksum covers the prefix)", reason="bad_checksum")
    _other_family(f, ca, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", ca, "none", reason="empty", rule="empty")
    add(f, "bitcoincash:", "prefix only", "mutation", "the prefix with no payload", ca, "none", reason="bad_length", rule="degenerate")


def fam_zec():
    f = "zec"
    u1 = U["zec_cp"]
    for (h, d, u, a) in H_PKH:
        derived(f, b58check_enc([0x1C, 0xB8], h), "transparent P2PKH (t1...)", "Prefix 0x1cb8 (PUBKEY_ADDRESS) applied to the " + d, u1, "b58c")
    for (h, d, u, a) in H_SH:
        derived(f, b58check_enc([0x1C, 0xBD], h), "transparent P2SH (t3...)", "Prefix 0x1cbd (SCRIPT_ADDRESS) applied to the " + d, u1, "b58c")
    pub(f, "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte", "transparent-source-only address (tex1..., Bech32m)", "ZIP-320 example code (conversion of a tex address to a t1 address)", U["zip320"], "bech32m",
        notes="ZIP-320 defines the TEX address: Bech32m, HRP tex, 20-byte hash with no witness version.")
    raw = bytes(convertbits(list(bech32_decode_words("tex", "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte")), 5, 8, False))
    derived(f, b58check_enc([0x1C, 0xB8], raw), "transparent P2PKH (t1...)", "Prefix 0x1cb8 applied to the 20-byte hash of the ZIP-320 tex example (the t1 address that ZIP-320 derives from it)", U["zip320"], "b58c")
    for (h, d, u, a) in H_PKH[:3]:
        derived(f, bech32_encode("tex", convertbits(list(h), 8, 5, True), BECH32M_CONST), "transparent-source-only address (tex1..., Bech32m)", "ZIP-320 TEX encoding of the " + d, U["zip320"], "bech32m")
    t = [r for r in ROWS if r["family"] == f and r["address"].startswith("tex1")][0]
    derived(f, t["address"].upper(), "tex address, upper case", "Upper-case form of " + t["id"], U["zip320"], "bech32m", notes="Bech32m permits all-uppercase strings.")
    h, d, u = ref_hash(0)
    derived(f, b58check_enc([0x1D, 0x25], h), "testnet P2PKH (tm...)", "Prefix 0x1d25 (testnet PUBKEY_ADDRESS) applied to the " + d, u1, "b58c", valid=False, reason="wrong_network", net="testnet")
    h2, d2, u2 = ref_hash(0, True)
    derived(f, b58check_enc([0x1C, 0xBA], h2), "testnet P2SH (t2...)", "Prefix 0x1cba (testnet SCRIPT_ADDRESS) applied to the " + d2, u1, "b58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, bech32_encode("textest", convertbits(list(h), 8, 5, True), BECH32M_CONST), "testnet tex address (textest1...)", "ZIP-320 testnet TEX encoding (HRP textest) of the " + d, U["zip320"], "bech32m", valid=False, reason="wrong_network", net="testnet")
    derived(f, bech32_encode("tex", convertbits(list(h), 8, 5, True), 1), "tex address with Bech32 constant", "ZIP-320 TEX encoding with the Bech32 constant instead of Bech32m", U["zip320"], "bech32", valid=False, reason="wrong_checksum_constant")
    derived(f, bech32_encode("tex", convertbits(list(h) + [0], 8, 5, True), BECH32M_CONST), "tex address with a 21-byte hash", "ZIP-320 TEX encoding of the hash plus one byte", U["zip320"], "bech32m", valid=False, reason="bad_program_length")
    derived(f, b58check_enc([0x00], h), "Bitcoin P2PKH version 0x00", "Single version byte 0x00 applied to the " + d, u1, "b58c", valid=False, reason="bad_length",
            notes="25 bytes decode where a 26-byte Zcash transparent address is expected.")
    derived(f, b58check_enc([0x1C], h), "one-byte prefix 0x1c", "Prefix byte 0x1c only (one byte of the two-byte prefix) applied to the " + d, u1, "b58c", valid=False, reason="bad_length")
    derived(f, b58check_enc([0x1C, 0xB9], h), "unassigned prefix 0x1cb9", "Prefix 0x1cb9 applied to the " + d, u1, "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0xB8, 0x1C], h), "prefix bytes swapped", "Prefix 0xb81c applied to the " + d, u1, "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x1C, 0xB8], h[:19]), "19-byte hash", "Prefix 0x1cb8 with the %s minus its last byte" % d, u1, "b58c", valid=False, reason="bad_length")
    bases = valid_rows(f)
    t1b = [r for r in bases if r["address"][0] == "t" and not r["address"].startswith("tex")]
    texb = [r for r in bases if r["address"].lower().startswith("tex1")]
    battery(f, t1b, skip=("tag_suffix",))
    b58_extra(f, t1b)
    seg_mutations(f, texb)
    _other_family(f, u1, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", u1, "none", reason="empty", rule="empty")
    add(f, "t1", "prefix only", "mutation", "two characters", u1, "none", reason="bad_length", rule="degenerate")


def bech32_decode_words(hrp, s):
    data = s[len(hrp) + 1:]
    return [BECH.index(c) for c in data][:-6]


SOL_IDS = [
    ("AddressLookupTab1e1111111111111111111111111", "address_lookup_table"), ("BPFLoader2111111111111111111111111111111111", "bpf_loader"),
    ("BPFLoader1111111111111111111111111111111111", "bpf_loader_deprecated"), ("BPFLoaderUpgradeab1e11111111111111111111111", "bpf_loader_upgradeable"),
    ("ComputeBudget111111111111111111111111111111", "compute_budget"), ("Config1111111111111111111111111111111111111", "config"),
    ("Ed25519SigVerify111111111111111111111111111", "ed25519_program"), ("Feature111111111111111111111111111111111111", "feature"),
    ("1nc1nerator11111111111111111111111111111111", "incinerator"), ("LoaderV411111111111111111111111111111111111", "loader_v4"),
    ("NativeLoader1111111111111111111111111111111", "native_loader"), ("KeccakSecp256k11111111111111111111111111111", "secp256k1_program"),
    ("Secp256r1SigVerify1111111111111111111111111", "secp256r1_program"), ("StakeConfig11111111111111111111111111111111", "stake_config"),
    ("Stake11111111111111111111111111111111111111", "stake"), ("11111111111111111111111111111111", "system_program"),
    ("Vote111111111111111111111111111111111111111", "vote"), ("Sysvar1111111111111111111111111111111111111", "sysvar"),
    ("SysvarC1ock11111111111111111111111111111111", "sysvar clock"), ("SysvarEpochRewards1111111111111111111111111", "sysvar epoch_rewards"),
    ("SysvarEpochSchedu1e111111111111111111111111", "sysvar epoch_schedule"),
    ("Sysvar1nstructions1111111111111111111111111", "sysvar instructions"), ("SysvarLastRestartS1ot1111111111111111111111", "sysvar last_restart_slot"),
    ("SysvarRecentB1ockHashes11111111111111111111", "sysvar recent_blockhashes"), ("SysvarRent111111111111111111111111111111111", "sysvar rent"),
    ("SysvarRewards111111111111111111111111111111", "sysvar rewards"), ("SysvarS1otHashes111111111111111111111111111", "sysvar slot_hashes"),
    ("SysvarS1otHistory11111111111111111111111111", "sysvar slot_history"), ("SysvarStakeHistory1111111111111111111111111", "sysvar stake_history"),
    ("ZkTokenProof1111111111111111111111111111111", "zk_token_proof_program"), ("ZkE1Gama1Proof11111111111111111111111111111", "zk_elgamal_proof_program"),
]


def fam_sol():
    f = "sol"
    for a, name in SOL_IDS:
        pub(f, a, "Base58, 32-byte address", "solana-sdk crate solana-sdk-ids: %s program or account ID" % name, U["sol_ids"], "none",
            notes=("Well formed (32 zero bytes: the system program). Whether to refuse it as a recipient is application policy." if a == "1" * 32 else
                   "No checksum: validity means exactly 32 decoded bytes. Program derived addresses and other off-curve values are valid addresses."),
            origin="public-well-known")
    for t, hx in RFC8032_KEYS:
        derived(f, b58enc(bytes.fromhex(hx)), "Base58, 32-byte address", "Base58 encoding of the Ed25519 public key of RFC 8032 section 7.1, %s" % t, U["sol_addr"], "none")
    bases = valid_rows(f)
    # truncation and extension of a checksum-free format: some results stay valid on purpose
    for b in bases[:20]:
        mut(b, "truncate_last_char", b["address"][:-1], "the last character removed", allow_valid=True)
    for b in bases[3:30]:
        mut(b, "extend_one_char", b["address"] + "1", "the character 1 appended", allow_valid=True)
    for b in bases[4:25]:
        mut(b, "substitute_last_char", _rot(f, b["address"], len(b["address"]) - 1), "the last character replaced", allow_valid=True)
    for b in bases[2:30]:
        mut(b, "drop_first_payload_char", b["address"][1:], "the first character removed", allow_valid=True)
    for b in bases[:5]:
        s = b["address"]
        mut(b, "non_base58_char_0", s[:10] + "0" + s[11:], "a character replaced by 0", reason="bad_charset")
    for b in bases[5:10]:
        s = b["address"]
        mut(b, "non_base58_char_O", s[:12] + "O" + s[13:], "a character replaced by O", reason="bad_charset")
    for b in bases[10:15]:
        s = b["address"]
        mut(b, "non_base58_char_l", s[:14] + "l" + s[15:], "a character replaced by l", reason="bad_charset")
    for b in bases[15:20]:
        s = b["address"]
        mut(b, "non_ascii_lookalike", s[:5] + "а" + s[6:], "a character replaced by CYRILLIC SMALL LETTER A", reason="bad_charset")
    for b in bases[:3]:
        mut(b, "hex_form", b58dec(b["address"]).hex(), "the 32 bytes written as 64 hex digits", reason="bad_length", allow_valid=True)
    for b in bases[20:25]:
        mut(b, "doubled_address", b["address"] + b["address"], "the address written twice", reason="bad_length")
    battery(f, bases[5:], skip=("substitute_last_char", "truncate_last_char", "drop_first_payload_char", "extend_one_char", "swap_adjacent_chars", "substitute_payload_char", "substitute_first_payload_char", "insert_char", "tag_suffix"))
    for b in bases[3:8]:
        mut(b, "swap_adjacent_chars", f_swap(f)(b["address"]), "two adjacent characters swapped", allow_valid=True,
            notes="Swapping characters keeps the length: with no checksum the result is again a valid 32-byte address.")
    for b in bases[8:13]:
        mut(b, "substitute_payload_char", f_subst_mid(f)(b["address"]), "a character in the middle replaced", allow_valid=True)
    for b in bases[13:18]:
        mut(b, "tag_suffix", b["address"] + ":1", "a colon suffix appended", reason="extra_data")
    _other_family(f, U["sol_addr"], _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", U["sol_addr"], "none", reason="empty", rule="empty")
    add(f, "1", "single character", "mutation", "one zero byte", U["sol_addr"], "none", reason="bad_length", rule="degenerate")


def fam_tron():
    f = "tron"
    tu = U["tron"]
    pub(f, "TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL", "Base58Check (T...)", "TRON developer documentation, Accounts: address format example", tu, "b58c")
    pub(f, "418840E6C55B9ADA326D211D818C34A994AECED808", "hex form (41 + 20 bytes)", "TRON developer documentation, Accounts: the hex form of the same address", tu, "none",
        notes="The documentation lists the hex form as one of the two address formats.")
    pub(f, "TDp4x8kCJ6aHz8wnqZgkaVQAm2ajH1og3L", "Base58Check (T...)", "TRON developer documentation, Accounts: address derived from the sample public key", tu, "b58c")
    pub(f, "412a260a110bc7b03f19c40a0bd04ff2c5dcb57594", "hex form (41 + 20 bytes), lower case", "TRON developer documentation, Accounts: hex address of the sample public key (printed in lower case)", tu, "none",
        notes="The documentation prints one hex address in upper case and this one in lower case; no case rule is stated, so both cases are treated as valid.")
    derived(f, "412A260A110BC7B03F19C40A0BD04FF2C5DCB57594", "hex form (41 + 20 bytes), upper case", "Upper-case form of the hex address of the sample public key printed in the TRON documentation", tu, "none")
    seen_h = set()
    for i, (h, d, u, a) in enumerate(H_PKH + H_SH):
        if h in seen_h:
            continue
        seen_h.add(h)
        derived(f, b58check_enc([0x41], h), "Base58Check (T...)", "Version byte 0x41 applied to the " + d, tu, "b58c")
    for h, d, u, a in (H_PKH[:3]):
        derived(f, ("41" + h.hex()).upper(), "hex form (41 + 20 bytes)", "0x41 followed by the " + d, tu, "none")
    derived(f, b58check_enc([0x41], bytes(20)), "Base58Check of 41 + 20 zero bytes", "Version byte 0x41 followed by 20 zero bytes", tu, "b58c", notes="Well formed; whether to refuse the all-zero account is application policy.")
    h, d, u = ref_hash(0)
    derived(f, b58check_enc([0x00], h), "Bitcoin P2PKH version 0x00", "Version byte 0x00 applied to the " + d, tu, "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x42], h), "version byte 0x42", "Version byte 0x42 applied to the " + d, tu, "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0xA0], h), "version byte 0xa0", "Version byte 0xa0 applied to the " + d, tu, "b58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x41], h[:19]), "19-byte hash", "Version 0x41 with the %s minus its last byte" % d, tu, "b58c", valid=False, reason="bad_length")
    derived(f, b58check_enc([0x41], h + b"\x00"), "21-byte hash", "Version 0x41 with the %s plus one byte" % d, tu, "b58c", valid=False, reason="bad_length")
    derived(f, "418840E6C55B9ADA326D211D818C34A994AECED8", "hex form without the last byte", "The documented hex address minus its last byte", tu, "none", valid=False, reason="bad_length")
    derived(f, "0x8840E6C55B9ADA326D211D818C34A994AECED808", "Ethereum-form hex without the 41 prefix", "The documentation: the remaining 20 bytes after 41 are the Ethereum-form address", tu, "none", valid=False, reason="other_family",
            notes="A 20-byte Ethereum-form address (see the evm family), not a TRON address string.")
    bases = [r for r in valid_rows(f) if r["address"][0] == "T"]
    battery(f, bases, skip=("tag_suffix",))
    b58_extra(f, bases)
    hexb = [r for r in valid_rows(f) if r["address"].startswith("41")]
    for b in hexb[:3]:
        mut(b, "hex_extend", b["address"] + "0", "one hex digit appended", reason="bad_length")
        mut(b, "hex_non_hex", b["address"][:10] + "G" + b["address"][11:], "a character replaced by G", reason="bad_charset")
    _other_family(f, tu, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", tu, "none", reason="empty", rule="empty")
    add(f, "T", "single character", "mutation", "one character", tu, "none", reason="bad_length", rule="degenerate")


def fam_near():
    f = "near"
    nu = U["near_td"]
    ok = ["aa", "a-a", "a-aa", "100", "0o", "com", "near", "bowen", "b-o_w_e-n", "b.owen", "bro.wen", "a.ha", "a.b-a.ra", "system", "over.9000", "google.com",
          "0o0ooo00oo00o", "10-4.8-2", "no_lols", "0123456789012345678901234567890123456789012345678901234567890123", "near.a"]
    for a in ok:
        pub(f, a, "account ID, valid by the grammar", "near-account-id-rs test data, OK_ACCOUNT_IDS", nu, "none",
            notes=("A 64-character string of digits: valid as an account ID." if len(a) == 64 else ""))
    bad = [
        ("a", "bad_length"), ("A", "bad_length"), ("Abc", "bad_case"), ("-near", "bad_format"), ("near-", "bad_format"), ("-near-", "bad_format"),
        ("near.", "bad_format"), (".near", "bad_format"), ("near@", "bad_charset"), ("@near", "bad_charset"), ("неар", "bad_charset"), ("@@@@@", "bad_charset"),
        ("0__0", "bad_format"), ("0_-_0", "bad_format"), ("..", "bad_format"), ("a..near", "bad_format"), ("nEar", "bad_case"), ("_bowen", "bad_format"),
        ("hello world", "whitespace"), ("abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz", "bad_length"),
        ("01234567890123456789012345678901234567890123456789012345678901234", "bad_length"),         ("sub.buy_d1gitz@atata@b0-rg.c_0_m", "bad_charset"),
    ]
    for a, r in bad:
        pub(f, a, "account ID, published invalid", "near-account-id-rs test data, BAD_ACCOUNT_IDS", nu, "none", valid=False, reason=r,
            notes="One reason is shown; the string may fail several rules." if a in ("A", "..", "@@@@@") else "")
    dd = U["near_docs"]
    pub(f, "4101a46f3ba21613263de3decc83b1a79f745a9a791f570c0bc6df086cb43dbd", "implicit account (64 hex digits)", "NEAR documentation, Address (Account ID): implicit address example", dd, "none")
    pub(f, "0x85f17cf997934a597031b2e18a9ab6ebd4b9f6a4", "Ethereum-like account (0x + 40 hex)", "NEAR documentation, Address (Account ID): Ethereum-like address example", dd, "none")
    pub(f, "0s85f17cf997934a597031b2e18a9ab6ebd4b9f6a4", "deterministic account (0s + 40 hex)", "NEAR documentation, Address (Account ID): deterministic address example", dd, "none")
    pub(f, "0sfa485e3a3e4d6c4ab18b2df9f26631f1485f13c0", "deterministic account (0s + 40 hex)", "NEAR documentation, Address (Account ID): deterministic address example (Hello World contract)", dd, "none")
    pub(f, "0u0000000000000000000000000000000000000000000000000000", "universal account (0u + 52 characters)", "NEAR documentation, Address (Account ID): universal address example", dd, "none",
        notes="Valid by the account-ID grammar.")
    pub(f, "alice.near", "named account", "NEAR documentation, Address (Account ID): named address example", dd, "none")
    pub(f, "sub.account.testnet", "named account (sub account)", "NEAR documentation, Address (Account ID): named address example", dd, "none",
        notes="The grammar does not depend on the network; the .testnet suffix is a convention of the test network.")
    pub(f, "root", "named account", "NEAR documentation, Address (Account ID): valid account ID example", dd, "none")
    pub(f, "some-unique-string", "named account", "NEAR documentation, Address (Account ID): valid account ID example", dd, "none")
    pub(f, "something-to-remember-later", "named account", "NEAR documentation, Address (Account ID): valid account ID example", dd, "none")
    pub(f, "user.name", "named account", "NEAR documentation, Address (Account ID): valid account ID example", dd, "none")
    pub(f, "bob.near", "named account", "NEAR documentation, Address (Account ID): named address example", dd, "none")
    for t, hx in RFC8032_KEYS:
        derived(f, hx, "implicit account (64 hex digits)", "The Ed25519 public key of RFC 8032 section 7.1, %s, as lower-case hex (the implicit-account rule of the NEAR documentation)" % t, dd, "none")
    for r in [r for r in ROWS if r["family"] == "evm" and r["address"] == r["address"].lower() and r["spec_valid"] and len(r["address"]) == 42][:3]:
        derived(f, r["address"], "Ethereum-like account (0x + 40 hex)", "Lower-case EVM address of row %s (the same string)" % r["id"], dd, "none")
    derived(f, "a" * 64, "64 characters", "64 times a", dd, "none", notes="Valid by the grammar.")
    derived(f, "0" * 64, "64 zero digits", "64 zero digits", dd, "none", notes="Well formed. Whether to refuse the all-zero implicit account is application policy.")
    derived(f, "a" * 65, "65 characters", "65 times a", dd, "none", valid=False, reason="bad_length")
    derived(f, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "32-character top-level account", "32 times a", dd, "none",
            notes="Valid by the grammar.")
    derived(f, "11111111111111111111111111111111", "32 digits (also the Solana system program id)", "The Solana system program id, a string of 32 ones, read as a NEAR account ID", dd, "none",
            notes="Valid by the grammar; see cross-family-ambiguities.")
    derived(f, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "Bitcoin Bech32 address read as a NEAR account ID", "BIP-173 P2WPKH example read as a NEAR account ID", dd, "none",
            notes="Valid by the grammar (lower-case letters and digits, 42 characters); see cross-family-ambiguities.")
    derived(f, "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "CashAddr payload read as a NEAR account ID", "The prefix-less CashAddr example of the specification read as a NEAR account ID", dd, "none",
            notes="Valid by the grammar; see cross-family-ambiguities.")
    bases = [r for r in valid_rows(f) if 6 <= len(r["address"]) < 60]
    mutations_near(f, bases)
    _other_family(f, dd, _pick_others(f, 5))
    add(f, "", "empty string", "mutation", "empty string", dd, "none", reason="empty", rule="empty")


def mutations_near(f, bases):
    rules = [
        ("uppercase_whole", lambda s: s.upper(), "converted to upper case", "bad_case"),
        ("uppercase_first_letter", lambda s: next((s[:i] + s[i].upper() + s[i + 1:] for i, c in enumerate(s) if c.isalpha()), None), "the first letter upper-cased", "bad_case"),
        ("trailing_separator", lambda s: s + ".", "a trailing dot", "bad_format"),
        ("leading_separator", lambda s: "." + s, "a leading dot", "bad_format"),
        ("adjacent_separators", lambda s: s[:len(s) // 2] + ".." + s[len(s) // 2:], "two dots inserted", "bad_format"),
        ("dot_then_dash", lambda s: s[:len(s) // 2] + ".-" + s[len(s) // 2:], "a dot and a dash inserted", "bad_format"),
        ("forbidden_char_hash", lambda s: s[:len(s) // 2] + "#" + s[len(s) // 2:], "# inserted", "bad_charset"),
        ("forbidden_char_slash", lambda s: s[:len(s) // 2] + "/" + s[len(s) // 2:], "/ inserted", "bad_charset"),
        ("non_ascii_lookalike", lambda s: s[:1] + "а" + s[2:], "a character replaced by CYRILLIC SMALL LETTER A", "bad_charset"),
        ("extend_to_65", lambda s: (s + "a" * 65)[:65], "padded to 65 characters", "bad_length"),
        ("whitespace_leading", f_ws_lead, "a leading space added", "whitespace"),
        ("whitespace_trailing", f_ws_trail, "a trailing space added", "whitespace"),
        ("whitespace_internal", f_ws_inner, "a space inserted in the middle", "whitespace"),
        ("whitespace_control", f_ws_ctrl, "a leading tab and a trailing line feed", "whitespace"),
        ("uri_scheme_prefix", lambda s: SCHEME[f] + s, "wrapped with a URI-style scheme prefix", "bad_charset"),
        ("query_suffix", lambda s: s + QUERY[f], "a query string appended", "bad_charset"),
        ("tag_suffix", lambda s: s + TAGSUF[f], "a tag suffix appended", "bad_charset"),
        ("prefix_0X_uppercase", lambda s: "0X" + s[2:] if s.startswith("0x") else None, "the 0x prefix upper-cased", "bad_case"),
        ("deterministic_prefix_uppercase", lambda s: "0S" + s[2:] if s.startswith("0s") else None, "the 0s prefix upper-cased", "bad_case"),
        ("underscore_pair", lambda s: s[:len(s) // 2] + "__" + s[len(s) // 2:], "two underscores inserted", "bad_format"),
    ]
    for j, (rule, fn, desc, rr) in enumerate(rules):
        n = len(bases)
        for k in range(n):
            b = bases[(k + j * 3) % n]
            new = fn(b["address"])
            if new is None:
                continue
            mut(b, rule, new, desc, reason=rr)


def fam_ton():
    f = "ton"
    tu = U["ton"]
    pub(f, "EQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPrHF", "user-friendly, bounceable, base64url (EQ...)", "TON documentation, Address formats: Encoding examples (Bounceable)", tu, "crc16t")
    pub(f, "UQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPuwA", "user-friendly, non-bounceable, base64url (UQ...)", "TON documentation, Address formats: Encoding examples (Non-bounceable)", tu, "crc16t")
    pub(f, "kQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPgpP", "user-friendly, bounceable, testnet-only (kQ...)", "TON documentation, Address formats: Encoding examples (Bounceable-Testnet)", tu, "crc16t", valid=False, reason="wrong_network", net="testnet")
    pub(f, "0QDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPleK", "user-friendly, non-bounceable, testnet-only (0Q...)", "TON documentation, Address formats: Encoding examples (Non-bounceable-Testnet)", tu, "crc16t", valid=False, reason="wrong_network", net="testnet")
    pub(f, "0:ca6e321c7cce9ecedf0a8ca2492ec8592494aa5fb5ce0387dff96ef6af982a3e", "raw form workchain:hex", "TON documentation, Address formats: raw format example", tu, "none")
    raw = "ca6e321c7cce9ecedf0a8ca2492ec8592494aa5fb5ce0387dff96ef6af982a3e"
    acct = bytes.fromhex(raw)

    def friendly(flag, wc, acc, std=False):
        body = bytes([flag, wc]) + acc
        full = body + crc16(body).to_bytes(2, "big")
        return base64.b64encode(full).decode() if std else base64.urlsafe_b64encode(full).decode()

    assert friendly(0x11, 0, acct) == "EQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPrHF"
    assert friendly(0x91, 0, acct) == "kQDKbjIcfM6ezt8KjKJJLshZJJSqX7XOA4ff-W72r5gqPgpP"
    derived(f, "0:" + raw.upper(), "raw form, upper-case hex", "The raw example of the documentation with upper-case hex (the documentation allows A-F)", tu, "none")
    derived(f, friendly(0x11, 0, acct, True), "user-friendly, bounceable, standard base64", "The documented bounceable example in the standard base64 alphabet (the documentation says both alphabets are valid)", tu, "crc16t")
    derived(f, friendly(0x51, 0, acct, True), "user-friendly, non-bounceable, standard base64", "The documented non-bounceable example in the standard base64 alphabet", tu, "crc16t")
    derived(f, "-1:" + raw, "raw form on the masterchain", "The raw example with workchain -1 (the documentation names -1 as the masterchain)", tu, "none",
            notes="Valid under the documentation.")
    derived(f, friendly(0x11, 0xFF, acct), "user-friendly, bounceable, masterchain (Ef...)", "The documented bounceable example with workchain byte 0xff (-1)", tu, "crc16t", notes="Valid under the documentation.")
    derived(f, friendly(0x51, 0xFF, acct), "user-friendly, non-bounceable, masterchain (Uf...)", "The documented non-bounceable example with workchain byte 0xff (-1)", tu, "crc16t", notes="Valid under the documentation.")
    derived(f, friendly(0xD1, 0xFF, acct), "user-friendly, non-bounceable, testnet-only, masterchain", "Flags 0xd1 with workchain byte 0xff", tu, "crc16t", valid=False, reason="wrong_network", net="testnet")
    derived(f, friendly(0x13, 0, acct), "user-friendly with undefined flags 0x13", "Flags byte 0x13 with a correct CRC16", tu, "crc16t", valid=False, reason="bad_version_byte")
    derived(f, friendly(0x11, 1, acct), "user-friendly with workchain byte 1", "Workchain 1, which is not 0 or -1", tu, "crc16t", valid=False, reason="bad_format",
            notes="The documentation says the workchain id is a signed byte and names 0 and -1 as the existing workchains; this dataset does not treat other workchains as valid mainnet addresses.")
    for t, hx in RFC8032_KEYS:
        derived(f, "0:" + hx, "raw form workchain:hex", "The 32 bytes of the RFC 8032 section 7.1 public key, %s, as the account id of a raw address" % t, tu, "none")
    for t, hx in RFC8032_KEYS[:3]:
        derived(f, friendly(0x11, 0, bytes.fromhex(hx)), "user-friendly, bounceable, base64url (EQ...)", "Flags 0x11, workchain 0 and the RFC 8032 section 7.1 public key, %s, as the account id" % t, tu, "crc16t")
    for t, hx in RFC8032_KEYS[3:]:
        derived(f, friendly(0x51, 0, bytes.fromhex(hx)), "user-friendly, non-bounceable, base64url (UQ...)", "Flags 0x51, workchain 0 and the RFC 8032 section 7.1 public key, %s, as the account id" % t, tu, "crc16t")
    derived(f, "0:" + "0" * 64, "raw form with all-zero account id", "Workchain 0 and 32 zero bytes", tu, "none", notes="Well formed; application policy decides whether to refuse it.")
    derived(f, "0:" + raw[:-2], "raw form, 62 hex digits", "The raw example minus its last byte", tu, "none", valid=False, reason="bad_length")
    derived(f, "0:" + raw + "00", "raw form, 66 hex digits", "The raw example plus one byte", tu, "none", valid=False, reason="bad_length")
    derived(f, "0x" + raw, "hex without workchain", "The raw account id with a 0x prefix, no workchain", tu, "none", valid=False, reason="bad_length")
    derived(f, raw, "hex without workchain", "The 64 hex digits of the raw example with no workchain prefix", tu, "none", valid=False, reason="bad_length")
    bases = [r for r in valid_rows(f) if not r["address"].startswith(("0:", "-1:")) and r["spec_valid"]]
    battery(f, bases, skip=("tag_suffix", "uri_scheme_prefix"))
    rawb = [r for r in valid_rows(f) if r["address"].startswith("0:")]
    rawrules = [
        ("raw_truncate_last_char", f_trunc, "the last hex digit removed", "bad_length"),
        ("raw_extend_one_char", lambda s: s + "0", "one hex digit appended", "bad_length"),
        ("raw_missing_colon", lambda s: s.replace(":", "", 1), "the colon removed", "bad_length"),
        ("raw_workchain_out_of_range", lambda s: "300" + s[1:], "workchain 300 (outside a signed byte)", "bad_format"),
        ("raw_whitespace_leading", f_ws_lead, "a leading space added", "whitespace"),
        ("raw_uri_scheme_prefix", lambda s: "ton://transfer/" + s, "wrapped with a URI-style prefix", "bad_charset"),
        ("raw_query_suffix", lambda s: s + "?text=12345", "a comment query appended", "bad_charset"),
    ]
    for j, (rule, fn, desc, rr) in enumerate(rawrules):
        for k in range(len(rawb)):
            b = rawb[(k + j) % len(rawb)]
            mut(b, rule, fn(b["address"]), desc, reason=rr)
    for b in bases[3:6]:
        mut(b, "base64_padding_added", b["address"] + "==", "base64 padding appended", reason="bad_length")
    for b in bases[:5]:
        mut(b, "first_char_replaced", "Z" + b["address"][1:], "the first character replaced (changes the flags byte)", reason="bad_checksum")
    for b in bases[:4]:
        s = b["address"]
        if s[0] in "EU":
            mut(b, "bounce_flag_toggled_without_crc", ("U" if s[0] == "E" else "E") + s[1:], "E and U exchanged (flags 0x11 and 0x51) without recomputing the CRC16", reason="bad_checksum")
    _other_family(f, tu, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", tu, "none", reason="empty", rule="empty")
    add(f, "0:", "raw prefix only", "mutation", "workchain and colon, no account id", tu, "none", reason="bad_length", rule="degenerate")


def xaddr_enc(prefix, h, tag):
    flag = 0 if tag is None else 1
    t = (tag or 0).to_bytes(4, "little") + bytes(4)
    return b58check_enc(prefix, h + bytes([flag]) + t, RB58)


def fam_xrp():
    f = "xrp"
    xu = U["xrpl"]
    xl = U["xls5"]
    pub(f, "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh", "classic address (r...)", "XRPL documentation, Addresses: the genesis account", xu, "rb58c")
    pub(f, "rrrrrrrrrrrrrrrrrrrrrhoLvTp", "classic address, ACCOUNT_ZERO", "XRPL documentation, Addresses: special address ACCOUNT_ZERO", xu, "rb58c", notes="Well formed (the XRPL base58 encoding of the value 0); a blackhole address. Application policy decides whether to refuse it.")
    pub(f, "rrrrrrrrrrrrrrrrrrrrBZbvji", "classic address, ACCOUNT_ONE", "XRPL documentation, Addresses: special address ACCOUNT_ONE", xu, "rb58c", notes="Well formed; a blackhole address.")
    pub(f, "rrrrrrrrrrrrrrrrrNAMEtxvNvQ", "classic address, Ripple Name reservation", "XRPL documentation, Addresses: Ripple Name reservation blackhole", xu, "rb58c", notes="Well formed; a blackhole address.")
    pub(f, "rrrrrrrrrrrrrrrrrrrn5RM1rHd", "classic address, NaN", "XRPL documentation, Addresses: the address old JavaScript libraries generated for NaN", xu, "rb58c", notes="Well formed; a blackhole address.")
    pub(f, "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN", "classic address (r...)", "XRPL documentation, Addresses: output of the encode_address.js example", xu, "rb58c")
    pub(f, "rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf", "classic address (r...)", "XLS-5 Tagged Addresses: the classic address of the test table", xl, "rb58c")
    xmain = [
        ("XVLhHMPHU98es4dbozjVtdWzVrDjtV5fdx1mHp98tDMoQXb", None), ("XVLhHMPHU98es4dbozjVtdWzVrDjtV8AqEL4xcZj5whKbmc", 0), ("XVLhHMPHU98es4dbozjVtdWzVrDjtV8xvjGQTYPiAx6gwDC", 1),
        ("XVLhHMPHU98es4dbozjVtdWzVrDjtV8zpDURx7DzBCkrQE7", 2), ("XVLhHMPHU98es4dbozjVtdWzVrDjtVoYiC9UvKfjKar4LJe", 32), ("XVLhHMPHU98es4dbozjVtdWzVrDjtVoKj3MnFGMXEFMnvJV", 276),
        ("XVLhHMPHU98es4dbozjVtdWzVrDjtVozpjdhPQVdt3ghaWw", 65591), ("XVLhHMPHU98es4dbozjVtdWzVrDjtVqrDUk2vDpkTjPsY73", 16781933),
        ("XVLhHMPHU98es4dbozjVtdWzVrDjtV1kAsixQTdMjbWi39u", 4294967294), ("XVLhHMPHU98es4dbozjVtdWzVrDjtV18pX8yuPT7y4xaEHi", 4294967295),
    ]
    for a, tag in xmain:
        pub(f, a, "X-address, " + ("no tag" if tag is None else "tag %d" % tag), "XLS-5 Tagged Addresses, mainnet test table (%s)" % ("no tag" if tag is None else "tag %d" % tag), xl, "rb58c",
            notes="Tagged address of XLS-5 (prefix 0x05 0x44). Valid under XLS-5; the XRP Ledger itself uses classic addresses.")
    for a, tag in [("TVE26TYGhfLC7tQDno7G8dGtxSkYQn49b3qD26PK7FcGSKE", None), ("TVE26TYGhfLC7tQDno7G8dGtxSkYQnSy8RHqGHoGJ59spi2", 0), ("TVE26TYGhfLC7tQDno7G8dGtxSkYQnX8tDFQ53itLNqs6vU", 4294967294)]:
        pub(f, a, "X-address testnet (T...), " + ("no tag" if tag is None else "tag %d" % tag), "XLS-5 Tagged Addresses, testnet test table", xl, "rb58c", valid=False, reason="wrong_network", net="testnet")
    seen_h = set()
    for (h, d, u, a) in H_PKH + H_SH:
        if h in seen_h:
            continue
        seen_h.add(h)
        derived(f, b58check_enc([0x00], h, RB58), "classic address (r...)", "Version byte 0x00 and the XRPL alphabet applied to the " + d, xu, "rb58c")
    for (h, d, u, a), tag in zip(H_PKH[:4], (None, 0, 12345, 4294967295)):
        derived(f, xaddr_enc([0x05, 0x44], h, tag), "X-address, " + ("no tag" if tag is None else "tag %d" % tag), "XLS-5 packing (prefix 0x05 0x44) of the " + d + (" with no tag" if tag is None else " with tag %d" % tag), xl, "rb58c",
                notes="Tagged address of XLS-5.")
    h, d, u = ref_hash(0)
    derived(f, xaddr_enc([0x04, 0x93], h, 7), "X-address testnet (T...), tag 7", "XLS-5 packing with the testnet prefix 0x04 0x93", xl, "rb58c", valid=False, reason="wrong_network", net="testnet")
    derived(f, b58check_enc([0x01], h, RB58), "version byte 0x01", "Version byte 0x01 applied to the " + d, xu, "rb58c", valid=False, reason="bad_version_byte")
    derived(f, b58check_enc([0x00], h, B58), "Bitcoin alphabet instead of the XRPL alphabet", "The " + d + " encoded with version 0x00 in the Bitcoin Base58 alphabet", xu, "b58c", valid=False, reason="bad_checksum",
            notes="The characters are drawn from the same 58 symbols, but the alphabet order differs, so the string decodes to different bytes.")
    derived(f, b58check_enc([0x00], h[:19], RB58), "19-byte account id", "Version 0x00 with the %s minus its last byte" % d, xu, "rb58c", valid=False, reason="bad_length")
    derived(f, b58check_enc([0x00], h + b"\x00", RB58), "21-byte account id", "Version 0x00 with the %s plus one byte" % d, xu, "rb58c", valid=False, reason="bad_length")
    flagbad = b58check_enc([0x05, 0x44], h + bytes([0]) + (5).to_bytes(4, "little") + bytes(4), RB58)
    derived(f, flagbad, "X-address, NO_TAG flag with a non-zero tag field", "XLS-5 packing of the %s with flag 0 and a non-zero tag field" % d, xl, "rb58c", valid=False, reason="bad_format",
            notes="XLS-5: for NO_TAG the remaining 8 bytes must be zero.")
    flagbad2 = b58check_enc([0x05, 0x44], h + bytes([1]) + (5).to_bytes(4, "little") + bytes([0, 0, 0, 1]), RB58)
    derived(f, flagbad2, "X-address, TAG_32 flag with non-zero reserved bytes", "XLS-5 packing of the %s with flag 1 and non-zero upper bytes" % d, xl, "rb58c", valid=False, reason="bad_format",
            notes="XLS-5: for TAG_32 the last 4 bytes must be zero.")
    derived(f, b58check_enc([0x05, 0x44], h[:19] + bytes([0]) + bytes(8), RB58), "X-address with a 19-byte account id", "XLS-5 packing with the account id shortened by one byte", xl, "rb58c", valid=False, reason="bad_length")
    classic = valid_rows(f)
    cl = [r for r in classic if r["address"][0] == "r"]
    xb = [r for r in classic if r["address"][0] == "X"]
    battery(f, cl, skip=("tag_suffix",))
    for j, (rule, fn, desc) in enumerate([
        ("xaddr_substitute_last_char", f_subst_last(f), "the last character replaced"),
        ("xaddr_substitute_payload_char", f_subst_mid(f), "a payload character replaced"),
        ("xaddr_truncate_last_char", f_trunc, "the last character removed"),
        ("xaddr_extend_one_char", f_extend(f), "one character appended"),
        ("xaddr_whitespace_leading", f_ws_lead, "a leading space added"),
        ("xaddr_query_suffix", lambda s: s + "?dt=1", "a destination tag query appended"),
    ]):
        for k in range(len(xb)):
            b = xb[(k + j) % len(xb)]
            mut(b, rule, fn(b["address"]), desc, reason={"xaddr_whitespace_leading": "whitespace", "xaddr_query_suffix": "extra_data"}.get(rule))
    b58_x = cl[:]
    for b in b58_x[:5]:
        s = b["address"]
        mut(b, "non_xrpl_alphabet_char", s[:10] + "0" + s[11:], "a character replaced by 0, which is outside the alphabet", reason="bad_charset")
    for b in b58_x[5:10]:
        s = b["address"]
        mut(b, "non_ascii_lookalike", s[:10] + "а" + s[11:], "a character replaced by CYRILLIC SMALL LETTER A", reason="bad_charset")
    for b in b58_x[:5]:
        mut(b, "lowercase_whole", b["address"].lower(), "converted to lower case (the alphabet is case sensitive)", reason="bad_checksum")
    for b in cl[:6]:
        s = b["address"]
        mut(b, "destination_tag_appended", s + "?dt=12345", "a destination tag appended in query style", reason="extra_data")
    for b in cl[6:10]:
        s = b["address"]
        mut(b, "destination_tag_joined", s + ":12345", "a destination tag appended after a colon", reason="extra_data")
    _other_family(f, xu, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", xu, "none", reason="empty", rule="empty")
    add(f, "r", "single character", "mutation", "the character r alone", xu, "none", reason="bad_length", rule="degenerate")


def fam_stellar():
    f = "stellar"
    su = U["sep23"]
    G = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
    pub(f, G, "account ID (G...)", "SEP-23 valid test case: non-multiplexed account", su, "crc16s")
    pub(f, "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ", "muxed account (M...), id 0", "SEP-23 valid test case: multiplexed account", su, "crc16s",
        notes="A muxed account is an account ID with a 64-bit id; SEP-23 defines it as an address form.")
    pub(f, "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK", "muxed account (M...), id 2^64-1", "SEP-23 valid test case: multiplexed account with the maximum unsigned id", su, "crc16s",
        notes="")
    pub(f, "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA", "contract ID (C...)", "SEP-23 valid test case: contract", su, "crc16s",
        notes="A contract address of the smart-contract platform.")
    pub(f, "LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN", "pool ID (L...)", "SEP-23 valid test case: pool address", su, "crc16s", valid=False, reason="not_address_type",
        notes="A valid strkey, but a pool identifier, not an address to which a payment is sent. This dataset treats G, M and C strkeys as addresses.")
    pub(f, "BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU", "claimable balance ID (B...)", "SEP-23 valid test case: claimable balance address", su, "crc16s", valid=False, reason="not_address_type",
        notes="A valid strkey, but a balance identifier, not an address to which a payment is sent. This dataset treats G, M and C strkeys as addresses.")
    pub(f, "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM", "signed payload (P...)", "SEP-23 valid test case: signed payload with a 32-byte payload", su, "crc16s", valid=False, reason="not_address_type",
        notes="A valid strkey (a signer), not an address. This dataset treats G, M and C strkeys as addresses.")
    inv = [
        ("GAAAAAAAACGC6", "Invalid length (Ed25519 should be 32 bytes, not 5)", "bad_length"),
        ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR", "The unused trailing bit must be zero", "bad_padding"),
        ("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA", "Invalid length (congruent to 1 mod 8)", "bad_length"),
        ("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI", "Invalid length (base-32 decoding should yield 35 bytes, not 36)", "bad_length"),
        ("G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I", "Invalid algorithm (low 3 bits of version byte are 7)", "bad_version_byte"),
        ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA", "Invalid length (congruent to 6 mod 8)", "bad_length"),
        ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I", "Invalid length (base-32 decoding should yield 43 bytes, not 44)", "bad_length"),
        ("M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ", "Invalid algorithm (low 3 bits of version byte are 7)", "bad_version_byte"),
        ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===", "Padding bytes are not allowed", "bad_charset"),
        ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO", "Invalid checksum", "bad_checksum"),
    ]
    for a, why, r in inv:
        pub(f, a, "strkey, published invalid", "SEP-23 invalid test case: " + why, su, "crc16s", valid=False, reason=r,
            notes="One reason is shown; the string may fail several rules." if r in ("bad_length",) else "")
    for t, hx in RFC8032_KEYS:
        k = bytes.fromhex(hx)
        derived(f, strkey_enc(6 << 3, k), "account ID (G...)", "StrKey encoding (version byte 6<<3) of the Ed25519 public key of RFC 8032 section 7.1, %s" % t, su, "crc16s")
        derived(f, strkey_enc(2 << 3, k), "contract ID (C...)", "StrKey encoding (version byte 2<<3) of the 32 bytes of the RFC 8032 section 7.1 public key, %s" % t, su, "crc16s",
                notes="A deterministic re-encoding of a published 32-byte value; not a deployed contract.")
    derived(f, strkey_enc(6 << 3, bytes(32)), "account ID (G...) of the all-zero key", "StrKey encoding of 32 zero bytes", su, "crc16s", notes="Well formed; application policy decides whether to refuse it.")
    k = bytes.fromhex(RFC8032_KEYS[0][1])
    derived(f, strkey_enc(6 << 3 | 7, k), "strkey with algorithm bits 7", "Version byte 6<<3 | 7 with a correct CRC16", su, "crc16s", valid=False, reason="bad_version_byte")
    derived(f, strkey_enc(19 << 3, k), "pre-authorised transaction hash (T...)", "StrKey encoding of 32 bytes with version byte 19<<3", su, "crc16s", valid=False, reason="not_address_type",
            notes="A valid strkey, but a transaction-hash signer, not an address. No secret key is encoded.")
    derived(f, strkey_enc(23 << 3, k), "SHA-256 hash signer (X...)", "StrKey encoding of 32 bytes with version byte 23<<3", su, "crc16s", valid=False, reason="not_address_type",
            notes="A valid strkey, but a hash signer, not an address. No secret key is encoded.")
    derived(f, strkey_enc(6 << 3, k[:31]), "account ID with 31 payload bytes", "Version byte 6<<3 and the public key minus its last byte", su, "crc16s", valid=False, reason="bad_length")
    derived(f, strkey_enc(6 << 3, k + b"\x00"), "account ID with 33 payload bytes", "Version byte 6<<3 and the public key plus one zero byte", su, "crc16s", valid=False, reason="bad_length")
    raw = bytes([6 << 3]) + k
    badcrc = raw + bytes([crc16(raw) & 255, (crc16(raw) >> 8) ^ 1])
    derived(f, b32enc(badcrc), "account ID with the CRC16 high byte altered", "A correct strkey of the RFC 8032 key with the high CRC16 byte XOR 1", su, "crc16s", valid=False, reason="bad_checksum")
    swapped = raw + bytes([crc16(raw) >> 8, crc16(raw) & 255])
    derived(f, b32enc(swapped), "account ID with the CRC16 in big-endian order", "A strkey of the RFC 8032 key with the two CRC16 bytes in big-endian order", su, "crc16s", valid=False, reason="bad_checksum",
            notes="SEP-23 writes the CRC16 little-endian.")
    bases = [r for r in valid_rows(f) if r["address"][0] == "G"]
    battery(f, bases, skip=("tag_suffix",))
    allb = [r for r in valid_rows(f)]
    for b in [r for r in allb if r["address"][0] in "MC"][:6]:
        mut(b, "muxed_contract_substitute_last_char", f_subst_last(f)(b["address"]), "the last character replaced", reason="bad_checksum")
    for b in bases[:5]:
        mut(b, "lowercase_whole", b["address"].lower(), "converted to lower case (strkeys are upper case)", reason="bad_charset")
    for b in bases[5:10]:
        mut(b, "base32_padding_added", b["address"] + "====", "base32 padding appended", reason="bad_charset")
    for b in bases[:5]:
        mut(b, "base32_excluded_digit", b["address"][:10] + "1" + b["address"][11:], "a character replaced by 1, which is outside the base32 alphabet", reason="bad_charset")
    for b in bases[5:10]:
        mut(b, "non_ascii_lookalike", b["address"][:10] + "А" + b["address"][11:], "a character replaced by CYRILLIC CAPITAL LETTER A", reason="bad_charset")
    for b in bases[:3]:
        mut(b, "memo_suffix", b["address"] + ":12345", "a memo appended after a colon", reason="extra_data")
    _other_family(f, su, _pick_others(f))
    add(f, "", "empty string", "mutation", "empty string", su, "none", reason="empty", rule="empty")
    add(f, "G", "single character", "mutation", "the letter G alone", su, "none", reason="bad_length", rule="degenerate")


# ---------------------------------------------------------------------------
# cross-family ambiguities
# ---------------------------------------------------------------------------
def valid_families(s):
    return [fam for fam in FAMILIES if classify(fam, s)[0]]


def build_ambiguities():
    out = []

    def same_string(s, expect, what, src, url, notes=""):
        got = valid_families(s)
        if sorted(got) != sorted(expect):
            raise SystemExit("ambiguity %r: classify says %s, declared %s" % (s, got, expect))
        out.append({"kind": "same_string" if len(got) > 1 else "not_ambiguous_control", "string": s, "families_valid": got, "related": [], "what_it_shows": what, "source": src, "source_url": url, "notes": notes})

    def same_bytes(s, related, what, src, url, notes=""):
        for item in related:
            fam, addr = item.split(":", 1)
            if not classify(fam, addr)[0]:
                raise SystemExit("same_bytes related %r is not valid" % item)
        out.append({"kind": "same_bytes", "string": s, "families_valid": valid_families(s), "related": related, "what_it_shows": what, "source": src, "source_url": url, "notes": notes})

    same_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", ["btc", "bch"],
                "Base58Check version 0x00: the Bitcoin P2PKH string is also the legacy-format Bitcoin Cash address of the same hash. Nothing in the string says which chain it is for.",
                "Bitcoin genesis-block address (Bitcoin Wiki); CashAddr specification, legacy format", U["cashaddr"])
    same_string("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", ["btc", "ltc", "bch"],
                "Base58Check version 0x05: a Bitcoin P2SH address is byte-identical to a legacy Litecoin P2SH address (version 5, SCRIPT_ADDRESS) and to a legacy Bitcoin Cash P2SH address.",
                "Bitcoin Wiki Address page; Litecoin Core chainparams.cpp and key_io.cpp; CashAddr specification", U["ltc_key"],
                "Litecoin also uses version 0x32 (M...) for P2SH. A 3... string sent to the wrong chain is a valid address there, controlled by the holder of the script.")
    same_string("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", ["evm", "near"],
                "A lower-case 0x + 40 hex string is an EVM address (no checksum asserted) and a NEAR Ethereum-like account ID.",
                "EIP-55 test case in lower case; NEAR documentation, Ethereum-like address", U["near_docs"])
    same_string("11111111111111111111111111111111", ["sol", "near"],
                "The Solana system program id (32 zero bytes in Base58) is also a well-formed NEAR account ID (32 digits).",
                "solana-sdk-ids (system program); near-account-id-rs validation rules", U["near_val"])
    same_string("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", ["btc", "near"],
                "A lower-case Bitcoin Bech32 address satisfies the NEAR account ID grammar (lower-case letters and digits, 42 characters).",
                "BIP-173 example; near-account-id-rs validation rules", U["near_val"],
                "An application that accepts a NEAR account ID after a Bitcoin address was pasted into the wrong field cannot tell from the string alone.")
    same_string("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", ["bch", "near"],
                "A CashAddr without its prefix is a well-formed NEAR account ID.",
                "CashAddr specification example without prefix; near-account-id-rs validation rules", U["near_val"])
    same_string("0x52908400098527886E0F7030069857D2E4169EE7", ["evm"],
                "Upper-case hex digits are valid for EVM but not for NEAR (account IDs are lower case), so this string is not ambiguous with NEAR.",
                "EIP-55 test case", U["eip55"])
    same_string("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", ["near"],
                "64 lower-case hex digits: a NEAR implicit account ID and also the usual hex form of a 32-byte Ed25519 public key; it contains 0 and is not Base58, so it is not a Solana address.",
                "RFC 8032 section 7.1 test 1 public key; NEAR documentation, implicit address", U["near_docs"])
    pk = H_PKH[0][0]
    same_bytes(H_PKH[0][3], ["ltc:" + b58check_enc([0x30], pk), "doge:" + b58check_enc([0x1E], pk), "zec:" + b58check_enc([0x1C, 0xB8], pk), "tron:" + b58check_enc([0x41], pk),
                             "xrp:" + b58check_enc([0x00], pk, RB58), "bch:" + cash_encode("bitcoincash", 0, pk), "btc:" + segwit_encode("bc", 0, pk)],
               "The same 20-byte hash160 of the Bitcoin genesis-block address appears under seven address encodings: the strings differ, the bytes are the same. Whoever holds the key for one holds it for all of them.",
               "Bitcoin Wiki Genesis block page; the encodings of each family", U["b58c"],
               "A different version byte or alphabet is the only thing separating them; Base58Check detects a wrong version only if the receiver checks it.")
    k1 = RFC8032_KEYS[0][1]
    same_bytes("0:" + k1, ["near:" + k1, "sol:" + b58enc(bytes.fromhex(k1)), "stellar:" + strkey_enc(6 << 3, bytes.fromhex(k1))],
               "The 32-byte Ed25519 public key of RFC 8032 test 1 as a TON raw account id, a NEAR implicit account, a Solana address and a Stellar account ID.",
               "RFC 8032 section 7.1", U["rfc8032"], "A TON account id is a contract-state hash, not a public key; the raw form is only used here as a 32-byte container.")
    same_bytes("0x8840E6C55B9ADA326D211D818C34A994AECED808", ["tron:TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL", "tron:418840E6C55B9ADA326D211D818C34A994AECED808"],
               "The 20 bytes after the 41 prefix of a TRON hex address are the Ethereum-form address; TRON documentation says so.",
               "TRON developer documentation, Accounts", U["tron"], "The 0x-prefixed string with upper-case letters and no lower-case letters is a valid EVM string (single case).")
    out[-1]["families_valid"] = valid_families("0x8840E6C55B9ADA326D211D818C34A994AECED808")
    same_bytes("0x27b1FdB04752BBc536007A920D24ACB045561c26", ["evm:0x27b1fdb04752bbc536007a920d24acb045561c26"],
               "Same 20 bytes, two checksum conventions: the capitalisation above is the EIP-1191 checksum for chain id 30 (RSK mainnet); it is not the EIP-55 capitalisation, so an EIP-55 validator rejects it.",
               "EIP-1191 test cases, list rsk_mainnet", U["eip1191"], "The lower-case form of the same bytes is valid EVM (no checksum asserted).")
    for i, o in enumerate(out):
        o["id"] = "amb-%04d" % (i + 1)
    return out


FAMILY_TABLE = [
    dict(family="evm", name="EVM-style accounts (Ethereum and the chains that reuse its address format)", chain_caip2=["eip155:{chainId}"],
         alphabet="hexadecimal digits 0-9, a-f, A-F", lengths="42 characters (0x + 40 hex digits = 20 bytes)", prefixes="0x", checksum_algorithm="optional EIP-55 mixed-case checksum (Keccak-256 of the lower-case hex)",
         case_rules="all lower case or all upper case letters: no checksum asserted; mixed case: must equal the EIP-55 capitalisation; EIP-1191 defines a different capitalisation for some chains",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["eip55"], U["eip1191"], U["jsonrpc"]]),
    dict(family="btc", name="Bitcoin", chain_caip2=["bip122:000000000019d6689c085ae165831e93"], alphabet="Base58 (Bitcoin alphabet) for legacy forms; Bech32 for segwit forms",
         lengths="25-byte Base58Check payload (26-35 characters); Bech32 up to 90 characters", prefixes="version 0x00 (1...) and 0x05 (3...); HRP bc, witness version 0 (Bech32) or 1-16 (Bech32m)",
         checksum_algorithm="Base58Check (double SHA-256); Bech32 / Bech32m", case_rules="Base58 case sensitive; Bech32 all lower or all upper case, never mixed",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["b58c"], U["bip13"], U["bip173"], U["bip350"], U["bip84"], U["bip86"]]),
    dict(family="ltc", name="Litecoin", chain_caip2=["bip122:12a765e31ffd4059bada1e25190f6e98"], alphabet="Base58 for legacy forms; Bech32 for segwit forms",
         lengths="25-byte Base58Check payload; Bech32 up to 90 characters", prefixes="version 0x30 (L...), 0x32 (M...), 0x05 (3...); HRP ltc",
         checksum_algorithm="Base58Check (double SHA-256); Bech32 / Bech32m", case_rules="Base58 case sensitive; Bech32 all lower or all upper case",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["ltc_cp"], U["ltc_key"], U["bip173"], U["bip350"]]),
    dict(family="doge", name="Dogecoin", chain_caip2=["bip122:1a91e3dace36e2be3bf030a65679fe82"], alphabet="Base58", lengths="25-byte Base58Check payload (33-34 characters)",
         prefixes="version 0x1e (D...) and 0x16 (9... or A...)", checksum_algorithm="Base58Check (double SHA-256)", case_rules="case sensitive",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["doge_cp"], U["b58c"]]),
    dict(family="bch", name="Bitcoin Cash", chain_caip2=["bip122:000000000000000000651ef99cb9fcbe"], alphabet="CashAddr base32 (the Bech32 alphabet); Base58 for the legacy form",
         lengths="CashAddr: 42 characters after the prefix for a 20-byte hash, up to 102 for 64 bytes; legacy: 25-byte payload", prefixes="CashAddr prefix bitcoincash (may be omitted), type 0 (q...) and 1 (p...); legacy versions 0x00 and 0x05",
         checksum_algorithm="CashAddr BCH code (40 bits); Base58Check for the legacy form", case_rules="CashAddr all lower or all upper case, never mixed; legacy case sensitive",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["cashaddr"]]),
    dict(family="zec", name="Zcash (transparent forms)", chain_caip2=[], alphabet="Base58 (t1..., t3...); Bech32m (tex1...)", lengths="26-byte Base58Check payload (35 characters); tex: 43 characters",
         prefixes="two-byte versions 0x1cb8 (t1...) and 0x1cbd (t3...); HRP tex", checksum_algorithm="Base58Check (double SHA-256); Bech32m", case_rules="Base58 case sensitive; tex all lower or all upper case",
         memo_or_tag_convention="none", memo_notes="transparent addresses carry no memo; shielded outputs have an encrypted memo field (no shielded vectors in this release)", spec_urls=[U["zec_cp"], U["zip320"]]),
    dict(family="sol", name="Solana", chain_caip2=["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"], alphabet="Base58 (Bitcoin alphabet)", lengths="32 to 44 characters; decodes to exactly 32 bytes",
         prefixes="none", checksum_algorithm="none", case_rules="case sensitive", memo_or_tag_convention="none",
         memo_notes="no address-level memo", spec_urls=[U["sol_addr"], U["sol_ids"]]),
    dict(family="tron", name="TRON", chain_caip2=["tron:728126428"], alphabet="Base58 (Bitcoin alphabet); hex form", lengths="Base58Check: 34 characters; hex: 42 characters",
         prefixes="version byte 0x41 (T...)", checksum_algorithm="Base58Check (double SHA-256); none for the hex form", case_rules="Base58 case sensitive; hex form: either case (the documentation prints both)",
         memo_or_tag_convention="none", memo_notes="no address-level memo", spec_urls=[U["tron"]]),
    dict(family="near", name="NEAR", chain_caip2=[], alphabet="lower-case letters, digits, and the separators . - _", lengths="2 to 64 characters",
         prefixes="none; implicit accounts are 64 hex digits, Ethereum-like 0x + 40 hex, deterministic 0s + 40 hex, universal 0u + 52 characters (all satisfy the same grammar)",
         checksum_algorithm="none", case_rules="lower case only", memo_or_tag_convention="memo",
         memo_notes="no address-level memo; NEP-141 fungible-token transfers take an optional memo argument and custodial deposit services may require one", spec_urls=[U["near_docs"], U["near_td"], U["near_val"]]),
    dict(family="ton", name="TON", chain_caip2=[], alphabet="user-friendly: base64 or base64url; raw: workchain, colon, 64 hex digits", lengths="user-friendly: 48 characters (36 bytes); raw: 64 hex digits after the colon",
         prefixes="flags 0x11 (E...) bounceable, 0x51 (U...) non-bounceable, +0x80 testnet-only (k..., 0...); workchain 0 or -1", checksum_algorithm="CRC16-XMODEM (big-endian) for the user-friendly form; none for raw",
         case_rules="base64 case sensitive; raw hex either case", memo_or_tag_convention="comment",
         memo_notes="transfer messages can carry a plaintext comment; deposit services commonly use it as a tag", spec_urls=[U["ton"], "https://docs.ton.org/v3/documentation/smart-contracts/message-management/internal-messages"]),
    dict(family="xrp", name="XRP Ledger", chain_caip2=["xrpl:0"], alphabet="XRPL Base58 (rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz)", lengths="classic: 25 to 35 characters; X-address: 47 characters",
         prefixes="classic version 0x00 (r...); X-address prefix 0x05 0x44 (X...), testnet 0x04 0x93 (T...)", checksum_algorithm="Base58Check with the XRPL alphabet (double SHA-256)", case_rules="case sensitive",
         memo_or_tag_convention="destination_tag", memo_notes="32-bit unsigned destination tag, carried in the transaction or packed into an X-address", spec_urls=[U["xrpl"], U["xls5"]]),
    dict(family="stellar", name="Stellar", chain_caip2=["stellar:pubnet"], alphabet="RFC 4648 base32, upper case, no padding", lengths="G and C: 56 characters; M: 69 characters",
         prefixes="G (account ID), M (muxed account), C (contract)", checksum_algorithm="CRC16-XMODEM (little-endian) over version byte and payload", case_rules="upper case only",
         memo_or_tag_convention="memo", memo_notes="transactions carry a memo; custodial deposits commonly require one (SEP-29); an M address embeds a 64-bit id", spec_urls=[U["sep23"], "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0029.md"]),
]


# ---------------------------------------------------------------------------
# 4. writers
# ---------------------------------------------------------------------------
COLUMNS = [
    "id", "family", "chain_caip2", "network", "address", "encoding_form", "checksum_algorithm", "spec_valid", "reason",
    "memo_or_tag_convention", "origin", "source", "source_url", "notes", LIB_COLUMN,
]


def build_all():
    for fam in FAMILIES:
        globals()["fam_" + fam]()
    amb = build_ambiguities()
    return amb


def load_library_results():
    path = os.path.join(HERE, "library-results.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {(r["family"], r["address"]): r["valid"] for r in data["results"]}


def policy_note(r):
    """Why library 1.0.0 differs from the specification on this row (spec valid, library refuses)."""
    fam, a, form = r["family"], r["address"], r["encoding_form"].lower()
    zero = ("all-zero" in form or "zero address" in form or "account_zero" in form or "41 + 20 zero" in form or "64 zero digits" in form
            or (a == "1" * 32 and fam == "sol") or a == "0" * 64 or a.startswith("0:" + "0" * 64))
    if zero:
        return "the library refuses all-zero values (application policy); the encoding itself is well formed"
    if fam in ("btc", "ltc") and (a.lower().startswith(("bc1", "ltc1"))):
        low = a.lower()
        words = [BECH.index(c) for c in low[low.rfind("1") + 1:-6]]
        ver, prog = words[0], convertbits(words[1:], 5, 8, False)
        if a != low:
            return "the library accepts lower-case Bech32 only; BIP-173 also allows an all-upper-case string"
        if ver > 1 or (ver == 1 and len(prog) != 32):
            return "the library accepts witness version 0 (20 or 32 bytes) and version 1 (32 bytes) only; BIP-350 defines versions 2 to 16 and 2 to 40 byte programs as valid"
    if fam == "ltc" and a[0] == "3":
        return "the library treats 3... as a Bitcoin P2SH string and refuses it for Litecoin (pitfall ltc-legacy-3-prefix); Litecoin Core accepts version 5"
    if fam == "bch":
        if a[0] in "13":
            return "the library accepts CashAddr only and refuses the legacy Base58 form"
        if a == a.upper() and a != a.lower():
            return "the library accepts lower-case CashAddr only; the specification also accepts all upper case"
        return "the library accepts 20-byte CashAddr hashes only; the specification defines sizes from 20 to 64 bytes"
    if fam == "near":
        return "the library accepts a top-level (dot-free) ID of 32 or more characters only as 64 hex digits, 0x + 40 hex or 0s + 40 hex; the grammar allows any such lower-case string"
    if fam == "stellar":
        return "the library accepts G... account IDs only"
    if fam == "ton":
        return "the library accepts workchain 0 only"
    if fam == "tron":
        return "the library accepts Base58Check only, and refuses the all-zero account" if "zero" in form else "the library accepts the Base58Check form only"
    if fam == "xrp":
        return "the library accepts classic addresses only and refuses X-addresses"
    if fam == "zec":
        return "the library accepts Base58Check transparent addresses only (t1..., t3...)"
    return "UNEXPLAINED"


def finalize_rows(lib):
    out = []
    unexplained = []
    for r in ROWS:
        row = {c: r[c] for c in COLUMNS if c != LIB_COLUMN}
        v = lib.get((r["family"], r["address"]))
        row[LIB_COLUMN] = v
        if v is not None and v != r["spec_valid"]:
            note = policy_note(r)
            if note == "UNEXPLAINED":
                unexplained.append(r["id"])
            row["notes"] = (row["notes"] + " " if row["notes"] else "") + "Library 1.0.0: " + note + "."
        out.append(row)
    if unexplained:
        print("WARNING: unexplained divergences:", unexplained)
    return out


def csv_bool(v):
    return "" if v is None else ("true" if v else "false")


def write_csv(path, rows, cols, listcols=(), boolcols=()):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
        w.writerow(cols)
        for r in rows:
            line = []
            for c in cols:
                v = r[c]
                if c in boolcols:
                    line.append(csv_bool(v))
                elif c in listcols:
                    line.append(json.dumps(v, ensure_ascii=False, separators=(",", ":")))
                else:
                    line.append(v)
            w.writerow(line)


def write_json(path, rows):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=1)
        fh.write("\n")


def main():
    amb = build_all()
    lib = load_library_results()
    rows = finalize_rows(lib)
    data = os.path.join(ROOT, "data")
    os.makedirs(data, exist_ok=True)
    write_csv(os.path.join(data, "address-vectors.csv"), rows, COLUMNS, boolcols=("spec_valid", LIB_COLUMN))
    write_json(os.path.join(data, "address-vectors.json"), rows)
    fam_cols = ["family", "name", "chain_caip2", "alphabet", "lengths", "prefixes", "checksum_algorithm", "case_rules", "memo_or_tag_convention", "memo_notes", "spec_urls"]
    fam_rows = [{c: f[c] for c in fam_cols} for f in FAMILY_TABLE]
    write_csv(os.path.join(data, "address-families.csv"), fam_rows, fam_cols, listcols=("chain_caip2", "spec_urls"))
    write_json(os.path.join(data, "address-families.json"), fam_rows)
    amb_cols = ["id", "kind", "string", "families_valid", "related", "what_it_shows", "source", "source_url", "notes"]
    write_csv(os.path.join(data, "cross-family-ambiguities.csv"), amb, amb_cols, listcols=("families_valid", "related"))
    write_json(os.path.join(data, "cross-family-ambiguities.json"), [{c: a[c] for c in amb_cols} for a in amb])
    import docs  # noqa: E402  (documentation writer, same directory)
    docs.write_all(ROOT, rows, fam_rows, amb, FAMILIES, REASONS, RULECOUNT, ROWS, VERSION, RELEASE_DATE, LIB_COLUMN, U)
    print("rows %d, families %d, ambiguities %d, library column %s" % (len(rows), len(FAMILIES), len(amb), "filled" if lib else "empty"))


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    main()
