#!/usr/bin/env python3
"""Independent verifier for the address format test vectors.

Written from the specifications. It imports nothing from build.py, docs.py or from the
library under comparison, and it does not read scripts/library-results.json. Python 3
standard library only; no network access.

For every row it recomputes `spec_valid` and the set of reasons that apply to the string,
and exits with status 1 on any disagreement with the data files.

    python3 scripts/verify.py [--data DIR]
"""
import base64
import csv
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------------------------
# Keccak-256 (FIPS 202 permutation, original Keccak padding 0x01) with a 5x5 lane matrix
# ---------------------------------------------------------------------------------------------
MASK = (1 << 64) - 1


def _lfsr_bit(t):
    if t % 255 == 0:
        return 1
    r = 1
    for _ in range(t % 255):
        r <<= 1
        if r & 0x100:
            r ^= 0x171
    return r & 1


ROUND_CONSTANTS = []
for _i in range(24):
    _c = 0
    for _j in range(7):
        if _lfsr_bit(_j + 7 * _i):
            _c |= 1 << ((1 << _j) - 1)
    ROUND_CONSTANTS.append(_c)

RHO = [[0] * 5 for _ in range(5)]
_x, _y = 1, 0
for _t in range(24):
    RHO[_x][_y] = ((_t + 1) * (_t + 2) // 2) % 64
    _x, _y = _y, (2 * _x + 3 * _y) % 5


def _rotl(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK


def _permute(lanes):
    for rc in ROUND_CONSTANTS:
        c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                lanes[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(lanes[x][y], RHO[x][y])
        for x in range(5):
            for y in range(5):
                lanes[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y] & MASK)
        lanes[0][0] ^= rc
    return lanes


def keccak256(data):
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] ^= 0x80
    lanes = [[0] * 5 for _ in range(5)]
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lanes[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        lanes = _permute(lanes)
    out = b""
    for i in range(4):
        out += lanes[i % 5][i // 5].to_bytes(8, "little")
    return out


assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


def eip55_capitalisation(hex40):
    h = keccak256(hex40.lower().encode()).hex()
    return "".join(ch.upper() if int(h[i], 16) >= 8 else ch for i, ch in enumerate(hex40.lower()))


# ---------------------------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------------------------
ALPHA_BTC = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHA_XRP = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
assert len(set(ALPHA_BTC)) == 58 and len(set(ALPHA_XRP)) == 58 and set(ALPHA_BTC) == set(ALPHA_XRP)


def base58_decode(text, alphabet):
    """bytes, or None when a character is outside the alphabet."""
    if any(ch not in alphabet for ch in text):
        return None
    value = 0
    for ch in text:
        value = value * 58 + alphabet.index(ch)
    zeros = 0
    for ch in text:
        if ch == alphabet[0]:
            zeros += 1
        else:
            break
    body = b""
    while value:
        value, rem = divmod(value, 256)
        body = bytes([rem]) + body
    return bytes(zeros) + body


def checksum4(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


class B58Result:
    def __init__(self):
        self.reasons = set()
        self.network = None
        self.valid = False


def analyse_base58check(text, alphabet, prefix_len, payload_len, mainnet, testnet):
    """Base58Check string with a version prefix of prefix_len bytes and payload_len bytes of payload."""
    res = B58Result()
    raw = base58_decode(text, alphabet)
    if raw is None:
        res.reasons.add("bad_charset")
        return res
    if len(raw) != prefix_len + payload_len + 4:
        res.reasons.add("bad_length")
    if len(raw) >= 5 and checksum4(raw[:-4]) != raw[-4:]:
        res.reasons.add("bad_checksum")
    prefix = tuple(raw[:prefix_len])
    if prefix in mainnet:
        res.network = "mainnet"
    elif prefix in testnet:
        res.network = "testnet"
        res.reasons.add("wrong_network")
    else:
        res.reasons.add("bad_version_byte")
    res.valid = not res.reasons
    return res


# ---------------------------------------------------------------------------------------------
# Bech32 / Bech32m (BIP-173, BIP-350)
# ---------------------------------------------------------------------------------------------
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for bit in range(5):
            if (top >> bit) & 1:
                chk ^= generator[bit]
    return chk


def bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def regroup(data, src, dst, pad):
    acc, bits, out = 0, 0, []
    limit = (1 << dst) - 1
    for v in data:
        acc = (acc << src) | v
        bits += src
        while bits >= dst:
            bits -= dst
            out.append((acc >> bits) & limit)
    if pad:
        if bits:
            out.append((acc << (dst - bits)) & limit)
        return out
    if bits >= src or (acc << (dst - bits)) & limit:
        return None
    return out


def analyse_bech32_text(text):
    """Returns (reasons, hrp, data_values_without_checksum, constant) for a generic Bech32-family string."""
    reasons = set()
    if len(text) > 90:
        reasons.add("bad_length")
    if text != text.lower() and text != text.upper():
        reasons.add("mixed_case")
    low = text.lower()
    sep = low.rfind("1")
    if sep < 1:
        reasons.add("bad_prefix")
        return reasons, None, None, None
    hrp, data = low[:sep], low[sep + 1:]
    if len(data) < 6:
        reasons.add("bad_length")
    if any(ch not in BECH32_ALPHABET for ch in data):
        reasons.add("bad_charset")
        return reasons, hrp, None, None
    values = [BECH32_ALPHABET.index(ch) for ch in data]
    const = bech32_polymod(bech32_hrp_expand(hrp) + values)
    if const not in (BECH32_CONST, BECH32M_CONST):
        reasons.add("bad_checksum")
    return reasons, hrp, values[:-6] if len(values) >= 6 else [], const


def analyse_segwit(text, mainnet_hrp, testnet_hrps):
    res = B58Result()
    reasons, hrp, body, const = analyse_bech32_text(text)
    res.reasons |= reasons
    if hrp == mainnet_hrp:
        res.network = "mainnet"
    elif hrp in testnet_hrps:
        res.network = "testnet"
        res.reasons.add("wrong_network")
    else:
        res.reasons.add("bad_prefix")
    if body is None:
        return res
    if not body:
        res.reasons.add("bad_length")
        return res
    version = body[0]
    if version > 16:
        res.reasons.add("bad_witness_version")
    program = regroup(body[1:], 5, 8, False)
    if program is None:
        res.reasons.add("bad_padding")
    else:
        if version == 0 and len(program) not in (20, 32):
            res.reasons.add("bad_program_length")
        if version != 0 and not 2 <= len(program) <= 40:
            res.reasons.add("bad_program_length")
    if const in (BECH32_CONST, BECH32M_CONST):
        expected = BECH32_CONST if version == 0 else BECH32M_CONST
        if const != expected:
            res.reasons.add("wrong_checksum_constant")
    res.valid = not res.reasons
    return res


# ---------------------------------------------------------------------------------------------
# CashAddr
# ---------------------------------------------------------------------------------------------
def cashaddr_polymod(values):
    generator = (0x98F2BC8E61, 0x79B76D99E2, 0xF33E5FB3C4, 0xAE2EABE2A8, 0x1E4F43E470)
    c = 1
    for d in values:
        top = c >> 35
        c = ((c & 0x07FFFFFFFF) << 5) ^ d
        for bit in range(5):
            if (top >> bit) & 1:
                c ^= generator[bit]
    return c ^ 1


CASHADDR_SIZES = [20, 24, 28, 32, 40, 48, 56, 64]


def analyse_cashaddr(text):
    res = B58Result()
    if text != text.lower() and text != text.upper():
        res.reasons.add("mixed_case")
    low = text.lower()
    prefix = "bitcoincash"
    body = low
    if ":" in low:
        if low.count(":") > 1:
            res.reasons.add("bad_prefix")
        prefix, _, body = low.partition(":") if low.count(":") == 1 else (low.split(":")[0], ":", low.split(":", 1)[1])
        if prefix == "bitcoincash":
            res.network = "mainnet"
        elif prefix in ("bchtest", "bchreg"):
            res.network = "testnet"
            res.reasons.add("wrong_network")
        else:
            res.reasons.add("bad_prefix")
    else:
        res.network = "mainnet"
    if any(ch not in BECH32_ALPHABET for ch in body):
        res.reasons.add("bad_charset")
        return res
    if len(body) < 9:
        res.reasons.add("bad_length")
        return res
    words = [BECH32_ALPHABET.index(ch) for ch in body]
    if cashaddr_polymod([ord(c) & 31 for c in prefix] + [0] + words) != 0:
        res.reasons.add("bad_checksum")
    raw = regroup(words[:-8], 5, 8, False)
    if raw is None or not raw:
        res.reasons.add("bad_padding")
        return res
    version = raw[0]
    kind = (version >> 3) & 0x0F
    if version & 0x80 or kind not in (0, 1):
        res.reasons.add("bad_version_byte")
    if len(raw) - 1 != CASHADDR_SIZES[version & 7]:
        res.reasons.add("bad_length")
    res.valid = not res.reasons
    return res


# ---------------------------------------------------------------------------------------------
# CRC16-XMODEM (polynomial 0x1021, initial value 0), table driven
# ---------------------------------------------------------------------------------------------
_CRC_TABLE = []
for _n in range(256):
    _r = _n << 8
    for _ in range(8):
        _r = ((_r << 1) ^ 0x1021) & 0xFFFF if _r & 0x8000 else (_r << 1) & 0xFFFF
    _CRC_TABLE.append(_r)


def crc16_xmodem(data):
    crc = 0
    for byte in data:
        crc = ((crc << 8) & 0xFFFF) ^ _CRC_TABLE[((crc >> 8) ^ byte) & 0xFF]
    return crc


assert crc16_xmodem(b"123456789") == 0x31C3

# ---------------------------------------------------------------------------------------------
# family analysers: each returns B58Result with `reasons` (all that apply), `network`, `valid`
# ---------------------------------------------------------------------------------------------
def generic_pre(text, res):
    if text == "":
        res.reasons.add("empty")
    if re.search(r"\s", text):
        res.reasons.add("whitespace")


def fam_evm(text):
    res = B58Result()
    res.network = "none"
    generic_pre(text, res)
    if text == "":
        return res
    if not text.startswith("0x"):
        res.reasons.add("bad_prefix")
        body = text
    else:
        body = text[2:]
    if re.search(r"[^0-9a-fA-F]", body):
        res.reasons.add("bad_charset")
    if len(body) != 40:
        res.reasons.add("bad_length")
    letters = [ch for ch in body if ch.isalpha()]
    if re.fullmatch(r"[0-9a-fA-F]+", body or "x") and any(c.islower() for c in letters) and any(c.isupper() for c in letters):
        if len(body) == 40 and body != eip55_capitalisation(body):
            res.reasons.add("bad_checksum")
    res.valid = not res.reasons
    return res


def _btc_like(text, mainnet_versions, testnet_versions, hrp, testnet_hrps):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    low = text.lower()
    known = hrp and (low.startswith(hrp + "1") or any(low.startswith(h + "1") for h in testnet_hrps))
    if known:
        seg = analyse_segwit(text, hrp, testnet_hrps)
        seg.reasons |= res.reasons
        seg.valid = not seg.reasons
        return seg
    if hrp and text in (text.lower(), text.upper()) and re.fullmatch(r"[a-z0-9]{1,83}1[%s]{6,}" % BECH32_ALPHABET, low):
        seg = analyse_segwit(text, hrp, testnet_hrps)
        base = analyse_base58check(text, ALPHA_BTC, 1, 20, mainnet_versions, testnet_versions)
        seg.reasons |= base.reasons | res.reasons
        seg.valid = False
        return seg
    b = analyse_base58check(text, ALPHA_BTC, 1, 20, mainnet_versions, testnet_versions)
    b.reasons |= res.reasons
    b.valid = not b.reasons
    return b


def fam_btc(text):
    return _btc_like(text, {(0x00,), (0x05,)}, {(0x6F,), (0xC4,)}, "bc", ("tb", "bcrt"))


def fam_ltc(text):
    return _btc_like(text, {(48,), (50,), (5,)}, {(111,), (196,), (58,)}, "ltc", ("tltc", "rltc"))


def fam_doge(text):
    return _btc_like(text, {(30,), (22,)}, {(113,), (196,), (111,)}, None, ())


def fam_bch(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    legacy = analyse_base58check(text, ALPHA_BTC, 1, 20, {(0,), (5,)}, {(0x6F,), (0xC4,)})
    cash = analyse_cashaddr(text)
    if legacy.valid or cash.valid:
        chosen = legacy if legacy.valid else cash
        chosen.reasons = set(res.reasons)
        chosen.valid = not chosen.reasons
        return chosen
    merged = B58Result()
    merged.reasons = legacy.reasons | cash.reasons | res.reasons
    merged.network = legacy.network if "bad_charset" not in legacy.reasons else cash.network
    return merged


def fam_zec(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    low = text.lower()
    for hrp, net in (("tex", "mainnet"), ("textest", "testnet")):
        if low.startswith(hrp + "1"):
            reasons, h, body, const = analyse_bech32_text(text)
            out = B58Result()
            out.reasons = reasons | res.reasons
            out.network = net
            if h != hrp:
                out.reasons.add("bad_prefix")
            if net == "testnet":
                out.reasons.add("wrong_network")
            if const == BECH32_CONST:
                out.reasons.add("wrong_checksum_constant")
            if body is not None:
                program = regroup(body, 5, 8, False)
                if program is None:
                    out.reasons.add("bad_padding")
                elif len(program) != 20:
                    out.reasons.add("bad_program_length")
            out.valid = not out.reasons
            return out
    b = analyse_base58check(text, ALPHA_BTC, 2, 20, {(0x1C, 0xB8), (0x1C, 0xBD)}, {(0x1D, 0x25), (0x1C, 0xBA)})
    b.reasons |= res.reasons
    b.valid = not b.reasons
    return b


def fam_sol(text):
    res = B58Result()
    res.network = "none"
    generic_pre(text, res)
    if text == "":
        return res
    raw = base58_decode(text, ALPHA_BTC)
    if raw is None:
        res.reasons.add("bad_charset")
    elif len(raw) != 32:
        res.reasons.add("bad_length")
    res.valid = not res.reasons
    return res


def fam_tron(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    if re.fullmatch(r"41[0-9a-fA-F]{40}", text):
        res.network = "mainnet"
        res.valid = True
        return res
    if re.fullmatch(r"[0-9A-Fa-f]+", text) and len(text) != 42:
        res.reasons.add("bad_length")
    b = analyse_base58check(text, ALPHA_BTC, 1, 20, {(0x41,)}, set())
    b.reasons |= res.reasons
    b.valid = not b.reasons
    return b


def fam_xrp(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    raw = base58_decode(text, ALPHA_XRP)
    if raw is None:
        res.reasons.add("bad_charset")
        return res
    if len(raw) not in (25, 35):
        res.reasons.add("bad_length")
    if len(raw) >= 5 and checksum4(raw[:-4]) != raw[-4:]:
        res.reasons.add("bad_checksum")
    if len(raw) == 25:
        if raw[0] == 0:
            res.network = "mainnet"
        else:
            res.reasons.add("bad_version_byte")
    elif len(raw) == 35:
        if raw[:2] == bytes([0x05, 0x44]):
            res.network = "mainnet"
        elif raw[:2] == bytes([0x04, 0x93]):
            res.network = "testnet"
            res.reasons.add("wrong_network")
        else:
            res.reasons.add("bad_version_byte")
        flags, tag, tail = raw[22], raw[23:27], raw[27:31]
        if flags == 0:
            if tag != bytes(4) or tail != bytes(4):
                res.reasons.add("bad_format")
        elif flags == 1:
            if tail != bytes(4):
                res.reasons.add("bad_format")
        else:
            res.reasons.add("bad_format")
    res.valid = not res.reasons
    return res


NEAR_PATTERN = re.compile(r"^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$")


def fam_near(text):
    res = B58Result()
    res.network = "none"
    generic_pre(text, res)
    if text == "":
        return res
    if not 2 <= len(text) <= 64:
        res.reasons.add("bad_length")
    if re.search(r"[^a-zA-Z0-9._-]", text):
        res.reasons.add("bad_charset")
    if re.search(r"[A-Z]", text):
        res.reasons.add("bad_case")
    if not NEAR_PATTERN.match(text):
        res.reasons.add("bad_format")
    res.valid = not res.reasons
    return res


def fam_ton(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    m = re.fullmatch(r"(-?\d+):([0-9a-fA-F]*)", text)
    if m:
        res.network = "none"
        if len(m.group(2)) != 64:
            res.reasons.add("bad_length")
        if m.group(1) not in ("0", "-1"):
            res.reasons.add("bad_format")
        res.valid = not res.reasons
        return res
    if len(text) != 48:
        res.reasons.add("bad_length")
    if not re.fullmatch(r"[A-Za-z0-9+/]*", text) and not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        res.reasons.add("bad_charset")
    if len(text) == 48 and not res.reasons:
        if re.fullmatch(r"[A-Za-z0-9_-]*", text):
            raw = base64.urlsafe_b64decode(text)
        else:
            raw = base64.b64decode(text, validate=True)
        if crc16_xmodem(raw[:34]) != (raw[34] << 8 | raw[35]):
            res.reasons.add("bad_checksum")
        flags = raw[0]
        base_flags = flags & 0x7F
        if base_flags not in (0x11, 0x51):
            res.reasons.add("bad_version_byte")
        elif flags & 0x80:
            res.network = "testnet"
            res.reasons.add("wrong_network")
        else:
            res.network = "mainnet"
        if raw[1] not in (0x00, 0xFF):
            res.reasons.add("bad_format")
    res.valid = not res.reasons
    return res


STRKEY_LETTER = {"G": 6, "M": 12, "C": 2}
STRKEY_OTHER = {"S": 18, "T": 19, "X": 23, "P": 15, "L": 11, "B": 1, "W": 22}
STRKEY_LENGTH = {"G": 56, "C": 56, "M": 69}


def fam_stellar(text):
    res = B58Result()
    generic_pre(text, res)
    if text == "":
        return res
    if re.search(r"[^A-Z2-7]", text):
        res.reasons.add("bad_charset")
        return res
    letter = text[0]
    if letter not in STRKEY_LETTER and letter not in STRKEY_OTHER:
        res.reasons.add("bad_version_byte")
    if letter in STRKEY_OTHER:
        res.reasons.add("not_address_type")
    if letter in STRKEY_LENGTH and len(text) != STRKEY_LENGTH[letter]:
        res.reasons.add("bad_length")
    padded = text + "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(padded)
        canonical = base64.b32encode(raw).decode().rstrip("=") == text
    except Exception:
        res.reasons.add("bad_length")
        res.valid = False
        return res
    if not canonical:
        res.reasons.add("bad_padding")
    if len(raw) >= 3:
        if crc16_xmodem(raw[:-2]) != int.from_bytes(raw[-2:], "little"):
            res.reasons.add("bad_checksum")
        if letter in STRKEY_LETTER and raw[0] != STRKEY_LETTER[letter] << 3:
            res.reasons.add("bad_version_byte")
    res.network = "mainnet"
    res.valid = not res.reasons
    return res


ANALYSERS = {
    "evm": fam_evm, "btc": fam_btc, "ltc": fam_ltc, "doge": fam_doge, "bch": fam_bch, "zec": fam_zec,
    "sol": fam_sol, "tron": fam_tron, "near": fam_near, "ton": fam_ton, "xrp": fam_xrp, "stellar": fam_stellar,
}
FAMILIES = list(ANALYSERS)

SCHEME_PREFIX = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:(//)?([a-z]+/)?")


def applicable_reasons(family, text, analysis):
    """Reasons that apply to an invalid string, including the ones that need the other families."""
    reasons = set(analysis.reasons)
    for other in FAMILIES:
        if other != family and ANALYSERS[other](text).valid:
            reasons.add("other_family")
            break
    m = SCHEME_PREFIX.match(text)
    if m and ANALYSERS[family](text[m.end():]).valid:
        reasons.add("uri_wrapped")
    for sep in ("?", ":", "#", "@"):
        if sep in text:
            head = text.split(sep)[0]
            if head != text and ANALYSERS[family](head).valid:
                reasons.add("extra_data")
    if ANALYSERS[family](text.strip()).valid and re.search(r"^\s|\s$", text):
        reasons.add("whitespace")
    return reasons


# ---------------------------------------------------------------------------------------------
# expectations typed from the specification pages, independent of build.py
# ---------------------------------------------------------------------------------------------
EXPECT_CAIP2 = {
    "evm": "eip155:1", "btc": "bip122:000000000019d6689c085ae165831e93", "ltc": "bip122:12a765e31ffd4059bada1e25190f6e98",
    "doge": "bip122:1a91e3dace36e2be3bf030a65679fe82", "bch": "bip122:000000000000000000651ef99cb9fcbe", "zec": "",
    "sol": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "tron": "tron:728126428", "near": "", "ton": "",
    "xrp": "xrpl:0", "stellar": "stellar:pubnet",
}
EXPECT_MEMO = {"evm": "none", "btc": "none", "ltc": "none", "doge": "none", "bch": "none", "zec": "none", "sol": "none",
               "tron": "none", "near": "memo", "ton": "comment", "xrp": "destination_tag", "stellar": "memo"}
REASONS = {
    "empty", "whitespace", "bad_charset", "bad_length", "bad_checksum", "bad_version_byte", "bad_prefix", "wrong_network",
    "mixed_case", "bad_case", "bad_witness_version", "bad_program_length", "bad_padding", "wrong_checksum_constant",
    "uri_wrapped", "extra_data", "other_family", "not_address_type", "bad_format",
}
ORIGINS = {"specification", "public-well-known", "derived", "mutation"}
COLUMNS = ["id", "family", "chain_caip2", "network", "address", "encoding_form", "checksum_algorithm", "spec_valid", "reason",
           "memo_or_tag_convention", "origin", "source", "source_url", "notes", "multichain_memo_address_validator_1_0_0"]
MUTATION_CAP = 5
MIN_PER_FAMILY = 30
MIN_TOTAL = 600


def read_csv(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def to_bool(cell):
    return {"true": True, "false": False, "": None}[cell]


def main():
    data = os.path.join(HERE, "..", "data")
    if "--data" in sys.argv:
        data = sys.argv[sys.argv.index("--data") + 1]
    problems = []

    def fail(kind, msg):
        problems.append("%s: %s" % (kind, msg))

    csv_rows = read_csv(os.path.join(data, "address-vectors.csv"))
    with open(os.path.join(data, "address-vectors.json"), encoding="utf-8") as fh:
        json_rows = json.load(fh)
    if list(csv_rows[0].keys()) != COLUMNS:
        fail("columns", "CSV columns differ from the specified list: %s" % list(csv_rows[0].keys()))
    if len(csv_rows) != len(json_rows):
        fail("equality", "CSV has %d rows, JSON %d" % (len(csv_rows), len(json_rows)))
    for i, (c, j) in enumerate(zip(csv_rows, json_rows)):
        cc = dict(c)
        cc["spec_valid"] = to_bool(c["spec_valid"])
        cc[COLUMNS[-1]] = to_bool(c[COLUMNS[-1]])
        if cc != j:
            fail("equality", "row %d (%s) differs between CSV and JSON" % (i + 1, c["id"]))
            break
    rows = json_rows

    seen = set()
    ids = set()
    per_family = {f: 0 for f in FAMILIES}
    rule_count = {}
    next_number = {f: 1 for f in FAMILIES}
    for row in rows:
        rid, fam, addr = row["id"], row["family"], row["address"]
        if fam not in ANALYSERS:
            fail("family", "%s has unknown family %r" % (rid, fam))
            continue
        per_family[fam] += 1
        if (fam, addr) in seen:
            fail("duplicate", "%s duplicates family+address %r" % (rid, addr))
        seen.add((fam, addr))
        if rid in ids:
            fail("duplicate", "id %s repeated" % rid)
        ids.add(rid)
        if not re.fullmatch(r"%s-%04d" % (fam, next_number[fam]), rid):
            fail("id", "%s is not the next id of family %s (expected %s-%04d)" % (rid, fam, fam, next_number[fam]))
        next_number[fam] += 1
        analysis = ANALYSERS[fam](addr)
        if analysis.valid != row["spec_valid"]:
            fail("spec_valid mismatch", "%s %s %r: data says %s, independent implementation says %s (reasons %s)" % (
                rid, fam, addr, row["spec_valid"], analysis.valid, sorted(analysis.reasons)))
        if row["spec_valid"]:
            if row["reason"] != "":
                fail("reason", "%s is valid but has reason %r" % (rid, row["reason"]))
            if row["network"] != "mainnet" and fam not in ("evm", "sol", "near") and not (fam == "ton" and (":" in addr)):
                fail("network", "%s valid but network %s" % (rid, row["network"]))
        else:
            if row["reason"] not in REASONS:
                fail("reason", "%s has reason %r outside the vocabulary" % (rid, row["reason"]))
            else:
                allowed = applicable_reasons(fam, addr, analysis)
                if row["reason"] not in allowed:
                    fail("reason mismatch", "%s %r: declared %s, applicable %s" % (rid, addr, row["reason"], sorted(allowed)))
        if analysis.network == "testnet" and row["network"] != "testnet":
            fail("network", "%s %r is a testnet form but network is %s" % (rid, addr, row["network"]))
        if row["network"] == "testnet" and analysis.network not in ("testnet", None):
            fail("network", "%s declares testnet but the string reads as %s" % (rid, analysis.network))
        if row["network"] not in ("mainnet", "testnet", "none"):
            fail("network", "%s has network %r" % (rid, row["network"]))
        if row["origin"] not in ORIGINS:
            fail("origin", "%s has origin %r" % (rid, row["origin"]))
        if row["chain_caip2"] != EXPECT_CAIP2[fam]:
            fail("caip2", "%s has chain_caip2 %r, expected %r" % (rid, row["chain_caip2"], EXPECT_CAIP2[fam]))
        if row["memo_or_tag_convention"] != EXPECT_MEMO[fam]:
            fail("memo", "%s has memo convention %r" % (rid, row["memo_or_tag_convention"]))
        if not row["checksum_algorithm"] or not row["encoding_form"] or not row["source"]:
            fail("empty cell", "%s has an empty form, checksum or source cell" % rid)
        if not re.fullmatch(r"https://[^\s]+", row["source_url"]):
            fail("source_url", "%s has source_url %r" % (rid, row["source_url"]))
        if row["origin"] == "mutation":
            m = re.match(r"Mutation rule (\S+?)(?::| applied to (\S+?):)", row["source"])
            if not m:
                fail("mutation", "%s has origin mutation but no rule in source" % rid)
            else:
                key = (fam, m.group(1))
                rule_count[key] = rule_count.get(key, 0) + 1
                if m.group(2) and m.group(2) not in ids:
                    fail("mutation", "%s names base row %s that does not precede it" % (rid, m.group(2)))
                elif m.group(2) and not m.group(2).startswith(fam + "-"):
                    fail("mutation", "%s names base row %s of another family" % (rid, m.group(2)))
        if row[COLUMNS[-1]] is None:
            fail("library column", "%s has an empty library column" % rid)
    for key, count in sorted(rule_count.items()):
        if count > MUTATION_CAP:
            fail("cap", "family %s rule %s has %d rows (cap %d)" % (key[0], key[1], count, MUTATION_CAP))
    for fam in FAMILIES:
        if per_family[fam] < MIN_PER_FAMILY:
            fail("coverage", "family %s has %d rows (minimum %d)" % (fam, per_family[fam], MIN_PER_FAMILY))
        valid_forms = {r["encoding_form"] for r in rows if r["family"] == fam and r["spec_valid"]}
        if not valid_forms:
            fail("coverage", "family %s has no valid row" % fam)
    if len(rows) < MIN_TOTAL:
        fail("coverage", "only %d rows (minimum %d)" % (len(rows), MIN_TOTAL))

    # families table
    fam_csv = read_csv(os.path.join(data, "address-families.csv"))
    with open(os.path.join(data, "address-families.json"), encoding="utf-8") as fh:
        fam_json = json.load(fh)
    if [r["family"] for r in fam_csv] != FAMILIES and sorted(r["family"] for r in fam_csv) != sorted(FAMILIES):
        fail("families", "address-families.csv does not list the 12 families")
    if len(fam_csv) != len(fam_json):
        fail("families", "CSV and JSON of address-families differ in length")
    for c, j in zip(fam_csv, fam_json):
        cc = dict(c)
        for key in ("chain_caip2", "spec_urls"):
            cc[key] = json.loads(c[key])
        if cc != j:
            fail("families", "CSV and JSON differ for family %s" % c["family"])
        if j["memo_or_tag_convention"] != EXPECT_MEMO[j["family"]]:
            fail("families", "memo convention of %s" % j["family"])
        for url in j["spec_urls"]:
            if not url.startswith("https://"):
                fail("families", "spec url %r" % url)

    # ambiguities
    amb_csv = read_csv(os.path.join(data, "cross-family-ambiguities.csv"))
    with open(os.path.join(data, "cross-family-ambiguities.json"), encoding="utf-8") as fh:
        amb_json = json.load(fh)
    if len(amb_csv) != len(amb_json):
        fail("ambiguities", "CSV and JSON differ in length")
    for c, j in zip(amb_csv, amb_json):
        cc = dict(c)
        for key in ("families_valid", "related"):
            cc[key] = json.loads(c[key])
        if cc != j:
            fail("ambiguities", "CSV and JSON differ for %s" % c["id"])
        valid_in = [f for f in FAMILIES if ANALYSERS[f](j["string"]).valid]
        if sorted(valid_in) != sorted(j["families_valid"]):
            fail("ambiguities", "%s: families_valid %s but the independent implementation finds %s" % (j["id"], j["families_valid"], valid_in))
        if j["kind"] == "same_string" and len(valid_in) < 2:
            fail("ambiguities", "%s is a same_string entry but is valid under %d families" % (j["id"], len(valid_in)))
        if j["kind"] == "not_ambiguous_control" and len(valid_in) != 1:
            fail("ambiguities", "%s is a control entry but is valid under %d families" % (j["id"], len(valid_in)))
        for item in j["related"]:
            fam, _, addr = item.partition(":")
            if fam not in ANALYSERS or not ANALYSERS[fam](addr).valid:
                fail("ambiguities", "%s: related item %r is not valid" % (j["id"], item))
        if not j["source_url"].startswith("https://"):
            fail("ambiguities", "%s source_url" % j["id"])

    valid_total = sum(1 for r in rows if r["spec_valid"])
    print("rows %d (valid %d, invalid %d), families %d, ambiguities %d" % (len(rows), valid_total, len(rows) - valid_total, len(FAMILIES), len(amb_json)))
    if problems:
        shown = problems[:40]
        for p in shown:
            print("FAIL " + p)
        print("FAIL: %d problem(s)%s" % (len(problems), "" if len(problems) <= 40 else " (first 40 shown)"))
        return 1
    print("PASS: all %d rows recomputed by the independent implementation; labels, reasons, networks, uniqueness, caps and tables agree" % len(rows))
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
