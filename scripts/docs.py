"""Documentation and metadata writer for build.py (standard library only, deterministic)."""
import collections
import json
import os

ORG = "AllSwap (Haohang Network Technology Co., Limited)"
CONTACT = "service@allswap.io"
TOOL_URL = "https://allswap.io/tools/address-validator"
LIB_URL = "https://github.com/allswapio/multichain-memo-address-validator"
TITLE = "Blockchain address format test vectors"
CC_URL = "https://creativecommons.org/licenses/by/4.0/"
CC_LEGAL = "https://creativecommons.org/licenses/by/4.0/legalcode"

SPEC_SOURCES = [
    ("EIP-55, EIP-1014, EIP-1191, EIP-1820, EIP-1967, EIP-2470, EIP-2935, EIP-3770, EIP-4788, EIP-7002, EIP-7251 (Ethereum Improvement Proposals)", "https://eips.ethereum.org/", "CC0 1.0 (the EIP repository)"),
    ("Ethereum JSON-RPC documentation (hex encoding)", "https://ethereum.org/en/developers/docs/apis/json-rpc/", "the ethereum.org website repository carries the MIT licence; only the stated encoding rule is used"),
    ("BIP-13, BIP-49, BIP-84, BIP-86, BIP-173, BIP-350 (Bitcoin Improvement Proposals)", "https://github.com/bitcoin/bips", "set per BIP in its preamble: BSD-2-Clause (BIP-86, BIP-173, BIP-350), CC0-1.0 (BIP-84), public domain (BIP-49)"),
    ("Bitcoin Wiki: Base58Check encoding; Technical background of version 1 Bitcoin addresses; Address; Genesis block; Pay to script hash", "https://en.bitcoin.it/wiki/Main_Page", "Creative Commons Attribution 3.0 unless otherwise noted (stated on the pages)"),
    ("Litecoin Core: chainparams.cpp, key_io.cpp", "https://github.com/litecoin-project/litecoin", "MIT"),
    ("Dogecoin Core: chainparams.cpp", "https://github.com/dogecoin/dogecoin", "MIT"),
    ("Zcash: chainparams.cpp", "https://github.com/zcash/zcash", "MIT or Apache-2.0 per the repository (the licence detector reports no single identifier)"),
    ("Zcash ZIP-320 (TEX addresses)", "https://zips.z.cash/zip-0320", "MIT (the zcash/zips repository)"),
    ("CashAddr specification", "https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md", "MIT (the bitcoincash.org repository)"),
    ("solana-sdk: sdk-ids and address crates", "https://github.com/anza-xyz/solana-sdk", "Apache-2.0"),
    ("TRON developer documentation, Accounts", "https://developers.tron.network/docs/account", "no licence statement found on the page; only the example values and format rules are used"),
    ("NEAR documentation, Address (Account ID)", "https://docs.near.org/protocol/accounts-contracts/account-id", "Apache-2.0 (the near/docs repository)"),
    ("near-account-id-rs: test_data.rs, validation.rs", "https://github.com/near/near-account-id-rs", "MIT OR Apache-2.0"),
    ("TON documentation, Address formats; Internal messages", "https://docs.ton.org/v3/documentation/smart-contracts/addresses/address-formats", "MIT (the ton-org/docs repository)"),
    ("XRPL documentation, Addresses", "https://xrpl.org/docs/concepts/accounts/addresses", "MIT (the XRP Ledger Dev Portal)"),
    ("XLS-5 Tagged Addresses", "https://github.com/XRPLF/XRPL-Standards/blob/master/XLS-0005-tagged-addresses/README.md", "MIT (the XRPL-Standards repository)"),
    ("Stellar SEP-23 (Strkeys), SEP-29", "https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md", "no licence file found in the repository at the time of reading; only test strings and format rules are used"),
    ("RFC 8032 (test public keys, section 7.1)", "https://www.rfc-editor.org/rfc/rfc8032", "IETF Trust legal provisions; only the published test public keys are used"),
    ("CAIP-2 namespaces: bip122, eip155, solana, stellar, tron, xrpl", "https://namespaces.chainagnostic.org/", "CC0 (stated on the pages)"),
]

COLUMN_DOC = [
    ("id", "string", "Stable identifier, family code and a four-digit number (btc-0001). Numbers are assigned in build order and do not change between builds of the same release."),
    ("family", "string", "One of the 12 family codes."),
    ("chain_caip2", "string", "CAIP-2 identifier of the reference network of the row, taken from the namespace pages listed below. Empty when no registered identifier was found (zec, near, ton). For evm it is eip155:1 as a reference: the format is shared by all eip155 chains."),
    ("network", "string", "mainnet, testnet or none. none: the format does not encode a network (evm, sol, near, TON raw form) or the string is too damaged to tell."),
    ("address", "string", "The test string, exactly as given, including whitespace and non-ASCII characters where a rule inserts them."),
    ("encoding_form", "string", "Short description of the form the row represents or was derived from. For a mutation row it is the form of its base row, that is the form the string was meant to have."),
    ("checksum_algorithm", "string", "Checksum the form carries. none where the form has no checksum."),
    ("spec_valid", "boolean", "true: the string is a well-formed mainnet address of the family under the cited specification. false: it is not; reason says why. Independent of any library."),
    ("reason", "string", "Empty when spec_valid is true. Otherwise one value of the controlled vocabulary below. When several rules fail, one is given."),
    ("memo_or_tag_convention", "string", "The family convention: none, memo, comment or destination_tag. Per family, not per address."),
    ("origin", "string", "specification, public-well-known, derived or mutation (definitions below)."),
    ("source", "string", "Text saying where the value comes from or which rule produced it."),
    ("source_url", "string", "URL of the specification that defines the form. Each URL was fetched and answered 200 (see README, limitations)."),
    ("notes", "string", "Remarks, including, where the library column differs from spec_valid, the policy of library 1.0.0 that explains it."),
    ("multichain_memo_address_validator_1_0_0", "boolean", "Result of inspectAddress(family, address).valid of multichain-memo-address-validator 1.0.0. A comparison column, not a label."),
]

REASON_DOC = {
    "empty": "the string is empty",
    "whitespace": "contains a space, tab or line break",
    "bad_charset": "a character outside the alphabet of the form",
    "bad_length": "wrong length for the form, or an empty payload",
    "bad_checksum": "the checksum does not match",
    "bad_version_byte": "the version byte, prefix bytes, flags or type bits are not those of a mainnet address of the family",
    "bad_prefix": "wrong prefix, HRP or leading characters",
    "wrong_network": "well formed, but for a test network",
    "mixed_case": "upper and lower case in a form that allows only one",
    "bad_case": "the wrong case for a case-sensitive form",
    "bad_witness_version": "witness version above 16",
    "bad_program_length": "witness program of an invalid length",
    "bad_padding": "non-zero or excessive padding bits",
    "wrong_checksum_constant": "Bech32 constant where Bech32m is required, or the reverse",
    "uri_wrapped": "an address inside a URI-style or prefixed wrapper",
    "extra_data": "a valid address followed by a query, tag or memo",
    "other_family": "an address of another family",
    "not_address_type": "a valid encoding of a type that is not an address (Stellar signer, pool and balance IDs)",
    "bad_format": "violates a structural rule of the form (separators, tag fields, workchain)",
}

ORIGIN_DOC = {
    "specification": "a string printed in a specification, its test vectors or its examples, copied exactly",
    "public-well-known": "a published system, program or contract address, or another widely published public address, cited from a page that was read",
    "derived": "a deterministic re-encoding of a published value (a published hash or key under another version byte, HRP or alphabet), or a documented variant (case, prefix omitted)",
    "mutation": "a published or derived string changed by one documented rule",
}


def _md_table(header, rows):
    out = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |")
    return "\n".join(out)


def write_all(root, rows, fam_rows, amb, FAMILIES, REASONS, RULECOUNT, RAW, VERSION, RELEASE_DATE, LIB_COLUMN, U):
    n = len(rows)
    by_fam = {f: [r for r in rows if r["family"] == f] for f in FAMILIES}
    fam_stats = []
    for f in FAMILIES:
        rs = by_fam[f]
        o = collections.Counter(r["origin"] for r in rs)
        fam_stats.append((f, len(rs), sum(r["spec_valid"] for r in rs), sum(not r["spec_valid"] for r in rs),
                          o["specification"], o["public-well-known"], o["derived"], o["mutation"]))
    tot = ("total", n, sum(x[2] for x in fam_stats), sum(x[3] for x in fam_stats), sum(x[4] for x in fam_stats), sum(x[5] for x in fam_stats), sum(x[6] for x in fam_stats), sum(x[7] for x in fam_stats))
    reasons = collections.Counter(r["reason"] for r in rows if not r["spec_valid"])
    rules = collections.Counter(r["_rule"] for r in RAW if r["origin"] == "mutation" and r["_rule"])
    per_rule = collections.Counter((r["family"], r["_rule"]) for r in RAW if r["origin"] == "mutation")
    per_family_rule_max = max(per_rule.values())
    lib_filled = all(r[LIB_COLUMN] is not None for r in rows)
    diverge = [r for r in rows if r[LIB_COLUMN] is not None and r[LIB_COLUMN] != r["spec_valid"]]
    div_fam = collections.Counter(r["family"] for r in diverge)
    div_dir = collections.Counter((r["spec_valid"], r[LIB_COLUMN]) for r in diverge)
    policy = collections.Counter()
    for r in diverge:
        t = r["notes"].split("Library 1.0.0: ")[-1].rstrip(".")
        policy[(r["family"], t)] += 1
    nets = collections.Counter(r["network"] for r in rows)
    cap = per_family_rule_max

    readme = []
    A = readme.append
    A("# %s\n" % TITLE)
    A("[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24540799.svg)](https://doi.org/10.5281/zenodo.24540799)\n")
    A("Version %s, %s. Licence: CC-BY-4.0 (data), MIT (scripts). Published by %s. Contact: %s.\n" % (VERSION, RELEASE_DATE, ORG, CONTACT))
    A("A set of %d labelled strings for people who write or test blockchain address validators. Each row is a string and a verdict: is it a well-formed mainnet address of its family **under the cited specification**. The verdict is a property of the specification, not of any library. The set covers 12 address families (EVM-style accounts, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Zcash transparent addresses, Solana, TRON, NEAR, TON, XRP Ledger and Stellar). Every valid string is taken from, or is a deterministic re-encoding of, a value printed in a specification, a test-vector list or other public documentation; every invalid string is either printed as invalid in a specification or produced from a valid one by a documented rule.\n" % n)
    A("Parts of this dataset, its scripts and this text were prepared with AI coding tools. Correctness does not rest on that: every label is computed twice, by two independent implementations written from the specifications (`scripts/build.py` and `scripts/verify.py`), and `scripts/verify.py` stops on any disagreement. See [Verification](#verification).\n")
    A("It grew out of the test vectors of the library <%s>, and a related interactive address checker is at <%s>. Neither reads this dataset; it is published so that anyone can test an implementation against it.\n" % (LIB_URL, TOOL_URL))
    A("## Files\n")
    A(_md_table(["File", "Content"], [
        ("`data/address-vectors.csv`, `data/address-vectors.json`", "the %d rows (same rows and columns in both files)" % n),
        ("`data/address-families.csv`, `.json`", "one row per family: alphabet, lengths, prefixes, checksum, case rules, memo or tag convention, specification URLs"),
        ("`data/cross-family-ambiguities.csv`, `.json`", "%d strings or byte values that are valid under several families, each with a source" % len(amb)),
        ("`datapackage.json`", "Frictionless Data package descriptor: field types, enumerations, patterns and unique keys"),
        ("`scripts/build.py`, `scripts/docs.py`", "deterministic build (Python 3 standard library only, no network, no randomness)"),
        ("`scripts/verify.py`", "independent verifier: recomputes `spec_valid` and the reason from the specifications and fails on any mismatch"),
        ("`scripts/check-verifier.py`", "mutation check of the verifier: flips ten labels (fixed seed) and requires `verify.py` to fail on each"),
        ("`scripts/check-package.py`", "structure check of `datapackage.json` against the data files (types, enumerations, patterns, unique keys)"),
        ("`scripts/compare.mjs`", "checks the library column against a local copy of the library (Node.js 22)"),
        ("`scripts/library-results.json`", "the library results that `build.py` copies into the library column (written by `compare.mjs --write`)"),
        ("`LICENSE-DATA`, `LICENSE`, `CITATION.cff`, `CHANGELOG.md`, `.zenodo.json`", "licence notices and citation metadata"),
    ]))
    A("\n## Counts\n")
    A("Computed by `scripts/docs.py` from the data files at build time.\n")
    A(_md_table(["Family", "Rows", "spec_valid true", "spec_valid false", "specification", "public-well-known", "derived", "mutation"], fam_stats + [tot]))
    A("\nRows by `spec_valid = false` reason:\n")
    A(_md_table(["reason", "rows", "meaning"], [(k, reasons[k], REASON_DOC[k]) for k in REASONS if reasons[k]]))
    A("\nRows by network: " + ", ".join("%s %d" % (k, nets[k]) for k in sorted(nets)) + ".\n")
    A("Mutation rules: %d distinct rule names, at most %d rows of one rule in one family (the build applies a cap of 3 to the generic rules and 5 to the others; the verifier checks the limit of 5). Every mutation row names its rule in `source`, and its base row where it has one.\n" % (len(rules), cap))
    A("## Columns of `address-vectors`\n")
    A(_md_table(["Column", "Type", "Meaning"], COLUMN_DOC))
    A("\n### `origin`\n")
    A(_md_table(["Value", "Meaning"], list(ORIGIN_DOC.items())))
    A("\n### `reason`\n")
    A(_md_table(["Value", "Meaning"], [(k, REASON_DOC[k]) for k in REASONS]))
    A("\n### CAIP-2 identifiers\n")
    A("Taken from the namespace pages of the Chain Agnostic Standards Alliance: `bip122` (Bitcoin, Bitcoin Cash, Litecoin, Dogecoin test cases), `eip155`, `solana`, `stellar` (`pubnet`), `tron` (`tron:728126428`) and `xrpl` (`xrpl:0`). The `bip122` page lists no Zcash identifier, and no `near` or `ton` namespace page was found, so those rows have an empty `chain_caip2`. Registered identifiers were not invented.\n")
    A("## How `spec_valid` is decided\n")
    A("`spec_valid` answers one question: is the string a well-formed **mainnet** address of the family under the cited specification. Rules used (the same in `build.py` and, independently, in `verify.py`):\n")
    A("""- **EVM.** `0x` followed by 40 hexadecimal digits (the Ethereum JSON-RPC encoding of an address). Letters of one case only: valid, no checksum asserted. Letters of both cases: must equal the EIP-55 capitalisation. EIP-55 itself does not say that single-case strings are accepted; this is the convention of the ecosystem and is marked `checksum_algorithm = none (single-case hex ...)`. Chain-specific capitalisations (EIP-1191) are not EIP-55 checksums and fail it. The zero address is well formed.
- **Bitcoin.** Base58Check with version 0x00 or 0x05 and a 20-byte hash; Bech32 with HRP `bc` and witness version 0 (20 or 32 bytes) or Bech32m with versions 1 to 16 (2 to 40 bytes), as in BIP-173 and BIP-350, including all-upper-case strings.
- **Litecoin.** As Bitcoin with HRP `ltc` and Base58Check versions 0x30, 0x32 and the legacy 0x05, which Litecoin Core's `chainparams.cpp` and `key_io.cpp` define and decode. MWEB addresses are not covered.
- **Dogecoin.** Base58Check, versions 0x1e and 0x16.
- **Bitcoin Cash.** CashAddr with prefix `bitcoincash` (the prefix may be omitted; all lower or all upper case), type 0 or 1, hash sizes 20 to 64 bytes as encoded in the version byte; or the legacy Base58Check form (versions 0x00 and 0x05).
- **Zcash.** Transparent Base58Check addresses with the two-byte versions 0x1cb8 and 0x1cbd, and TEX addresses (ZIP-320: Bech32m, HRP `tex`, 20-byte hash). Shielded and unified addresses are not covered (see limitations).
- **Solana.** A Base58 string that decodes to exactly 32 bytes. There is no checksum, so truncating or altering a string often yields another valid address; such rows are labelled `true` on purpose.
- **TRON.** Base58Check with version 0x41 and a 20-byte hash, or the 42-digit hex form of the documentation (either case).
- **NEAR.** The account ID grammar of `near-account-id-rs`: 2 to 64 characters of `a-z`, `0-9` and the separators `.`, `-`, `_`, where separators are not adjacent, leading or trailing. Implicit, Ethereum-like, deterministic and universal accounts are all strings of this grammar. Whether a name can be created on the network is not a grammar question.
- **TON.** Raw `workchain:64 hex digits` with workchain 0 or -1; or the 36-byte user-friendly form (flags 0x11 or 0x51, workchain byte 0 or 0xff, CRC16-XMODEM big-endian) in base64 or base64url. Flags with the testnet bit (0x80) are for a test network.
- **XRP Ledger.** Base58Check with the XRPL alphabet: classic addresses (version 0x00, 20-byte account id) and the X-address of XLS-5 (prefix 0x05 0x44, tag flag 0 or 1, unused bytes zero). Prefix 0x04 0x93 is the testnet T-address.
- **Stellar.** StrKey (RFC 4648 base32, no padding, trailing bits zero, CRC16-XMODEM little-endian) of the types G (account), M (muxed account) and C (contract). Other valid StrKey types (signers, pool and balance identifiers) are labelled `not_address_type`: this is the definition of "address" used here.
- **All families.** Leading, trailing or inner whitespace, a URI wrapper, an appended query or tag, and non-ASCII look-alike characters make a string invalid. The empty string is invalid.
""")
    A("Strings that the specifications leave open (for example mixed-case hex in a TON raw address, the upper-case `0X` prefix, other TON workchains) are not included, so that no label depends on a guess.\n")
    A("## Where the library differs\n")
    if lib_filled:
        A("The last column records `inspectAddress(family, address).valid` of multichain-memo-address-validator 1.0.0, run by `scripts/compare.mjs` on a local copy. It differs from `spec_valid` on **%d of %d rows**, %s. The notes of each such row give the policy.\n" % (
            len(diverge), n, ("all in one direction: spec true and library false on %d rows. The library is stricter than the specifications by design (it accepts a deliberately narrow set of forms); on this data it never accepts a string that a specification rejects" % div_dir[(True, False)]) if set(div_dir) == {(True, False)} else
            "in both directions: " + ", ".join("spec %s and library %s on %d rows" % (str(s).lower(), str(l).lower(), v) for (s, l), v in sorted(div_dir.items()))))
        A(_md_table(["Family", "Rows that differ", "Policy of the library (version 1.0.0)", "Rows"], [(f, div_fam[f], t, c) for (f, t), c in sorted(policy.items(), key=lambda kv: (FAMILIES.index(kv[0][0]), -kv[1], kv[0][1]))]))
        A("")
    else:
        A("The library column is empty in this build; run `node scripts/compare.mjs <path to src/index.mjs> --write` and build again.\n")
    A("## Cross-family ambiguities\n")
    A("`data/cross-family-ambiguities.*` lists strings that are valid under several families and byte values that appear under several encodings, each shown by an example and a source. The families in which a string is valid are computed from the same rules as above and re-checked by `verify.py`. Kinds: `same_string` (one string valid under several families), `same_bytes` (the same underlying bytes written in several families) and `not_ambiguous_control` (a string that looks ambiguous but is not).\n")
    A(_md_table(["id", "kind", "string", "valid under"], [(a["id"], a["kind"], "`%s`" % (a["string"] if len(a["string"]) <= 48 else a["string"][:45] + "..."), ", ".join(a["families_valid"]) or "none (valid under no family)") for a in amb]))
    A("\n## Verification\n")
    A("""All commands run from the repository root. Python 3 (standard library only) and Node.js 22 are needed. Nothing is downloaded.

```sh
python3 scripts/build.py                      # writes data/ and the documentation
python3 scripts/verify.py                     # independent recomputation of every label; exits 1 on any mismatch
node scripts/compare.mjs <path>/src/index.mjs # checks the library column; add --write to refresh scripts/library-results.json
python3 scripts/check-verifier.py             # flips ten labels; verify.py must fail on every one
python3 scripts/check-package.py              # datapackage.json against the data files
```

`verify.py` shares no code with `build.py` or with the library. It implements, from the specifications, Keccak-256 and EIP-55, Base58 and Base58Check (Bitcoin and XRPL alphabets), Bech32 and Bech32m, CashAddr, CRC16-XMODEM, base64 and base32 StrKey decoding, and recomputes `spec_valid` for every row; it also checks that the declared reason is one of the reasons that actually apply to the string, the unique key (`family`, `address`), the cap of mutation rows per rule, the CAIP-2 values, that CSV and JSON hold the same rows, and the claims of the ambiguity table.
""")
    A("## Limitations\n")
    A("""- **Specification readings.** Where a specification is silent the row is left out (see above), but the readings listed in "How `spec_valid` is decided" are the maintainers' reading of the cited texts. They are open to correction; please open an issue with the passage you rely on.
- **Zcash.** No shielded (Sapling `zs1`) or unified (`u1`) address that is printed in a page that was read could be traced, so none is included. ZIP-173 lists a TODO for Sapling vectors.
- **Litecoin MWEB**, Bitcoin testnet forms beyond the listed rows, regtest, and other networks of the families are not systematically covered. Test-network rows exist to check that a mainnet validator refuses them.
- **No on-chain check.** The data says nothing about whether an address exists, is funded or accepts a given token. A deterministic re-encoding of a published hash is a well-formed string, not a statement about who controls it.
- **Re-encodings.** Many valid strings of the derived origin re-encode the same published 20-byte hashes and 32-byte public keys under different version bytes and alphabets. They test the encoding, not the existence of an account on that chain.
- **Specification pages change.** Each value was copied from the page as read on 2026-11-26 and the URL was checked to answer 200 on that day. The Solana documentation site refused automated requests (HTTP 429), so Solana values come from the `solana-sdk` source files listed in the sources.
- **Library column.** It describes one version of one library and is a comparison aid, not part of the verdict.
- **Not verified**: behaviour of other libraries; correctness of the specifications themselves; the data against a live node of any chain.
""")
    A("## Specification sources and licences\n")
    A("Strings in this set are facts or test values printed in the sources below; no prose of the sources is reproduced. Licences are listed as found at the time of reading; they are given for attribution and do not change the licence of this dataset.\n")
    A(_md_table(["Source", "URL", "Licence as found"], SPEC_SOURCES))
    A("\nThe exact URL of the specification of every row is in `source_url`.\n")
    A("## Licence\n")
    A("The data (`data/`, `datapackage.json`, this README) is licensed under the Creative Commons Attribution 4.0 International licence (CC-BY-4.0): <%s>, legal code <%s>. The scripts in `scripts/` are licensed under the MIT licence (`LICENSE`). See `LICENSE-DATA`.\n" % (CC_URL, CC_LEGAL))
    A("## How to cite\n")
    A("""> %s. *%s*, version %s, %s. https://allswap.io/tools/address-validator

DOI of version 1.0.0: <https://doi.org/10.5281/zenodo.24540799>. All versions: <https://doi.org/10.5281/zenodo.24540798>. `CITATION.cff` holds the machine-readable citation.

Attribution: please credit "%s" and link to the licence. Suggested short form: "Blockchain address format test vectors, AllSwap, CC-BY-4.0".
""" % (ORG, TITLE, VERSION, RELEASE_DATE[:4], ORG))
    A("Contact: %s\n" % CONTACT)
    with open(os.path.join(root, "README.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(readme))

    # ------------------------------------------------------------------ licences, citation, changelog
    with open(os.path.join(root, "LICENSE-DATA"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("""%s

The data in this repository (the files under data/, datapackage.json and README.md) is licensed under the
Creative Commons Attribution 4.0 International Public Licence (CC BY 4.0).

Licence summary:  %s
Legal code:       %s

You are free to share and adapt the data for any purpose, including commercially, provided you give appropriate
credit, provide a link to the licence and indicate if changes were made.

Attribution: %s, "%s", version %s.

The strings in the data are facts or test values published in the specifications and documents listed in
README.md ("Specification sources and licences"); this notice does not change the terms of those sources.
The scripts in scripts/ are licensed separately under the MIT licence (see LICENSE).
""" % (TITLE, CC_URL, CC_LEGAL, ORG, TITLE, VERSION))
    with open(os.path.join(root, "LICENSE"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("""MIT License

Copyright (c) 2026 %s

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software") (the files under scripts/), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
""" % ORG)
    with open(os.path.join(root, "CITATION.cff"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("""cff-version: 1.2.0
message: "If you use this dataset, please cite it as below."
type: dataset
title: "%s"
version: "%s"
date-released: "%s"
license: CC-BY-4.0
doi: 10.5281/zenodo.24540799
url: "%s"
abstract: "%d labelled strings for testing blockchain address validators across 12 address families. Each label states whether the string is a well-formed mainnet address under the cited specification."
keywords:
  - blockchain
  - address validation
  - test vectors
  - checksum
  - Bech32
  - Base58Check
  - EIP-55
authors:
  - name: "%s"
    email: "%s"
    website: "%s"
""" % (TITLE, VERSION, RELEASE_DATE, TOOL_URL, n, ORG, CONTACT, TOOL_URL))
    with open(os.path.join(root, "CHANGELOG.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("""# Changelog

## %s (%s)

First release.

- %d rows in 12 address families (see README.md for the counts by family and origin).
- Families: EVM-style accounts, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Zcash (transparent forms), Solana, TRON, NEAR, TON, XRP Ledger, Stellar.
- `data/address-families.*` and `data/cross-family-ambiguities.*` added.
- Two independent implementations (`scripts/build.py`, `scripts/verify.py`) agree on every label.
- Library comparison column for multichain-memo-address-validator 1.0.0.
""" % (VERSION, RELEASE_DATE, n))
    zen = {
        "title": TITLE,
        "upload_type": "dataset",
        "description": "Labelled test strings for blockchain address validators in 12 address families (EVM-style accounts, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Zcash transparent, Solana, TRON, NEAR, TON, XRP Ledger, Stellar). Each row states whether the string is a well-formed mainnet address under the cited specification, with the reason when it is not, the origin of the string (specification, public-well-known, derived or mutation) and the specification URL. Includes a table of family formats and a table of cross-family ambiguities. Parts were prepared with AI coding tools; labels are checked by two independent implementations.",
        "version": VERSION,
        "publication_date": RELEASE_DATE,
        "access_right": "open",
        "license": "cc-by-4.0",
        "creators": [{"name": ORG}],
        "keywords": ["blockchain", "address validation", "test vectors", "checksum", "Bech32", "Base58Check", "EIP-55", "CashAddr", "StrKey"],
        "related_identifiers": [
            {"identifier": LIB_URL, "relation": "isDerivedFrom", "scheme": "url"},
            {"identifier": TOOL_URL, "relation": "references", "scheme": "url"},
        ],
    }
    with open(os.path.join(root, ".zenodo.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(zen, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    # ------------------------------------------------------------------ Frictionless descriptor
    def enum_of(col):
        return sorted(set(r[col] for r in rows))
    vec_fields = [
        {"name": "id", "type": "string", "constraints": {"required": True, "unique": True, "pattern": "^[a-z]+-[0-9]{4}$"}, "description": "Stable row identifier."},
        {"name": "family", "type": "string", "constraints": {"required": True, "enum": list(FAMILIES)}, "description": "Address family code."},
        {"name": "chain_caip2", "type": "string", "constraints": {"pattern": "^$|^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$"}, "description": "CAIP-2 identifier of the reference network; empty when none is registered."},
        {"name": "network", "type": "string", "constraints": {"required": True, "enum": ["mainnet", "testnet", "none"]}, "description": "Network of the form."},
        {"name": "address", "type": "string", "constraints": {"required": True}, "description": "The test string, exactly as given."},
        {"name": "encoding_form", "type": "string", "constraints": {"required": True}, "description": "Form of the string."},
        {"name": "checksum_algorithm", "type": "string", "constraints": {"required": True}, "description": "Checksum algorithm of the form."},
        {"name": "spec_valid", "type": "boolean", "constraints": {"required": True}, "description": "Well-formed mainnet address under the cited specification."},
        {"name": "reason", "type": "string", "constraints": {"enum": [""] + list(REASONS)}, "description": "Reason when spec_valid is false; empty otherwise."},
        {"name": "memo_or_tag_convention", "type": "string", "constraints": {"required": True, "enum": ["none", "memo", "comment", "destination_tag"]}, "description": "Family convention."},
        {"name": "origin", "type": "string", "constraints": {"required": True, "enum": ["specification", "public-well-known", "derived", "mutation"]}, "description": "How the string was obtained."},
        {"name": "source", "type": "string", "constraints": {"required": True}, "description": "Where the value comes from or which rule produced it."},
        {"name": "source_url", "type": "string", "format": "uri", "constraints": {"required": True, "pattern": "^https://"}, "description": "Specification URL."},
        {"name": "notes", "type": "string", "description": "Remarks."},
        {"name": LIB_COLUMN, "type": "boolean", "constraints": {"required": True}, "description": "inspectAddress(...).valid of multichain-memo-address-validator 1.0.0."},
    ]
    fam_fields = [{"name": c, "type": t, "constraints": {"required": True}} if c not in ("chain_caip2", "spec_urls") else {"name": c, "type": "array", "arrayItem": {"type": "string"}} for c, t in [
        ("family", "string"), ("name", "string"), ("chain_caip2", "array"), ("alphabet", "string"), ("lengths", "string"), ("prefixes", "string"),
        ("checksum_algorithm", "string"), ("case_rules", "string"), ("memo_or_tag_convention", "string"), ("memo_notes", "string"), ("spec_urls", "array")]]
    amb_fields = [
        {"name": "id", "type": "string", "constraints": {"required": True, "unique": True, "pattern": "^amb-[0-9]{4}$"}},
        {"name": "kind", "type": "string", "constraints": {"required": True, "enum": ["same_string", "same_bytes", "not_ambiguous_control"]}},
        {"name": "string", "type": "string", "constraints": {"required": True}},
        {"name": "families_valid", "type": "array", "arrayItem": {"type": "string"}},
        {"name": "related", "type": "array", "arrayItem": {"type": "string"}},
        {"name": "what_it_shows", "type": "string", "constraints": {"required": True}},
        {"name": "source", "type": "string", "constraints": {"required": True}},
        {"name": "source_url", "type": "string", "format": "uri", "constraints": {"required": True}},
        {"name": "notes", "type": "string"},
    ]
    dp = {
        "$schema": "https://datapackage.org/profiles/2.0/datapackage.json",
        "name": "address-format-test-vectors",
        "title": TITLE,
        "version": VERSION,
        "created": RELEASE_DATE,
        "description": "Labelled test strings for blockchain address validators in 12 address families. spec_valid is a property of the cited specification, not of a library.",
        "keywords": ["blockchain", "address validation", "test vectors"],
        "licenses": [{"name": "CC-BY-4.0", "path": CC_URL, "title": "Creative Commons Attribution 4.0 International"}],
        "contributors": [{"title": ORG, "email": CONTACT, "path": TOOL_URL, "roles": ["author", "publisher"]}],
        "homepage": TOOL_URL,
        "resources": [
            {"name": "address-vectors", "path": "data/address-vectors.csv", "format": "csv", "mediatype": "text/csv", "encoding": "utf-8",
             "profile": "tabular-data-resource", "schema": {"fields": vec_fields, "primaryKey": ["id"], "uniqueKeys": [["family", "address"]], "missingValues": []}},
            {"name": "address-families", "path": "data/address-families.csv", "format": "csv", "mediatype": "text/csv", "encoding": "utf-8",
             "profile": "tabular-data-resource", "schema": {"fields": fam_fields, "primaryKey": ["family"], "missingValues": []}},
            {"name": "cross-family-ambiguities", "path": "data/cross-family-ambiguities.csv", "format": "csv", "mediatype": "text/csv", "encoding": "utf-8",
             "profile": "tabular-data-resource", "schema": {"fields": amb_fields, "primaryKey": ["id"], "missingValues": []}},
        ],
    }
    with open(os.path.join(root, "datapackage.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(dp, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
