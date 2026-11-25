# Blockchain address format test vectors

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24540799.svg)](https://doi.org/10.5281/zenodo.24540799)

Version 1.0.0, 2026-11-26. Licence: CC-BY-4.0 (data), MIT (scripts). Published by AllSwap (Haohang Network Technology Co., Limited). Contact: service@allswap.io.

A set of 1386 labelled strings for people who write or test blockchain address validators. Each row is a string and a verdict: is it a well-formed mainnet address of its family **under the cited specification**. The verdict is a property of the specification, not of any library. The set covers 12 address families (EVM-style accounts, Bitcoin, Litecoin, Dogecoin, Bitcoin Cash, Zcash transparent addresses, Solana, TRON, NEAR, TON, XRP Ledger and Stellar). Every valid string is taken from, or is a deterministic re-encoding of, a value printed in a specification, a test-vector list or other public documentation; every invalid string is either printed as invalid in a specification or produced from a valid one by a documented rule.

Parts of this dataset, its scripts and this text were prepared with AI coding tools. Correctness does not rest on that: every label is computed twice, by two independent implementations written from the specifications (`scripts/build.py` and `scripts/verify.py`), and `scripts/verify.py` stops on any disagreement. See [Verification](#verification).

It grew out of the test vectors of the library <https://github.com/allswapio/multichain-memo-address-validator>, and a related interactive address checker is at <https://allswap.io/tools/address-validator>. Neither reads this dataset; it is published so that anyone can test an implementation against it.

## Files

| File | Content |
| --- | --- |
| `data/address-vectors.csv`, `data/address-vectors.json` | the 1386 rows (same rows and columns in both files) |
| `data/address-families.csv`, `.json` | one row per family: alphabet, lengths, prefixes, checksum, case rules, memo or tag convention, specification URLs |
| `data/cross-family-ambiguities.csv`, `.json` | 12 strings or byte values that are valid under several families, each with a source |
| `datapackage.json` | Frictionless Data package descriptor: field types, enumerations, patterns and unique keys |
| `scripts/build.py`, `scripts/docs.py` | deterministic build (Python 3 standard library only, no network, no randomness) |
| `scripts/verify.py` | independent verifier: recomputes `spec_valid` and the reason from the specifications and fails on any mismatch |
| `scripts/check-verifier.py` | mutation check of the verifier: flips ten labels (fixed seed) and requires `verify.py` to fail on each |
| `scripts/check-package.py` | structure check of `datapackage.json` against the data files (types, enumerations, patterns, unique keys) |
| `scripts/compare.mjs` | checks the library column against a local copy of the library (Node.js 22) |
| `scripts/library-results.json` | the library results that `build.py` copies into the library column (written by `compare.mjs --write`) |
| `LICENSE-DATA`, `LICENSE`, `CITATION.cff`, `CHANGELOG.md`, `.zenodo.json` | licence notices and citation metadata |

## Counts

Computed by `scripts/docs.py` from the data files at build time.

| Family | Rows | spec_valid true | spec_valid false | specification | public-well-known | derived | mutation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| evm | 122 | 47 | 75 | 30 | 13 | 9 | 70 |
| btc | 161 | 29 | 132 | 46 | 0 | 24 | 91 |
| ltc | 127 | 27 | 100 | 0 | 0 | 38 | 89 |
| doge | 82 | 13 | 69 | 0 | 0 | 22 | 60 |
| bch | 124 | 43 | 81 | 24 | 0 | 30 | 70 |
| zec | 118 | 18 | 100 | 1 | 0 | 27 | 90 |
| sol | 99 | 47 | 52 | 0 | 31 | 5 | 63 |
| tron | 91 | 18 | 73 | 4 | 0 | 21 | 66 |
| near | 135 | 47 | 88 | 55 | 0 | 15 | 65 |
| ton | 105 | 20 | 85 | 5 | 0 | 24 | 76 |
| xrp | 122 | 30 | 92 | 20 | 0 | 21 | 81 |
| stellar | 100 | 15 | 85 | 17 | 0 | 18 | 65 |
| total | 1386 | 354 | 1032 | 202 | 44 | 254 | 886 |

Rows by `spec_valid = false` reason:

| reason | rows | meaning |
| --- | --- | --- |
| empty | 12 | the string is empty |
| whitespace | 160 | contains a space, tab or line break |
| bad_charset | 127 | a character outside the alphabet of the form |
| bad_length | 182 | wrong length for the form, or an empty payload |
| bad_checksum | 245 | the checksum does not match |
| bad_version_byte | 26 | the version byte, prefix bytes, flags or type bits are not those of a mainnet address of the family |
| bad_prefix | 11 | wrong prefix, HRP or leading characters |
| wrong_network | 32 | well formed, but for a test network |
| mixed_case | 13 | upper and lower case in a form that allows only one |
| bad_case | 13 | the wrong case for a case-sensitive form |
| bad_witness_version | 4 | witness version above 16 |
| bad_program_length | 10 | witness program of an invalid length |
| bad_padding | 4 | non-zero or excessive padding bits |
| wrong_checksum_constant | 9 | Bech32 constant where Bech32m is required, or the reverse |
| uri_wrapped | 42 | an address inside a URI-style or prefixed wrapper |
| extra_data | 51 | a valid address followed by a query, tag or memo |
| other_family | 55 | an address of another family |
| not_address_type | 5 | a valid encoding of a type that is not an address (Stellar signer, pool and balance IDs) |
| bad_format | 31 | violates a structural rule of the form (separators, tag fields, workchain) |

Rows by network: mainnet 844, none 506, testnet 36.

Mutation rules: 88 distinct rule names, at most 5 rows of one rule in one family (the build applies a cap of 3 to the generic rules and 5 to the others; the verifier checks the limit of 5). Every mutation row names its rule in `source`, and its base row where it has one.

## Columns of `address-vectors`

| Column | Type | Meaning |
| --- | --- | --- |
| id | string | Stable identifier, family code and a four-digit number (btc-0001). Numbers are assigned in build order and do not change between builds of the same release. |
| family | string | One of the 12 family codes. |
| chain_caip2 | string | CAIP-2 identifier of the reference network of the row, taken from the namespace pages listed below. Empty when no registered identifier was found (zec, near, ton). For evm it is eip155:1 as a reference: the format is shared by all eip155 chains. |
| network | string | mainnet, testnet or none. none: the format does not encode a network (evm, sol, near, TON raw form) or the string is too damaged to tell. |
| address | string | The test string, exactly as given, including whitespace and non-ASCII characters where a rule inserts them. |
| encoding_form | string | Short description of the form the row represents or was derived from. For a mutation row it is the form of its base row, that is the form the string was meant to have. |
| checksum_algorithm | string | Checksum the form carries. none where the form has no checksum. |
| spec_valid | boolean | true: the string is a well-formed mainnet address of the family under the cited specification. false: it is not; reason says why. Independent of any library. |
| reason | string | Empty when spec_valid is true. Otherwise one value of the controlled vocabulary below. When several rules fail, one is given. |
| memo_or_tag_convention | string | The family convention: none, memo, comment or destination_tag. Per family, not per address. |
| origin | string | specification, public-well-known, derived or mutation (definitions below). |
| source | string | Text saying where the value comes from or which rule produced it. |
| source_url | string | URL of the specification that defines the form. Each URL was fetched and answered 200 (see README, limitations). |
| notes | string | Remarks, including, where the library column differs from spec_valid, the policy of library 1.0.0 that explains it. |
| multichain_memo_address_validator_1_0_0 | boolean | Result of inspectAddress(family, address).valid of multichain-memo-address-validator 1.0.0. A comparison column, not a label. |

### `origin`

| Value | Meaning |
| --- | --- |
| specification | a string printed in a specification, its test vectors or its examples, copied exactly |
| public-well-known | a published system, program or contract address, or another widely published public address, cited from a page that was read |
| derived | a deterministic re-encoding of a published value (a published hash or key under another version byte, HRP or alphabet), or a documented variant (case, prefix omitted) |
| mutation | a published or derived string changed by one documented rule |

### `reason`

| Value | Meaning |
| --- | --- |
| empty | the string is empty |
| whitespace | contains a space, tab or line break |
| bad_charset | a character outside the alphabet of the form |
| bad_length | wrong length for the form, or an empty payload |
| bad_checksum | the checksum does not match |
| bad_version_byte | the version byte, prefix bytes, flags or type bits are not those of a mainnet address of the family |
| bad_prefix | wrong prefix, HRP or leading characters |
| wrong_network | well formed, but for a test network |
| mixed_case | upper and lower case in a form that allows only one |
| bad_case | the wrong case for a case-sensitive form |
| bad_witness_version | witness version above 16 |
| bad_program_length | witness program of an invalid length |
| bad_padding | non-zero or excessive padding bits |
| wrong_checksum_constant | Bech32 constant where Bech32m is required, or the reverse |
| uri_wrapped | an address inside a URI-style or prefixed wrapper |
| extra_data | a valid address followed by a query, tag or memo |
| other_family | an address of another family |
| not_address_type | a valid encoding of a type that is not an address (Stellar signer, pool and balance IDs) |
| bad_format | violates a structural rule of the form (separators, tag fields, workchain) |

### CAIP-2 identifiers

Taken from the namespace pages of the Chain Agnostic Standards Alliance: `bip122` (Bitcoin, Bitcoin Cash, Litecoin, Dogecoin test cases), `eip155`, `solana`, `stellar` (`pubnet`), `tron` (`tron:728126428`) and `xrpl` (`xrpl:0`). The `bip122` page lists no Zcash identifier, and no `near` or `ton` namespace page was found, so those rows have an empty `chain_caip2`. Registered identifiers were not invented.

## How `spec_valid` is decided

`spec_valid` answers one question: is the string a well-formed **mainnet** address of the family under the cited specification. Rules used (the same in `build.py` and, independently, in `verify.py`):

- **EVM.** `0x` followed by 40 hexadecimal digits (the Ethereum JSON-RPC encoding of an address). Letters of one case only: valid, no checksum asserted. Letters of both cases: must equal the EIP-55 capitalisation. EIP-55 itself does not say that single-case strings are accepted; this is the convention of the ecosystem and is marked `checksum_algorithm = none (single-case hex ...)`. Chain-specific capitalisations (EIP-1191) are not EIP-55 checksums and fail it. The zero address is well formed.
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

Strings that the specifications leave open (for example mixed-case hex in a TON raw address, the upper-case `0X` prefix, other TON workchains) are not included, so that no label depends on a guess.

## Where the library differs

The last column records `inspectAddress(family, address).valid` of multichain-memo-address-validator 1.0.0, run by `scripts/compare.mjs` on a local copy. It differs from `spec_valid` on **90 of 1386 rows**, all in one direction: spec true and library false on 90 rows. The library is stricter than the specifications by design (it accepts a deliberately narrow set of forms); on this data it never accepts a string that a specification rejects. The notes of each such row give the policy.

| Family | Rows that differ | Policy of the library (version 1.0.0) | Rows |
| --- | --- | --- | --- |
| evm | 1 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| btc | 6 | the library accepts lower-case Bech32 only; BIP-173 also allows an all-upper-case string | 2 |
| btc | 6 | the library accepts witness version 0 (20 or 32 bytes) and version 1 (32 bytes) only; BIP-350 defines versions 2 to 16 and 2 to 40 byte programs as valid | 2 |
| btc | 6 | the library refuses all-zero values (application policy); the encoding itself is well formed | 2 |
| ltc | 9 | the library treats 3... as a Bitcoin P2SH string and refuses it for Litecoin (pitfall ltc-legacy-3-prefix); Litecoin Core accepts version 5 | 6 |
| ltc | 9 | the library accepts witness version 0 (20 or 32 bytes) and version 1 (32 bytes) only; BIP-350 defines versions 2 to 16 and 2 to 40 byte programs as valid | 2 |
| ltc | 9 | the library accepts lower-case Bech32 only; BIP-173 also allows an all-upper-case string | 1 |
| doge | 1 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| bch | 26 | the library accepts 20-byte CashAddr hashes only; the specification defines sizes from 20 to 64 bytes | 11 |
| bch | 26 | the library accepts lower-case CashAddr only; the specification also accepts all upper case | 8 |
| bch | 26 | the library accepts CashAddr only and refuses the legacy Base58 form | 7 |
| zec | 5 | the library accepts Base58Check transparent addresses only (t1..., t3...) | 5 |
| sol | 1 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| tron | 7 | the library accepts the Base58Check form only | 6 |
| tron | 7 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| near | 6 | the library accepts a top-level (dot-free) ID of 32 or more characters only as 64 hex digits, 0x + 40 hex or 0s + 40 hex; the grammar allows any such lower-case string | 5 |
| near | 6 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| ton | 4 | the library accepts workchain 0 only | 3 |
| ton | 4 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| xrp | 15 | the library accepts classic addresses only and refuses X-addresses | 14 |
| xrp | 15 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |
| stellar | 9 | the library accepts G... account IDs only | 8 |
| stellar | 9 | the library refuses all-zero values (application policy); the encoding itself is well formed | 1 |

## Cross-family ambiguities

`data/cross-family-ambiguities.*` lists strings that are valid under several families and byte values that appear under several encodings, each shown by an example and a source. The families in which a string is valid are computed from the same rules as above and re-checked by `verify.py`. Kinds: `same_string` (one string valid under several families), `same_bytes` (the same underlying bytes written in several families) and `not_ambiguous_control` (a string that looks ambiguous but is not).

| id | kind | string | valid under |
| --- | --- | --- | --- |
| amb-0001 | same_string | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | btc, bch |
| amb-0002 | same_string | `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy` | btc, ltc, bch |
| amb-0003 | same_string | `0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed` | evm, near |
| amb-0004 | same_string | `11111111111111111111111111111111` | sol, near |
| amb-0005 | same_string | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` | btc, near |
| amb-0006 | same_string | `qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a` | bch, near |
| amb-0007 | not_ambiguous_control | `0x52908400098527886E0F7030069857D2E4169EE7` | evm |
| amb-0008 | not_ambiguous_control | `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62...` | near |
| amb-0009 | same_bytes | `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | btc, bch |
| amb-0010 | same_bytes | `0:d75a980182b10ab7d54bfed3c964073a0ee172f3daa...` | ton |
| amb-0011 | same_bytes | `0x8840E6C55B9ADA326D211D818C34A994AECED808` | evm |
| amb-0012 | same_bytes | `0x27b1FdB04752BBc536007A920D24ACB045561c26` | none (valid under no family) |

## Verification

All commands run from the repository root. Python 3 (standard library only) and Node.js 22 are needed. Nothing is downloaded.

```sh
python3 scripts/build.py                      # writes data/ and the documentation
python3 scripts/verify.py                     # independent recomputation of every label; exits 1 on any mismatch
node scripts/compare.mjs <path>/src/index.mjs # checks the library column; add --write to refresh scripts/library-results.json
python3 scripts/check-verifier.py             # flips ten labels; verify.py must fail on every one
python3 scripts/check-package.py              # datapackage.json against the data files
```

`verify.py` shares no code with `build.py` or with the library. It implements, from the specifications, Keccak-256 and EIP-55, Base58 and Base58Check (Bitcoin and XRPL alphabets), Bech32 and Bech32m, CashAddr, CRC16-XMODEM, base64 and base32 StrKey decoding, and recomputes `spec_valid` for every row; it also checks that the declared reason is one of the reasons that actually apply to the string, the unique key (`family`, `address`), the cap of mutation rows per rule, the CAIP-2 values, that CSV and JSON hold the same rows, and the claims of the ambiguity table.

## Limitations

- **Specification readings.** Where a specification is silent the row is left out (see above), but the readings listed in "How `spec_valid` is decided" are the maintainers' reading of the cited texts. They are open to correction; please open an issue with the passage you rely on.
- **Zcash.** No shielded (Sapling `zs1`) or unified (`u1`) address that is printed in a page that was read could be traced, so none is included. ZIP-173 lists a TODO for Sapling vectors.
- **Litecoin MWEB**, Bitcoin testnet forms beyond the listed rows, regtest, and other networks of the families are not systematically covered. Test-network rows exist to check that a mainnet validator refuses them.
- **No on-chain check.** The data says nothing about whether an address exists, is funded or accepts a given token. A deterministic re-encoding of a published hash is a well-formed string, not a statement about who controls it.
- **Re-encodings.** Many valid strings of the derived origin re-encode the same published 20-byte hashes and 32-byte public keys under different version bytes and alphabets. They test the encoding, not the existence of an account on that chain.
- **Specification pages change.** Each value was copied from the page as read on 2026-11-26 and the URL was checked to answer 200 on that day. The Solana documentation site refused automated requests (HTTP 429), so Solana values come from the `solana-sdk` source files listed in the sources.
- **Library column.** It describes one version of one library and is a comparison aid, not part of the verdict.
- **Not verified**: behaviour of other libraries; correctness of the specifications themselves; the data against a live node of any chain.

## Specification sources and licences

Strings in this set are facts or test values printed in the sources below; no prose of the sources is reproduced. Licences are listed as found at the time of reading; they are given for attribution and do not change the licence of this dataset.

| Source | URL | Licence as found |
| --- | --- | --- |
| EIP-55, EIP-1014, EIP-1191, EIP-1820, EIP-1967, EIP-2470, EIP-2935, EIP-3770, EIP-4788, EIP-7002, EIP-7251 (Ethereum Improvement Proposals) | https://eips.ethereum.org/ | CC0 1.0 (the EIP repository) |
| Ethereum JSON-RPC documentation (hex encoding) | https://ethereum.org/en/developers/docs/apis/json-rpc/ | the ethereum.org website repository carries the MIT licence; only the stated encoding rule is used |
| BIP-13, BIP-49, BIP-84, BIP-86, BIP-173, BIP-350 (Bitcoin Improvement Proposals) | https://github.com/bitcoin/bips | set per BIP in its preamble: BSD-2-Clause (BIP-86, BIP-173, BIP-350), CC0-1.0 (BIP-84), public domain (BIP-49) |
| Bitcoin Wiki: Base58Check encoding; Technical background of version 1 Bitcoin addresses; Address; Genesis block; Pay to script hash | https://en.bitcoin.it/wiki/Main_Page | Creative Commons Attribution 3.0 unless otherwise noted (stated on the pages) |
| Litecoin Core: chainparams.cpp, key_io.cpp | https://github.com/litecoin-project/litecoin | MIT |
| Dogecoin Core: chainparams.cpp | https://github.com/dogecoin/dogecoin | MIT |
| Zcash: chainparams.cpp | https://github.com/zcash/zcash | MIT or Apache-2.0 per the repository (the licence detector reports no single identifier) |
| Zcash ZIP-320 (TEX addresses) | https://zips.z.cash/zip-0320 | MIT (the zcash/zips repository) |
| CashAddr specification | https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md | MIT (the bitcoincash.org repository) |
| solana-sdk: sdk-ids and address crates | https://github.com/anza-xyz/solana-sdk | Apache-2.0 |
| TRON developer documentation, Accounts | https://developers.tron.network/docs/account | no licence statement found on the page; only the example values and format rules are used |
| NEAR documentation, Address (Account ID) | https://docs.near.org/protocol/accounts-contracts/account-id | Apache-2.0 (the near/docs repository) |
| near-account-id-rs: test_data.rs, validation.rs | https://github.com/near/near-account-id-rs | MIT OR Apache-2.0 |
| TON documentation, Address formats; Internal messages | https://docs.ton.org/v3/documentation/smart-contracts/addresses/address-formats | MIT (the ton-org/docs repository) |
| XRPL documentation, Addresses | https://xrpl.org/docs/concepts/accounts/addresses | MIT (the XRP Ledger Dev Portal) |
| XLS-5 Tagged Addresses | https://github.com/XRPLF/XRPL-Standards/blob/master/XLS-0005-tagged-addresses/README.md | MIT (the XRPL-Standards repository) |
| Stellar SEP-23 (Strkeys), SEP-29 | https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md | no licence file found in the repository at the time of reading; only test strings and format rules are used |
| RFC 8032 (test public keys, section 7.1) | https://www.rfc-editor.org/rfc/rfc8032 | IETF Trust legal provisions; only the published test public keys are used |
| CAIP-2 namespaces: bip122, eip155, solana, stellar, tron, xrpl | https://namespaces.chainagnostic.org/ | CC0 (stated on the pages) |

The exact URL of the specification of every row is in `source_url`.

## Licence

The data (`data/`, `datapackage.json`, this README) is licensed under the Creative Commons Attribution 4.0 International licence (CC-BY-4.0): <https://creativecommons.org/licenses/by/4.0/>, legal code <https://creativecommons.org/licenses/by/4.0/legalcode>. The scripts in `scripts/` are licensed under the MIT licence (`LICENSE`). See `LICENSE-DATA`.

## How to cite

> AllSwap (Haohang Network Technology Co., Limited). *Blockchain address format test vectors*, version 1.0.0, 2026. https://allswap.io/tools/address-validator

DOI of version 1.0.0: <https://doi.org/10.5281/zenodo.24540799>. All versions: <https://doi.org/10.5281/zenodo.24540798>. `CITATION.cff` holds the machine-readable citation.

Attribution: please credit "AllSwap (Haohang Network Technology Co., Limited)" and link to the licence. Suggested short form: "Blockchain address format test vectors, AllSwap, CC-BY-4.0".

Contact: service@allswap.io
