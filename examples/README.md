# Examples

Scripts behind two articles about this dataset. The Python scripts need the standard library only. The `.mjs`
scripts need Node.js 22 and `npm install multichain-memo-address-validator@1.0.0`.

```sh
python3 examples/a1_cross_family.py
python3 examples/a2_single_char_substitution.py
node examples/c2_bech32_spec_check.mjs
```

| Script | What it shows |
| :--- | :--- |
| `a1_cross_family.py`, `a1b_library_cross_check.mjs` | strings that are well formed under more than one family |
| `a2_single_char_substitution.py`, `snippet_a_substitute.py` | which one-character edits stay valid with and without a checksum |
| `a3_bech32_constants.py`, `snippet_a_bech32.py`, `c2_bech32_spec_check.mjs` | Bech32 and Bech32m constants |
| `a4_spec_vs_library.py`, `c1_dataset_traps.mjs` | rows where the specification and the library differ |
| `a5_ton_forms.py` | the forms of one TON account |
| `a6_mutation_rows.py` | one-character mutation rows that stay valid |
| `c0_minimal.mjs`, `c3_input_feedback.mjs` | validator results and input feedback |

Licence: MIT, like `scripts/`.
