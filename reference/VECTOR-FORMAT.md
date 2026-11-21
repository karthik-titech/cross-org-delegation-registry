# PEDIGREE -01 vector format

Each case in [vectors/pedigree-01](../vectors/pedigree-01/) is stored as `<id>.json`. See [valid-3-hop.json](../vectors/pedigree-01/valid-3-hop.json) for a complete example.

| Case field | Contents |
| --- | --- |
| `id` | Case ID, also used as the filename stem. |
| `source` | `appendix_a` for cases based on Appendix A of PEDIGREE -01, or `local` for cases added by this suite. |
| `presentations` | Ordered list. Each entry has `chain` (compact tokens in root-to-leaf order), `invocation` (compact invocation or an empty string), and `args` (the request argument object). It also records `outcome` and the ordered `trusted_inputs_used` labels. |
| `wpt` | One Workload Proof Token assumption per presentation. Each entry has `presentation_index` (one-based), `holder_key` (base64-encoded Ed25519 public key), `fresh` (assumed freshness and replay-check result), and `covers` (request fields covered). |
| `consent` | Trusted fixture answers. Each entry has `trust_anchor_kid`, `consent_id`, `valid_at` (RFC 3339 timestamp), and `active` (boolean). |
| `at` | RFC 3339 verification time. |
| `trust_anchors` | Map from configured issuer IDs to base64-encoded Ed25519 public keys. |
| `verifier_ids` | Accepted verifier audience IDs. |
| `replay_available` | Boolean that controls whether invocation replay state is available. |
| `keys` | Reproducibility data. Each entry has a `label` of `TEST ONLY`, a numeric `index`, and the hexadecimal Ed25519 seed in `seed_hex`. |

[expected.json](../vectors/pedigree-01/expected.json) is the frozen result table. Its `cases` array has one entry per presentation with `id`, `source`, one-based `presentation`, `outcome`, and ordered `trusted_inputs_used`. The generator leaves this file untouched.

[manifest.json](../vectors/pedigree-01/manifest.json) is generator-owned. It records `profile`, `arguments_binding`, `wpt`, `policy`, `ceiling_ref`, and `ceiling`. Each entry in `cases` has `id`, `file`, `source`, and `digest`. A digest is `sha256:` followed by the lowercase hexadecimal SHA-256 of the case file bytes.

## Running another implementation

1. Load each case listed in `expected.json`. Use the manifest digests to check the case file bytes.
2. Configure the verifier with the case's trust anchors, verifier IDs, and verification time. Use the manifest's fixture profile and the pinned policy effects and decisions in [fixtures.json](go/pedigree/testdata/fixtures.json).
3. Verify each presentation in array order using its `chain`, `invocation`, and `args`. Supply the matching WPT assumption and the consent answers as trusted fixture inputs. When `replay_available` is true, start with empty replay state for each case and share it across that case's presentations. Otherwise, report replay state as unavailable to the verifier.
4. Compare the result and its ordered trusted-input labels to the `expected.json` row for that case ID and presentation number. Check that the case file's recorded result also agrees with that row.
