# SURADAR B9 Supplier-Run Conformance Vectors — IETF 126 Hackathon

**SURADAR delegation-layer vectors derived from the shared B9 interop
scenario, for cross-org-delegation-registry issue #3**

All data is **SYNTHETIC**. Every identity, organization, grant, endpoint, and
event in this artifact is fictional.

## Reproducibility boundary (read first)

These vectors are **supplier-run**: the harness executes inside the SURADAR
maintainer's private checkout, and what is published here is the vectors plus
the supplier-reported expected output. Stated precisely:

- **Independently checkable by anyone:** the `subject_digest` computation.
  The canonical action is public (reproduced below, and in the AAC bundle's
  `pos-provenance-binding/input.json`). Any RFC 8785 JCS implementation can
  recompute `SHA-256(JCS(action))` and confirm the digest.
- **Supplier-reported only:** the chain-attestation signing and verification,
  and the divergence-detection results. The HMAC key and the precise
  signing-input construction are NOT included in these published artifacts,
  so third parties cannot re-verify the published signature from this run kit
  alone. The signature hex in each `vector.json` is a recorded output, not an
  independently verifiable proof.
- Per this registry's own grading, this evidence is `local_harness`. An
  independent party re-running the scenario in their own stack is what would
  upgrade it.

## The shared canonical action

The B9 scenario's canonical action (authored in the AAC bundle,
`interop-vectors/provenance-binding/pos-provenance-binding/input.json` on
`github.com/action-state-group/agent-action-capsule`, branch
`feat/provenance-binding-vectors`):

```json
{
  "action_type": "delegation.api_call",
  "delegator": "org:alpha-corp:agent-A@v2",
  "delegatee": "org:beta-systems:agent-B@v1",
  "parameters": {
    "api_endpoint": "https://api.beta-systems.example/v1/data-export",
    "grant_id": "grant:alpha-corp:2026-Q3-0042",
    "scope": ["read:records", "export:csv"],
    "not_after": "2026-07-18T23:59:59Z",
    "max_records": "5000"
  },
  "policy_ref": "policy:alpha-corp:cross-org-delegation@v1",
  "requested_at": "2026-07-18T10:00:00Z"
}
```

## The subject_digest

```text
0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
```

This is `SHA-256(JCS(action))` over the action above (RFC 8785 JCS; no
absent-field normalization applies because the action has no null or empty
members). **Check it yourself** with any JCS implementation; agreement does
not depend on trusting either supplier. SURADAR additionally recomputes it
with its own JCS implementation in a private test
(`TestInteropSubjectDigest_B9`); that recompute matching is supplier-reported.

## What the vectors contain

| Vector | Contents | Supplier-reported expected result |
|---|---|---|
| `pos-pedigree-binding/vector.json` | A single-grant delegation chain (alpha-corp to beta-systems, scopes `read:records` + `export:csv`, target = the data-export endpoint) with its recorded HMAC attestation, plus an honest observed `export:csv` action | zero divergences |
| `neg-pedigree-splice/vector.json` | The same chain and attestation, with the observed action's scope substituted to `delete:records` | rejected with divergence class `scope_creep` |

## Supplier-run commands

Run by the supplier in a private SURADAR checkout (`<glyphzero>` = checkout
root); reproduced here for transparency of method, not as an outsider
build path:

```sh
cd <glyphzero>/suradar
go test ./delegation/ -run TestInteropSubjectDigest_B9 -v
go test ./capability/ -run TestInteropB9_PedigreeHardening -v
go test ./delegation/ ./capability/ -race
```

Supplier-reported output:

```text
SURADAR JCS subject_digest = 0b4da06b84263c0ee02746e52f6893a40586c0563e01961314b1bddf74d72cb6
positive: clean; splice: scope_creep caught
all tests PASS, race detector clean
```

## What the checks are, stated precisely so they are not overread

- The negative is a **terminal action-scope check**: an observed
  `delete:records` action is rejected against the single grant's allowed
  scope-set (`scope_creep`). It is not a grant-document or digest-binding
  splice test, and it does not bind the divergence check to
  `subject_digest`.
- These vectors do **not** exercise PEDIGREE's core per-hop narrowing rule:
  the chain contains only one grant, and a one-grant chain cannot
  demonstrate that a child grant is narrower than its parent. Covered:
  supplier-run single-grant attestation processing and terminal action-scope
  enforcement. Not covered: parent/child scope subsetting, multi-hop
  verification, key rotation, expiry failure.
- The AAC harness in the counterpart bundle performs a **different** check:
  `provenance_ref_binds` confirms the carried grant document is the exact
  artifact the capsule's provenance reference committed to. The two are
  complementary checks at different layers over the same synthetic scenario
  and the same shared `subject_digest`. They are not the same test, and
  neither reproduces the other.

## Synthetic key note

The chain attestation was produced with a synthetic, throwaway HMAC test key
that exists only in the supplier's private test code. It must not be reused,
and it is deliberately not published; consequently the attestation signature
is not third-party verifiable (see the reproducibility boundary above).
