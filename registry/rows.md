# Registry rows

One row per mechanism per claim. Each row follows
[`../schema/row-schema.md`](../schema/row-schema.md). Suppliers add and
correct their own rows by pull request; see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

Rows below the seed are contributed by their suppliers. A `TODO` row is a
placeholder inviting the named supplier's PR; it asserts nothing until they
fill it.

---

## Seed row (worked example)

### PEDIGREE / C-002 (authority)

- **c_id:** C-002 (who authorized the delegation)
- **r_mapping:** R5, R1
- **mechanism:** PEDIGREE per-hop delegation chain
- **supplier:** Glyphzero, Inc.
- **claim:** authority for this operation was conveyed from the root
  principal and narrowed at every hop; the terminal scope covers the
  operation. Does not by itself prove holder possession (R4), human
  authorization, or acceptance.
- **carrier:** per-hop delegation tokens, conveyed inline with the request.
- **verifier_and_rule:** relying party, offline: re-verify each hop's
  signature against its issuer key, check per-hop scope subsetting and
  mandate narrowing, take effective expiry as the minimum over hops,
  require the operator-ceiling conjunct.
- **binding_and_freshness:** bound to the root principal and the holder's
  key; staleness bounded by chain lifetime. Fail-closed on stale revocation
  data is NOT yet normative in PEDIGREE (see the C-008 row); this is an
  admitted gap, scheduled for pedigree-02.
- **failure_behavior:** any hop signature failure, subset violation, or
  expiry fails the request as an authorization failure, independent of
  possession and of human authorization.
- **accepted_result:** on success the verifier may consume exactly: "this
  chain conveys the stated terminal scope for this operation from the root
  principal, at verification time." It does not authorize consuming holder
  possession, human authorization, execution evidence, physical completion,
  or relying-party policy acceptance.
- **dependency:** the originating organization's trust anchor (root only;
  self-certifying identifiers cover intermediate hops), inline conveyance of
  parent tokens, and a possession-proving transport for holder proof.
- **evidence:** partial. Synthetic B9 vectors at
  [`interop-vectors/b9-pedigree-binding/`](../interop-vectors/b9-pedigree-binding/)
  (IETF 126 Hackathon). Independently checkable by anyone: the shared B9
  `subject_digest` recomputes from the published canonical action with any
  RFC 8785 JCS implementation. Supplier-reported only: a supplier-run
  private harness reported successful signing and verification of a
  synthetic single-grant chain attestation (the published vectors do not
  include the HMAC key or signing-input definition and are not
  independently signature-verifiable), and a terminal action-scope negative
  in which `delete:records` is rejected against the single grant's allowed
  scope-set (`scope_creep`); this is not a grant-document or digest-binding
  splice test. These vectors do NOT exercise the core C-002 per-hop
  narrowing claim: the chain has one grant, so parent/child scope
  subsetting, multi-hop verification, key rotation, and expiry are all
  uncovered. Reproducibility boundary stated in the RUNKIT.
  `evidence_type: local_harness`.
- **gradient_position:** `{ "root": "general_infrastructure",
  "consequence_tier": "software", "sufficiency_bar": "none" }` (root anchor
  acquisition; a continuity mechanism to amortize the root pin across
  rotation is a PEDIGREE provisioning item, not yet specified).
- **spec_status:** specified (chain verification); planned (normative
  fail-closed revocation, pedigree-02).
- **impl_status:** partial.
- **evaluated_against:** draft-rampalli-pedigree-00 (the only revision
  posted; -01 and -02 are in the submission pipeline, and this row
  re-evaluates when they post); reece-00; draft-bu-02.

---

## Contributed rows

_PR your rows here. Placeholders below name the expected supplier and claim;
they assert nothing until filled by that supplier._

- **TODO EMILIA Protocol / C-005, C-007, C-008, C-011, C-012** - EP
  carriers (admissibility profiles, effect_attestation and ceremony_evidence
  AEG nodes, EP-WITNESS-v1 cosignatures, RFC-3161 timestamp), with tests and
  vectors, referencing receipts-06, quorum-02, evidence-record-01,
  evidence-chain-02. Source: EP-CID-R1R9-CROSSWALK.md.
- **TODO WinMagic / possession row** - Live Key condition-bound credential
  (possession under condition), reconciled Nguyen-Huu and Bu row. Source:
  WIMSE condition-bounded thread.
