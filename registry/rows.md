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

### AGENT ACTION CAPSULE / C-005 (action record)

- **c_id:** C-005 (what action was requested, attempted, completed, blocked, or failed).
- **r_mapping:** R8, R9, R2 (proposed; the C-ID-to-R crosswalk is not yet reconciled on the WIMSE list).
- **mechanism:** Agent Action Capsule -- a signed, canonical record of one agent
  action carrying a disposition from a fixed vocabulary (executed, blocked,
  denied, timeout, errored, deferred, expired, escalated) bound to a content
  digest of the action.
- **supplier:** Action State Group, Inc.
- **claim:** the capsule records what a single agent action was and how it was
  disposed -- requested, attempted, completed, blocked, or failed -- as a
  tamper-evident statement a party with no pre-arranged relationship to the
  producer can verify against a transparency service each party joined
  independently (R2), not a bilateral arrangement specific to the interaction.
  Does NOT prove authority or delegated scope (C-002), holder possession (R4),
  human authorization, physical completion of any downstream effect, independent
  observation, or relying-party policy acceptance; effect binding records what
  was dispatched or confirmed, not that the world changed.
- **carrier:** the capsule object -- a canonical (JCS, RFC 8785) structure with a
  computed capsule_id over model/compute attestation, disposition, optional
  effect record, and optional prior-capsule chain; carryable, e.g., as the
  payload of a SCITT Signed Statement.
- **verifier_and_rule:** any relying party, offline -- recompute capsule_id over
  the canonical bytes, check the disposition against its class invariants and
  the frozen-vector expectations, and where anchored check SCITT inclusion
  (RFC 9162_SHA256) against the transparency log. Independent Python and Go
  verifiers produce identical verdicts over the frozen suite.
- **binding_and_freshness:** bound to the action's content digest and, when
  present, the model/compute attestation and prior-capsule chain; freshness via
  the anchored inclusion time. Replay against a different action is detectable --
  the capsule_id is over the action bytes. The record itself has no revocation
  (a record is a historical fact); key validity is establishable as of the
  anchored time.
- **failure_behavior:** a capsule whose recomputed capsule_id, disposition
  invariants, or (when required) attestation or effect fields do not hold fails
  verification closed -- the record is rejected, not downgraded. Absence of a
  capsule asserts nothing.
- **accepted_result:** on success the verifier may consume exactly: "this action
  was recorded with this disposition, tamper-evidently, verifiable by a party
  trusting neither the producer nor a prior arrangement, as of the anchored
  time." It does not authorize consuming authority, delegated scope, human
  authorization, execution truth, physical completion, independent observation,
  or relying-party policy acceptance.
- **dependency:** a canonicalization (RFC 8785 JCS) and an explicit
  hash-algorithm identifier; for the third-party-verifiable path, a SCITT
  transparency service the relying party accepts (e.g.
  anchor.agentactioncapsule.org) -- no bilateral arrangement with the producer
  required.
- **evidence:** 32 frozen Class-1 conformance vectors with `test-vectors/SHA256SUMS`
  (input + expected per vector; 64 sums), checked by two independent verifier
  implementations by the supplier -- Python (`python/agent_action_capsule/verify.py`)
  and Go (`go/verify/verify.go`) -- producing identical verdicts; a live anchor at
  anchor.agentactioncapsule.org issuing RFC 9162_SHA256 receipts; and an
  independent third-party reproduction of the frozen suite reported to the
  authors (32/32), attribution and link pending the reporter's OK.
  `evidence_type: cross_language_consistency`.
- **gradient_position:** `{ "root": "general_infrastructure", "consequence_tier": "software", "sufficiency_bar": "none" }` (third-party verification rests on a transparency log each party joins independently; no bespoke bilateral arrangement).
- **spec_status:** specified.
- **impl_status:** implemented.
- **evaluated_against:** draft-mih-scitt-agent-action-capsule-02; reece-00; draft-bu-02.

### BILATERAL ATTESTATION / C-007 (cross-org record)

- **c_id:** C-007 (what evidence, attestation, or record supports an action -- here a cross-organizational, both-signed one).
- **r_mapping:** R8 (proposed; the C-ID-to-R crosswalk is not yet reconciled on the WIMSE list). Deliberately NOT R2: this mechanism is a per-interaction bilateral arrangement between the two transacting parties, which R2 excludes; its third-party verifiability is via the anchor, not an R2 claim.
- **mechanism:** Bilateral attestation -- the requesting organization and the
  performing organization each sign an attestation over the same action digest
  (a request attestation, an action attestation recording the deterministic
  constraint results and disposition, and a mutual acknowledgment), so each
  holds the other's signed record; anchored so a third party can verify.
- **supplier:** Action State Group, Inc.
- **claim:** the exchange produces a record of a cross-organizational action
  that BOTH parties are bound to and can prove -- the request, the constraint
  results and disposition at the performing boundary, and each party's
  acknowledgment -- verifiable by an outside party who trusts neither
  organization. Refusal is recorded with the same fidelity as performance.
  Does NOT prove authority or delegated scope (C-002), holder possession (R4),
  human authorization, physical completion, or relying-party acceptance.
- **carrier:** four signed objects (request attestation, action attestation, two
  acknowledgments) bound by a shared action digest and signature-digest
  chaining; each carryable as a SCITT Signed Statement. Wire encodings are TBD
  (the -01 revision fixes the binding obligations, not the wire format).
- **verifier_and_rule:** a relying party trusting neither organization, offline --
  check both parties' signatures over the shared action digest, the chain
  linkage (the action attestation references the request), that the two
  operators are distinct, and, when anchored, SCITT inclusion. `verify_pair`
  implements the pairwise check.
- **binding_and_freshness:** each half bound to the shared action digest and the
  counterparty's signature digest, so neither can be lifted onto a different
  exchange; freshness via the request validity window and the anchored inclusion
  time.
- **failure_behavior:** a missing or non-matching signature, a digest mismatch, a
  broken chain, or a same-operator pair fails verification closed. A one-sided
  record, or one carrying an asymmetry disposition (delivery_unconfirmed,
  counterparty_timeout, countersign_refused), is marked reduced-assurance and
  never silently treated as fully bilateral.
- **accepted_result:** on success the verifier may consume exactly: "these two
  organizations are each bound to this action record over the same digest,
  tamper-evidently." It does not authorize consuming authority, delegated scope,
  human authorization, execution truth, physical completion, or relying-party
  acceptance.
- **dependency:** a verifiable organizational identity for each party (a root the
  relying party accepts); a canonicalization; and, for third-party
  verification, a SCITT transparency service.
- **evidence:** a reference implementation in `capsule_emit` -- the handshake
  state machine (`capsule_emit/bilateral.py`) and pairwise verifier
  (`verify_pair`) -- with unit tests. No independent cross-implementation interop
  yet. `evidence_type: local_harness`.
- **gradient_position:** `{ "root": "general_infrastructure", "consequence_tier": "software", "sufficiency_bar": "none" }`.
- **spec_status:** specified (draft-mih-agent-bilateral-attestation-00 posted); planned (the -01 revision adds constraint-set pinning MUST, input-commitment SHOULD, and completeness MUST -- this row is re-filed at -01).
- **impl_status:** partial.
- **evaluated_against:** draft-mih-agent-bilateral-attestation-00; reece-00; draft-bu-02.
