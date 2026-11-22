# Design decisions and plan history

This file explains why the PEDIGREE -01 reference verifier and its test vectors are built the way they are. It records each revision of the build plan, what changed, and why. The normative source is [draft-rampalli-pedigree-01](https://datatracker.ietf.org/doc/draft-rampalli-pedigree/01/); section numbers below refer to it.

## Goals

1. Anyone can clone this repository, run one command, and get byte-level vectors for PEDIGREE -01 together with the outcome this suite expects for each published presentation. Each expected outcome holds for the published fixture inputs and this suite's profile. For example, `local-status-present` expects `status_unknown` because this suite has no status-list resolver. A conforming verifier with an authoritative status answer can reach a different outcome.
2. The lead case is the one a delegation chain alone cannot answer: every hop is valid and the invocation is valid, yet the receiving service denies the action under its own policy (Section 7.2).
3. Every assumption the verifier makes is printed next to its result, so a reader never mistakes a test assumption for a protocol guarantee.

## Standing decisions

| Decision | Reason |
|---|---|
| Clean-room implementation written from the public -01 text, a written build specification, and this suite's written reporting rules, fixtures and frozen tests | Readers can check every protocol behavior against the draft. Where the draft is silent, such as the reporting labels, this suite's own rules apply and are marked as such. No private code is involved. |
| Go standard library only, offline | Anyone can run it without fetching dependencies. |
| Ed25519 only | Section 4.1 makes Ed25519 mandatory to implement. |
| Test keys only, derived from published seeds | Vectors must be reproducible, and no real key may appear in a public repository. |
| Byte-level vectors | Appendix A of -01 lists test cases by name but includes no byte-level vectors. |
| Trusted inputs are separate from the request | Holder binding (Section 11.2), consent status (Section 10.4) and policy decisions come from outside the request. Keeping them apart, and reporting them with each result, makes clear what was assumed. |
| Policy decisions come from a fixture test double | Real Cedar evaluation is planned for a later stage. Until then, the vectors pin a small set of Cedar policies with their known decisions, and any policy or request outside that set stops the run instead of passing. |
| Arguments binding uses an illustrative profile | Section 6.2 leaves the construction to a profile. The profile used here is labeled illustrative, not a PEDIGREE requirement. |

## Plan history

The plan went through eight revisions, then one amendment after code review. An independent reviewer checked each one, and each version answers the findings on the one before it. "Serious" means the verifier could return the wrong outcome; "important" means a test or step could pass for the wrong reason. The reviewer checked each version against the -01 text before any code was written. Each review asked whether every expected outcome is the first check that fails under Section 5.3, and whether anything could make the verifier report "permit" when -01 requires a refusal.

| Version | Review of this version | Findings | What changed from the previous version | Why |
|---|---|---|---|---|
| v1 | Blocked | 3 serious, 6 important | First plan: verifier steps 1 to 9 and the invocation checks, generator, one-command runner, frozen expected outcomes taken from Appendix A. The lead case added: a valid chain where the service policy denies an export over 5,000 records, and permits one for 500. | Make the "service still decides" case the first thing a reader sees. |
| v2 | Blocked | 1 serious, 6 important | The verifier receives the request arguments and checks their signed binding (Section 6.3 step 6). The invocation key comes from the assumed holder-binding input, matched to the leaf key thumbprint (Section 6.1 forbids a key in the invocation header). Consent status comes from fixture answers, and missing answers refuse (Section 10.4). The ceiling digest uses the -01 wire form, "sha256:" plus lowercase hex (Section 4.2). Full RFC 8785 number handling. Exceptions to the Appendix A rebuild rule for the parent-swap and reissued-parent cases. | Review round 1 found that the verifier could reach "permit" without checking the arguments, without a source for the invocation key, and without consent status. |
| v3 | Blocked | 1 serious, 5 important | Any token that carries a "status" reference refuses with status_unknown, because this stage cannot resolve status lists. Trusted inputs moved out of the request object. Mandate policies limited to a pinned corpus with known decisions; anything else stops as unsupported instead of being reported as invalid Cedar. Case files compared with the expected table exactly. Each frozen test must fail on its own before the build starts. Documentation and license moved to a separate stage. | Review round 2 found that a token with a status reference could still pass, and that the fixture design could mislabel a valid Cedar policy as invalid. |
| v4 | Blocked | 0 serious, 3 important, 1 minor | Consent answers must match the trust anchor, the consent ID and the evaluation instant exactly; a new case gives an active answer for a different consent and expects status_unknown. The replay cache reports three states: first use, replay, or unknown (replay_unknown, Section 6.3 step 5). Every token in the base chain grants "read" and "export" on one fixed resource. Mandate shape checked once at parse; policy effects come from the pinned corpus. Holder-binding assumptions recorded per request, with freshness and the fields they cover. | Review round 3 found that an active consent answer for one consent could approve another, and that the lead case would have stopped at scope_not_granted before reaching the service policy. |
| v5 | Blocked | 0 serious, 1 important | Holder binding checked against the chain first, then a missing invocation is reported as invocation_invalid, then coverage of the invocation is checked. Exactly one holder-binding assumption is passed per verification call, so the two presentations of the replay case stay distinct. Every outgoing commit is scanned on its own before publication. | Review round 4 found no serious issues; it found an ordering conflict in the no-invocation case and an ambiguity in the replay case. |
| v6 | Blocked | 0 serious, 1 important | Holder-binding coverage is stated per request: the no-invocation case reports only the fields that were present, alongside invocation_invalid. | Review round 5 found no serious issues; the result label for the no-invocation case claimed coverage of a field that was absent. |
| v7 | Blocked | 0 serious, 1 important | Every expected result pins the list of trusted assumptions it relied on, and the runner compares that list as well as the outcome. | Review round 6 found that a wrong assumption label could still pass because the expected table did not record labels. |
| v8 | Approved | None | One fixed rule decides which assumptions each result lists: policy, then consent, then holder binding, and only those the verifier used before it returned. | Review round 7 found that the expected assumption list for the no-invocation case left out the consent and policy inputs used at earlier steps. |
| v8, amendment 1 | Approved | 2 important (code review) | After the code review: Ed25519 public keys of small order are refused at every signature check, and a failed narrowing check returns mandate_not_narrower even when a narrowing_proof is present (Section 8.4 rule 4, since this stage implements no proof format). Before first publication, the test-key seed phrase became "pedigree-01 test key " followed by the key index, and the frozen tests were renamed by row number. | The code review found that a small-order key could pass signature checks for any message, and that the narrowing outcome did not follow Section 8.4. The seed phrase was fixed before publication because changing it later would change every vector. |

## What this stage does not cover

Token Status List resolution, real Workload Proof Token verification, real Cedar evaluation, narrowing proofs, completion blocks, the mapping from an ID-JAG to the root of a PEDIGREE chain, OAuth authorization_details narrowing, and access-token lifetime coupling. These are planned for later stages, together with a runner that checks the two verifiers agree on every case. The second, independently written verifier is now in `reference/node` (see below).

## Changes after the second verifier

Building an independent Node.js verifier, and checking both verifiers against private cases prepared from the draft text and this suite's own rules, found places where the Go verifier and the earlier rules needed to change. The published vector results did not change.

| Change | Draft basis |
|---|---|
| Trusted inputs are listed in the order the verifier first used them, each once. On a chain with no mandate, the policy fixture is first read at step 11, and only if the step 11 grant check passes. It is then listed after consent and holder binding. This replaces the fixed order in v8 above. | Section 5.3 step 11; reporting rule of this suite |
| The holder-binding label names only the fields the assumption covers. A field that is present in the request but not covered is not named. This replaces the per-request wording in v6 above. | Sections 6.4 and 11.2; reporting rule of this suite |
| A holder-binding assumption that is not fresh is refused with `holder_binding_failed`. No holder-binding label is recorded for it, because the label states that the assumption is fresh. Labels recorded at earlier steps stay. A fresh assumption keeps the coverage-based label above. | Section 11.2; reporting rule of this suite |
| Step 5 runs each check over the whole chain in the order the draft lists them: mandate effects, then grant coverage, then mandate narrowing. | Section 5.3 step 5 |
| Unknown public members in a child token's `jwk` are ignored; private key members are refused. | RFC 7517 Section 4; Section 4.1 |
| For the objects this suite verifies, the integer range rule applies to token headers and payloads and, through Section 6.1, to invocation headers and payloads. It does not apply to the request arguments, which are bound through JCS. Section 4.4 also covers completion blocks, which this stage leaves out. | Sections 4.4, 6.1 and 6.2; RFC 8785 |
| An invocation counts as used once the single-use check passes, even if a later check refuses it. | Section 6.3 checks 5 and 6 |
| Within step 11, the grant check runs before the policy fixture is read. | Section 5.3 step 11 |

