# PEDIGREE -01 reference verifier

In `local-service-denies-50000`, every delegation hop and the invocation are valid, yet the receiving service denies the action under its own policy.
In the paired case `local-service-permits-500`, the service permits the action.

## Quick start

From the repository root, run this command with Go 1.22 or later. The suite runs offline and uses only the Go standard library.

```sh
cd reference/go && go run ./cmd/pedigree-verify -dir ../../vectors/pedigree-01
```

The verifier prints one JSON line per presentation with `expected`, `got`, `trusted_inputs_used`, and a `status` of `PASS` or `FAIL`. Each result reports the trusted fixture inputs used. The command exits with status 0 when all presentations pass.

From `reference/go`, run `go test ./...` for the Go tests or `go run ./cmd/pedigree-vectors` to regenerate the vectors.

## Second verifier (Node.js)

A second, independent verifier is in `reference/node`. It uses only the Node.js standard library, so its Ed25519, JSON and base64 code differ from the Go verifier's. From the repository root:

```sh
node reference/node/pedigree-verify.mjs --dir vectors/pedigree-01
```

On the published vectors it prints the same JSON lines as the Go verifier. It exits with status 0 when all presentations pass. The Go runner adds a `fixture_runner_stop` member to a line whose outcome is `unsupported_fixture_policy`; the Node runner does not. No published presentation has that outcome. Run `node --test reference/node/test/*.test.mjs` through a shell for its tests. It was tested on Node.js 25.9.0 with OpenSSL 3.6.2 and is written against Node.js 20 APIs; it has not been run on Node.js 20.

The Node verifier was written from the draft text, a written build specification, this README as first published, the vector format, the published vectors and fixture file, and the frozen tests in `reference/node/test`, without access to the Go source. Both verifiers were produced with the same family of AI coding models, so agreement between them does not by itself rule out a shared misreading of the draft. As a control, private cases were prepared before the Node build from the draft text and, where the draft is silent, this suite's own rules (the reporting labels among them). Disagreements found with these cases were settled by recorded rulings, which changed both verifiers; one expected label list was revised by such a ruling after the build began. Both verifiers match the final expected outcomes and labels on all 36 private presentations. The two verifiers give identical result lines on all 28 published presentations.

### Arguments binding and large numbers

The illustrative arguments binding hashes the RFC 8785 (JCS) form of the request arguments. JCS serializes every number through its IEEE 754 binary64 value, so two spellings that round to the same value bind the same way: for example `9007199254740993` and `9007199254740992`, or `0.50000000000000001` and `0.5`. A profile that needs exact large integers or exact decimals should carry them as strings.

## Coverage

The suite exercises PEDIGREE -01 Section 5.3 steps 1 to 11 and the Section 6 invocation checks, including refusal of small-order Ed25519 keys. The policy evaluator is a fixture test double with pinned decisions for pinned Cedar policies.

The suite leaves Token Status List resolution, real Workload Proof Token verification, real Cedar evaluation, narrowing proofs, completion blocks, ID-JAG root mapping, and OAuth `authorization_details` narrowing out of scope.

All keys are **TEST ONLY**. Each published vector's Ed25519 seed is the SHA-256 hash of the published prefix `pedigree-01 test key ` (including its trailing space) followed by the decimal key index.

The normative source is [draft-rampalli-pedigree-01](https://datatracker.ietf.org/doc/draft-rampalli-pedigree/01/).

- [Why it is built this way](DESIGN-DECISIONS.md)
- [Vector format](VECTOR-FORMAT.md)

## License

[LICENSE-CODE](../LICENSE-CODE) (Apache-2.0) covers `reference/**` and `vectors/pedigree-01/**`. [LICENSE.md](../LICENSE.md) (CC-BY-4.0) covers the rest of the repository.
