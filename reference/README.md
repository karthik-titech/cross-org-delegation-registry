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

It prints the same JSON lines as the Go verifier and exits with status 0 when all presentations pass. Run `node --test reference/node/test/*.test.mjs` through a shell for its tests. It was tested on Node.js 25.9.0 with OpenSSL 3.6.2 and is written against Node.js 20 APIs; it has not been run on Node.js 20.

The Node verifier was written from the draft text, this directory's documents and the published vectors, without access to the Go source. Both verifiers were produced with the same family of AI coding models, so agreement between them does not by itself rule out a shared misreading of the draft. As a control, additional private cases were written from the draft text alone before the Node verifier was built; both verifiers now give the same result as those cases on every presentation. The two verifiers give identical result lines on all 28 published presentations.

### Arguments binding and large numbers

The illustrative arguments binding hashes the RFC 8785 (JCS) form of the request arguments. JCS serializes every number through its IEEE 754 binary64 value, so two spellings that round to the same value bind the same way: for example `9007199254740993` and `9007199254740992`, or `0.50000000000000001` and `0.5`. A profile that needs exact large integers or exact decimals should carry them as strings.

## Coverage

The suite exercises PEDIGREE -01 Section 5.3 steps 1 to 11 and the Section 6 invocation checks, including refusal of small-order Ed25519 keys. The policy evaluator is a fixture test double with pinned decisions for pinned Cedar policies.

The suite leaves Token Status List resolution, real Workload Proof Token verification, real Cedar evaluation, narrowing proofs, completion blocks, ID-JAG root mapping, and OAuth `authorization_details` narrowing out of scope.

All keys are **TEST ONLY**. Each Ed25519 seed is the SHA-256 hash of the published prefix `pedigree-01 test key ` (including its trailing space) followed by the decimal key index.

The normative source is [draft-rampalli-pedigree-01](https://datatracker.ietf.org/doc/draft-rampalli-pedigree/01/).

- [Why it is built this way](DESIGN-DECISIONS.md)
- [Vector format](VECTOR-FORMAT.md)

## License

[LICENSE-CODE](../LICENSE-CODE) (Apache-2.0) covers `reference/**` and `vectors/pedigree-01/**`. [LICENSE.md](../LICENSE.md) (CC-BY-4.0) covers the rest of the repository.
