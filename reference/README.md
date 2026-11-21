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

## Coverage

The suite exercises PEDIGREE -01 Section 5.3 steps 1 to 11 and the Section 6 invocation checks, including refusal of small-order Ed25519 keys. The policy evaluator is a fixture test double with pinned decisions for pinned Cedar policies.

The suite leaves Token Status List resolution, real Workload Proof Token verification, real Cedar evaluation, narrowing proofs, completion blocks, ID-JAG root mapping, and OAuth `authorization_details` narrowing out of scope.

All keys are **TEST ONLY**. Each Ed25519 seed is the SHA-256 hash of the published prefix `pedigree-01 test key ` (including its trailing space) followed by the decimal key index.

The normative source is [draft-rampalli-pedigree-01](https://datatracker.ietf.org/doc/draft-rampalli-pedigree/01/).

- [Why it is built this way](DESIGN-DECISIONS.md)
- [Vector format](VECTOR-FORMAT.md)

## License

[LICENSE-CODE](../LICENSE-CODE) (Apache-2.0) covers `reference/**` and `vectors/pedigree-01/**`. [LICENSE.md](../LICENSE.md) (CC-BY-4.0) covers the rest of the repository.
