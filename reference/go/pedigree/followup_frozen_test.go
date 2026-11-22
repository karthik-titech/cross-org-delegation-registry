package pedigree

// Frozen tests FU1 to FU6. Source: review of the reference verifier against
// the draft (draft-rampalli-pedigree-01, Sections 5.3, 7.1 and 7.2) and
// RFC 8785.
//
// The rows pin three points:
//
//   - FU1, FU2: at step 7 every configured ceiling must hash to the reference
//     that names it, whether or not a token uses it. A configuration that
//     fails the check stops the run as unsupported_fixture_policy.
//   - FU3, FU4, FU5: at step 11 the whole decision table is checked before
//     any lookup. A row whose arguments cannot be serialized, or two rows for
//     the same request with different decisions, stop the run as
//     unsupported_fixture_policy. A row repeated with the same decision is
//     allowed.
//   - FU6: the runner output for the published vectors does not change and
//     no line carries the member fixture_runner_stop.
//
// Inputs are minted here with the published TEST ONLY seeds through the
// helpers of conformance_frozen_test.go, review_fixes_frozen_test.go and
// ordering_frozen_test.go.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"testing"
)

const fuStop = "unsupported_fixture_policy"

// fuPermitLabels returns the label list that expected.json pins for
// valid-3-hop, after a check that the pinned outcome is permit.
func fuPermitLabels(t *testing.T) []string {
	t.Helper()
	for _, e := range expectations(t) {
		if e.ID == "valid-3-hop" && e.Presentation == 1 {
			if e.Outcome != "permit" || len(e.TrustedInputsUsed) == 0 {
				t.Fatalf("setup: expected.json pins %s %q for valid-3-hop", e.Outcome, e.TrustedInputsUsed)
			}
			return e.TrustedInputsUsed
		}
	}
	t.Fatal("setup: no expected.json row for valid-3-hop")
	return nil
}

// fuCheck compares one result with the wanted outcome and label list.
func fuCheck(t *testing.T, name string, got Result, outcome string, labels []string) {
	t.Helper()
	if got.Outcome != outcome {
		t.Errorf("%s outcome: want %s, got %s", name, outcome, got.Outcome)
	}
	if got.TrustedInputsUsed == nil || !slices.Equal(got.TrustedInputsUsed, labels) {
		t.Errorf("%s labels: want %q, got %q", name, labels, got.TrustedInputsUsed)
	}
}

// fuPolicyIDs returns the two policy identifiers that the valid-3-hop
// request reads in the decision table: the mandate and the ceiling.
func fuPolicyIDs(t *testing.T) []string {
	t.Helper()
	return []string{"mandate", loadFixture(t).CeilingRef}
}

// fuPermitRow returns the index of the single decision row that permits the
// valid-3-hop request (read, 500 records) for the given policy.
func fuPermitRow(t *testing.T, s sample, policyID string) int {
	t.Helper()
	want := string(raw(s.p.Args))
	found := -1
	for i, row := range s.trust.Policies.Decisions {
		if row.PolicyID != policyID || row.Action != s.inv["action"] || row.Resource != s.inv["resource"] || string(raw(row.Args)) != want {
			continue
		}
		if found >= 0 || row.Decision != "permit" {
			t.Fatalf("setup: want one permit row for %s, got a second row or decision %q", policyID, row.Decision)
		}
		found = i
	}
	if found < 0 {
		t.Fatalf("setup: no permit row for %s", policyID)
	}
	return found
}

// fuWithRow returns the valid-3-hop sample with one extra decision row,
// placed before or after the rows of the fixture file.
func fuWithRow(t *testing.T, row func(s sample) FixtureDecision, first bool) sample {
	t.Helper()
	s := makeSample(t, "valid-3-hop")
	extra := row(s)
	rows := slices.Clone(s.trust.Policies.Decisions)
	if first {
		rows = append([]FixtureDecision{extra}, rows...)
	} else {
		rows = append(rows, extra)
	}
	s.trust.Policies.Decisions = rows
	return s
}

func fuPlace(first bool) string {
	if first {
		return "first"
	}
	return "last"
}

// TestFU1 pins the ceiling configuration check of step 7. The second entry
// has a well-formed reference, no token names it, and its bytes do not hash
// to it. The run stops before the consent check of step 8, so the label list
// holds only the policies fixture consulted at step 5.
func TestFU1(t *testing.T) {
	wellFormed := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	other := []byte(`["permit(principal, action, resource);"]`)
	otherRef := fmt.Sprintf("sha256:%x", sha256.Sum256(other))
	for _, tc := range []struct {
		name, ref string
		doc       []byte
	}{
		{"bytes of another document", otherRef, []byte(`["forbid(principal, action, resource);"]`)},
		{"one byte appended", otherRef, append(slices.Clone(other), '\n')},
		{"empty bytes", otherRef, []byte{}},
	} {
		s := makeSample(t, "valid-3-hop")
		if !wellFormed.MatchString(tc.ref) || fmt.Sprintf("sha256:%x", sha256.Sum256(tc.doc)) == tc.ref {
			t.Fatalf("FU1 %s setup: reference is not a well-formed mismatch", tc.name)
		}
		if _, ok := s.cfg.AcceptedCeilings[tc.ref]; ok || len(s.cfg.AcceptedCeilings) != 1 {
			t.Fatalf("FU1 %s setup: unexpected ceiling configuration", tc.name)
		}
		for _, claims := range s.claims {
			if claims["ceiling_ref"] == tc.ref {
				t.Fatalf("FU1 %s setup: a token names the extra ceiling", tc.name)
			}
		}
		s.cfg.AcceptedCeilings[tc.ref] = tc.doc
		fuCheck(t, "FU1 "+tc.name, rfVerify(s), fuStop, []string{orPolicy})
	}
}

// TestFU2 is the control for FU1: the unmodified configuration permits with
// the labels of expected.json, and so does a configuration with a second
// entry that no token names and that hashes to its reference.
func TestFU2(t *testing.T) {
	labels := fuPermitLabels(t)
	fuCheck(t, "FU2 unmodified", rfVerify(makeSample(t, "valid-3-hop")), "permit", labels)

	s := makeSample(t, "valid-3-hop")
	other := []byte(`["permit(principal, action, resource);"]`)
	s.cfg.AcceptedCeilings[fmt.Sprintf("sha256:%x", sha256.Sum256(other))] = other
	fuCheck(t, "FU2 second valid ceiling", rfVerify(s), "permit", labels)
}

// TestFU3 pins that a decision row whose arguments cannot be serialized
// stops the run. The row has the policy, action and resource of the permit
// row. 1e400 is valid JSON number text outside the binary64 range, so
// RFC 8785 serialization refuses it. The outcome is never permit, whatever
// the decision or the position of the row.
func TestFU3(t *testing.T) {
	labels := fuPermitLabels(t)
	huge := json.Number("1e400")
	for _, policyID := range fuPolicyIDs(t) {
		for _, args := range []object{
			{"max_records": huge},
			{"max_records": 500, "limit": huge},
		} {
			if _, err := serializeArgsJCS(args); err == nil {
				t.Fatalf("FU3 setup: arguments %v serialize", args)
			}
			for _, decision := range []string{"permit", "deny"} {
				for _, first := range []bool{true, false} {
					s := fuWithRow(t, func(s sample) FixtureDecision {
						row := s.trust.Policies.Decisions[fuPermitRow(t, s, policyID)]
						row.Args = args
						row.Decision = decision
						return row
					}, first)
					name := fmt.Sprintf("FU3 %s %s row %s, args %s", policyID, decision, fuPlace(first), raw(args))
					fuCheck(t, name, rfVerify(s), fuStop, labels)
				}
			}
		}
	}
}

// TestFU4 pins that two rows for the same request with different decisions
// stop the run, in both orders. The extra row equals the permit row except
// for its decision.
func TestFU4(t *testing.T) {
	labels := fuPermitLabels(t)
	for _, policyID := range fuPolicyIDs(t) {
		for _, first := range []bool{true, false} {
			s := fuWithRow(t, func(s sample) FixtureDecision {
				row := s.trust.Policies.Decisions[fuPermitRow(t, s, policyID)]
				row.Decision = "deny"
				return row
			}, first)
			name := fmt.Sprintf("FU4 %s deny row %s", policyID, fuPlace(first))
			fuCheck(t, name, rfVerify(s), fuStop, labels)
		}
	}
}

// TestFU5 is the control for FU3 and FU4: a permit row repeated exactly is
// not a contradiction, so the request is still permitted.
func TestFU5(t *testing.T) {
	labels := fuPermitLabels(t)
	for _, policyID := range fuPolicyIDs(t) {
		for _, first := range []bool{true, false} {
			s := fuWithRow(t, func(s sample) FixtureDecision {
				return s.trust.Policies.Decisions[fuPermitRow(t, s, policyID)]
			}, first)
			name := fmt.Sprintf("FU5 %s permit row repeated %s", policyID, fuPlace(first))
			fuCheck(t, name, rfVerify(s), "permit", labels)
		}
	}
}

// fuOutputDigest is the SHA-256 of the complete runner output for the
// published vectors, line order included.
const fuOutputDigest = "4d9fb4e31acf9fa51112173144352a3e2053edbe86d88e219e500205bd4bec76"

// TestFU6 pins the complete runner output for the published vectors: the
// lines that expected.json determines, in the order of expected.json, with
// the digest above, and no line with the member fixture_runner_stop.
func TestFU6(t *testing.T) {
	var out bytes.Buffer
	if err := RunVectors(vectorDir, &out); err != nil {
		t.Errorf("FU6 runner: %v", err)
	}
	pin := expectations(t)
	var ids []string
	groups := map[string][]expectedEntry{}
	for _, e := range pin {
		if groups[e.ID] == nil {
			ids = append(ids, e.ID)
		}
		groups[e.ID] = append(groups[e.ID], e)
	}
	var want bytes.Buffer
	for _, id := range ids {
		entries := groups[id]
		slices.SortFunc(entries, func(a, b expectedEntry) int { return a.Presentation - b.Presentation })
		for _, e := range entries {
			line, err := json.Marshal(rfLine{e.ID, e.Presentation, e.Outcome, e.Outcome, e.TrustedInputsUsed, "PASS"})
			if err != nil {
				t.Fatal(err)
			}
			want.Write(line)
			want.WriteByte('\n')
		}
	}
	gotLines := bytes.Split(bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), []byte{'\n'})
	wantLines := bytes.Split(bytes.TrimSuffix(want.Bytes(), []byte{'\n'}), []byte{'\n'})
	if len(gotLines) != len(wantLines) {
		t.Errorf("FU6 runner: want %d result lines, got %d", len(wantLines), len(gotLines))
	}
	for i, line := range gotLines {
		if i < len(wantLines) && !bytes.Equal(line, wantLines[i]) {
			t.Errorf("FU6 line %d:\nwant %s\ngot  %s", i+1, wantLines[i], line)
		}
		if bytes.Contains(line, []byte("fixture_runner_stop")) {
			t.Errorf("FU6 line %d carries fixture_runner_stop: %s", i+1, line)
		}
	}
	if !bytes.Equal(out.Bytes(), want.Bytes()) {
		t.Errorf("FU6 runner output differs from the lines of expected.json")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(out.Bytes())); got != fuOutputDigest {
		t.Errorf("FU6 output digest: want %s, got %s", fuOutputDigest, got)
	}
}
