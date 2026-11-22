package pedigree

// Frozen tests OR1 to OR5. Source: draft-rampalli-pedigree-01, Section 5.3
// step 5, and the trusted-input label rule of the vector suite.
//
// The rows pin two points:
//
//   - OR1, OR2, OR3: the label list names every fixture the verifier
//     consulted, in the order of first consultation, each at most once. The
//     policies fixture is first consulted at step 5 when a hop carries a
//     mandate, otherwise at the first fixture lookup of step 11. A run that
//     ends before any lookup in the policies fixture does not list it.
//   - OR4, OR5: step 5 runs each check over the whole chain before the next
//     check starts: known mandate effects, then grant coverage, then mandate
//     narrowing. A grant failure on a later hop is reported before a
//     narrowing failure on an earlier hop.
//
// Inputs are minted here with the published TEST ONLY seeds through the
// helpers of conformance_frozen_test.go and review_fixes_frozen_test.go.

import (
	"slices"
	"testing"
)

const (
	orPolicy  = "policy_fixture"
	orConsent = "consent_fixture"
	orWPT     = "wpt_assumed:fresh,covers=Pedigree+Pedigree-Invocation"
)

// orMandateFree returns the valid-3-hop sample with the mandate removed from
// every token and the given request, signed again.
func orMandateFree(t *testing.T, action string, maxRecords int) sample {
	t.Helper()
	s := makeSample(t, "valid-3-hop")
	for _, claims := range s.claims {
		delete(claims, "mandate")
	}
	s.p.Args = object{"max_records": maxRecords}
	s.inv["action"] = action
	s.inv["args"] = object{"sha256": digest(raw(s.p.Args))}
	rfResign(&s)
	return s
}

// orCeilingDecision reads the decision table of the fixture file for the
// ceiling and the given request. It fails the test when no row matches.
func orCeilingDecision(t *testing.T, action string, maxRecords int) string {
	t.Helper()
	f := loadFixture(t)
	want := string(raw(object{"max_records": maxRecords}))
	decision := ""
	for _, row := range f.Decisions {
		if row.PolicyID != f.CeilingRef || row.Action != action || row.Resource != f.Resource || string(raw(row.Args)) != want {
			continue
		}
		if decision != "" {
			t.Fatalf("setup: more than one ceiling decision for %s %d", action, maxRecords)
		}
		decision = row.Decision
	}
	switch decision {
	case "permit":
		return "permit"
	case "deny":
		return "ceiling_denied"
	}
	t.Fatalf("setup: no ceiling decision for %s %d", action, maxRecords)
	return ""
}

// orStep5Sample returns the valid-3-hop sample with a mandate on the root
// token, changed by mutate and signed again. The scope and mandate helpers
// below are the single changes that the rows combine.
func orStep5Sample(t *testing.T, mutate ...func(s *sample)) sample {
	t.Helper()
	s := makeSample(t, "valid-3-hop")
	s.claims[0]["mandate"] = object{"format": "cedar", "policy_set": loadFixture(t).Mandate}
	for _, m := range mutate {
		m(&s)
	}
	rfResign(&s)
	return s
}

// orWiden adds a scope to hop i that its parent does not grant.
func orWiden(i int) func(s *sample) {
	return func(s *sample) {
		s.claims[i]["grants"].([]object)[0]["scopes"] = []string{"read", "export", "delete"}
	}
}

// orDropMandate removes the mandate of hop i. Its parent carries one.
func orDropMandate(i int) func(s *sample) {
	return func(s *sample) { delete(s.claims[i], "mandate") }
}

// TestOR1 pins the label order on a chain without mandates: the policies
// fixture is first consulted at step 11, after the consent fixture (step 8)
// and the assumed WPT (step 10), so its label is last.
func TestOR1(t *testing.T) {
	want := []string{orConsent, orWPT, orPolicy}
	for _, tc := range []struct {
		action     string
		maxRecords int
	}{
		{"read", 500},
		{"export", 50000},
	} {
		outcome := orCeilingDecision(t, tc.action, tc.maxRecords)
		got := rfVerify(orMandateFree(t, tc.action, tc.maxRecords))
		if got.Outcome != outcome {
			t.Errorf("OR1 %s %d outcome: want %s, got %s", tc.action, tc.maxRecords, outcome, got.Outcome)
		}
		if !slices.Equal(got.TrustedInputsUsed, want) {
			t.Errorf("OR1 %s %d labels: want %q, got %q", tc.action, tc.maxRecords, want, got.TrustedInputsUsed)
		}
	}
}

// TestOR2 pins the unmodified valid-3-hop result: the chain carries mandates,
// so the policies fixture is consulted at step 5 and its label is first, as
// the published expected.json row lists it.
func TestOR2(t *testing.T) {
	var want []string
	for _, e := range expectations(t) {
		if e.ID == "valid-3-hop" && e.Presentation == 1 {
			want = e.TrustedInputsUsed
		}
	}
	if len(want) != 3 || want[0] != orPolicy {
		t.Fatalf("OR2 setup: expected.json labels for valid-3-hop are %q", want)
	}
	got := rfVerify(makeSample(t, "valid-3-hop"))
	if got.Outcome != "permit" {
		t.Errorf("OR2 outcome: want permit, got %s", got.Outcome)
	}
	if !slices.Equal(got.TrustedInputsUsed, want) {
		t.Errorf("OR2 labels: want %q, got %q", want, got.TrustedInputsUsed)
	}
}

// TestOR3 pins that a chain without mandates that is refused at step 11
// because the leaf does not grant the action never consults the policies
// fixture, so its label is absent.
func TestOR3(t *testing.T) {
	want := []string{orConsent, orWPT}
	got := rfVerify(orMandateFree(t, "delete", 500))
	if got.Outcome != "scope_not_granted" {
		t.Errorf("OR3 outcome: want scope_not_granted, got %s", got.Outcome)
	}
	if !slices.Equal(got.TrustedInputsUsed, want) {
		t.Errorf("OR3 labels: want %q, got %q", want, got.TrustedInputsUsed)
	}
}

// orStep5Controls checks that each single change of a row is refused on its
// own with its own outcome, so that the row combines two live failures.
func orStep5Controls(t *testing.T, row string, widen, drop int) {
	t.Helper()
	if got := rfVerify(orStep5Sample(t, orWiden(widen))); got.Outcome != "scope_widened" {
		t.Fatalf("%s setup: widened grants on hop %d alone: want scope_widened, got %s", row, widen, got.Outcome)
	}
	if got := rfVerify(orStep5Sample(t, orDropMandate(drop))); got.Outcome != "mandate_not_narrower" {
		t.Fatalf("%s setup: dropped mandate on hop %d alone: want mandate_not_narrower, got %s", row, drop, got.Outcome)
	}
}

// TestOR4 pins the step 5 check order when the narrowing failure is on an
// earlier hop than the grant failure: grant coverage runs over the whole
// chain first, so the result is scope_widened.
func TestOR4(t *testing.T) {
	orStep5Controls(t, "OR4", 2, 1)
	want := []string{orPolicy}
	got := rfVerify(orStep5Sample(t, orDropMandate(1), orWiden(2)))
	if got.Outcome != "scope_widened" {
		t.Errorf("OR4 outcome: want scope_widened, got %s", got.Outcome)
	}
	if !slices.Equal(got.TrustedInputsUsed, want) {
		t.Errorf("OR4 labels: want %q, got %q", want, got.TrustedInputsUsed)
	}
}

// TestOR5 pins the same order when the grant failure is on the earlier hop:
// the result is scope_widened under both a per-hop and a per-check order, so
// this row guards the case that already holds.
func TestOR5(t *testing.T) {
	orStep5Controls(t, "OR5", 1, 2)
	got := rfVerify(orStep5Sample(t, orWiden(1), orDropMandate(2)))
	if got.Outcome != "scope_widened" {
		t.Errorf("OR5 outcome: want scope_widened, got %s", got.Outcome)
	}
}
