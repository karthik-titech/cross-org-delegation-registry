package pedigree

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuilderAcceptedCeilingDigests(t *testing.T) {
	other := []byte(`["forbid(principal, action, resource);"]`)
	otherRef := ceilingDigest(other)
	for _, tc := range []struct {
		name, id, outcome string
		change            func(*sample)
	}{
		{"wrong ancestor ceiling", "valid-3-hop", fixtureStop, func(s *sample) {
			s.claims[0]["ceiling_ref"] = otherRef
			rfResign(s)
			s.cfg.AcceptedCeilings[otherRef] = []byte("wrong")
		}},
		{"wrong unused ceiling", "valid-3-hop", fixtureStop, func(s *sample) {
			s.cfg.AcceptedCeilings[otherRef] = []byte("wrong")
		}},
		{"wrong configured ceiling precedes unknown reference", "local-ceiling-unknown", fixtureStop, func(s *sample) {
			s.cfg.AcceptedCeilings[otherRef] = []byte("wrong")
		}},
		{"uppercase digest", "valid-3-hop", fixtureStop, func(s *sample) {
			ref := "sha256:" + strings.ToUpper(strings.TrimPrefix(otherRef, "sha256:"))
			s.cfg.AcceptedCeilings[ref] = other
		}},
		{"empty configuration", "valid-3-hop", "ceiling_unknown", func(s *sample) {
			clear(s.cfg.AcceptedCeilings)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, tc.id)
			tc.change(&s)
			checkOrderingResult(t, s, tc.outcome, []string{orPolicy})
		})
	}
}

func TestBuilderFixtureDecisionValidation(t *testing.T) {
	for _, tc := range []struct {
		name, outcome string
		change        func(*sample, int)
	}{
		{"deny with unencodable args", fixtureStop, func(s *sample, i int) {
			row := s.trust.Policies.Decisions[i]
			row.Args = object{"max_records": json.Number("1e400")}
			row.Decision = "deny"
			s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, row)
		}},
		{"deny before permit", fixtureStop, func(s *sample, i int) {
			row := s.trust.Policies.Decisions[i]
			row.Decision = "deny"
			s.trust.Policies.Decisions = append([]FixtureDecision{row}, s.trust.Policies.Decisions...)
		}},
		{"deny after permit", fixtureStop, func(s *sample, i int) {
			row := s.trust.Policies.Decisions[i]
			row.Decision = "deny"
			s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, row)
		}},
		{"repeated permit", "permit", func(s *sample, i int) {
			s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, s.trust.Policies.Decisions[i])
		}},
		{"error alone", fixtureStop, func(s *sample, i int) {
			s.trust.Policies.Decisions[i].Decision = "error"
		}},
		{"error beside deny", fixtureStop, func(s *sample, i int) {
			s.trust.Policies.Decisions[i].Decision = "deny"
			row := s.trust.Policies.Decisions[i]
			row.Decision = "error"
			s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, row)
		}},
		{"different number spellings", fixtureStop, func(s *sample, i int) {
			row := s.trust.Policies.Decisions[i]
			row.Args = object{"max_records": json.Number("5e2")}
			row.Decision = "deny"
			s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, row)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, "valid-3-hop")
			tc.change(&s, fuPermitRow(t, s, "mandate"))
			checkOrderingResult(t, s, tc.outcome, []string{orPolicy, orConsent, orWPT})
		})
	}
}

func TestBuilderUnrelatedFixtureDecisionRows(t *testing.T) {
	for _, unrelated := range []struct {
		name   string
		change func(*FixtureDecision)
	}{
		{"policy", func(row *FixtureDecision) { row.PolicyID = "other" }},
		{"action", func(row *FixtureDecision) { row.Action = "other" }},
		{"resource", func(row *FixtureDecision) { row.Resource += "/other" }},
	} {
		for _, tc := range []struct {
			name, outcome string
			args          object
		}{
			{"unencodable args", fixtureStop, object{"max_records": json.Number("1e400")}},
			{"nil args", fixtureStop, nil},
			{"empty args object", "permit", object{}},
		} {
			t.Run(unrelated.name+"/"+tc.name, func(t *testing.T) {
				s := makeSample(t, "valid-3-hop")
				row := s.trust.Policies.Decisions[fuPermitRow(t, s, "mandate")]
				unrelated.change(&row)
				row.Args = tc.args
				s.trust.Policies.Decisions = append(s.trust.Policies.Decisions, row)
				checkOrderingResult(t, s, tc.outcome, []string{orPolicy, orConsent, orWPT})
			})
		}
	}
}

func TestBuilderFixtureDecisionValidationAfterGrant(t *testing.T) {
	for _, tc := range []struct {
		action, outcome string
		labels          []string
	}{
		{"delete", "scope_not_granted", []string{orConsent, orWPT}},
		{"read", fixtureStop, []string{orConsent, orWPT, orPolicy}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			s := orMandateFree(t, tc.action, 500)
			s.trust.Policies.Decisions[0].Decision = "error"
			checkOrderingResult(t, s, tc.outcome, tc.labels)
		})
	}
}

func TestBuilderArgsJCSRejectsUintptr(t *testing.T) {
	if _, err := serializeArgsJCS(object{"value": uintptr(1)}); err == nil {
		t.Fatal("argument serialization accepted uintptr")
	}
}

func TestBuilderMintArgsBindingRoundsToBinary64(t *testing.T) {
	sum := sha256.Sum256([]byte(`{"max_records":9007199254740992}`))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	binding := mintArgsBinding(object{"max_records": json.Number("9007199254740993")})
	if got := binding["sha256"]; got != want {
		t.Errorf("sha256 = %v, want %q", got, want)
	}
}

func TestBuilderResultsOwnLabels(t *testing.T) {
	used := inputUse{orPolicy}
	first := used.result(fixtureStop)
	second := used.result(fixtureStop)
	first.TrustedInputsUsed[0] = "changed"
	if second.TrustedInputsUsed[0] != orPolicy || used[0] != orPolicy {
		t.Fatal("result shares its labels with another result or the working list")
	}
	b, err := json.Marshal(inputUse(nil).result("malformed").TrustedInputsUsed)
	if err != nil || string(b) != "[]" {
		t.Fatalf("empty labels encoded as %q, error %v", b, err)
	}
}

func TestBuilderRunnerReportsPinnedFixtureStop(t *testing.T) {
	const id = "local-unlisted-request"
	f, err := loadFixtureSpec()
	if err != nil {
		t.Fatal(err)
	}
	s := orMandateFree(t, "read", 501)
	c := newFixtureCase(f, id, "local")
	want := Result{Outcome: fixtureStop, TrustedInputsUsed: []string{orConsent, orWPT, orPolicy}}
	c.Presentations = []casePresentation{{s.p, want}}
	c.WPT = []WPTAssumption{s.trust.WPT}
	dir := t.TempDir()
	for name, contents := range map[string]any{
		id + ".json":    c,
		"manifest.json": object{},
		"expected.json": object{"cases": []pinnedResult{{id, c.Source, 1, want}}},
	} {
		if _, err := writeVector(filepath.Join(dir, name), contents); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := RunVectors(dir, &out); err != nil {
		t.Fatal(err)
	}
	var report object
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report["got"] != fixtureStop || report["status"] != "PASS" {
		t.Errorf("unexpected runner output: %s", out.Bytes())
	}
	if _, ok := report["fixture_runner_stop"]; ok {
		t.Errorf("runner output includes fixture_runner_stop: %s", out.Bytes())
	}
}
