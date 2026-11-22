package pedigree

import (
	"slices"
	"strings"
	"testing"
)

// TestBuilderStaleWPT checks that a non-fresh holder-binding assumption is
// refused with holder_binding_failed and that no holder-binding label is
// recorded, for every coverage shape, with and without an invocation.
func TestBuilderStaleWPT(t *testing.T) {
	for _, tc := range []struct {
		name           string
		covers         []string
		omitInvocation bool
		otherHolderKey bool
	}{
		{"full coverage", []string{"Pedigree", "Pedigree-Invocation"}, false, false},
		{"full coverage, invocation absent", []string{"Pedigree", "Pedigree-Invocation"}, true, false},
		{"token only", []string{"Pedigree"}, false, false},
		{"token only, invocation absent", []string{"Pedigree"}, true, false},
		{"invocation only", []string{"Pedigree-Invocation"}, false, false},
		{"unknown coverage", []string{"Other"}, false, false},
		{"empty coverage", []string{}, false, false},
		{"nil coverage", nil, true, false},
		{"full coverage, other holder key", []string{"Pedigree", "Pedigree-Invocation"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := func(fresh bool) sample {
				s := makeSample(t, "valid-3-hop")
				s.trust.WPT.Fresh = fresh
				s.trust.WPT.Covers = tc.covers
				if tc.omitInvocation {
					s.p.Invocation = ""
				}
				if tc.otherHolderKey {
					s.trust.WPT.HolderKey = pub(5)
				}
				return s
			}
			fresh := rfVerify(build(true)).TrustedInputsUsed
			if len(fresh) == 0 || !strings.HasPrefix(fresh[len(fresh)-1], wptLabelPrefix) {
				t.Fatalf("fresh labels = %q, want a last holder-binding label", fresh)
			}
			got := rfVerify(build(false))
			if got.Outcome != "holder_binding_failed" {
				t.Errorf("outcome = %q, want holder_binding_failed", got.Outcome)
			}
			for _, label := range got.TrustedInputsUsed {
				if strings.HasPrefix(label, "wpt") {
					t.Errorf("labels = %q, want no holder-binding label", got.TrustedInputsUsed)
				}
			}
			// Labels recorded at earlier steps are the same as in the fresh run.
			if want := fresh[:len(fresh)-1]; !slices.Equal(got.TrustedInputsUsed, want) {
				t.Errorf("labels = %q, want %q", got.TrustedInputsUsed, want)
			}
		})
	}
}

// TestBuilderFreshWPTUnchanged checks that a fresh assumption keeps the
// coverage-based label and outcome.
func TestBuilderFreshWPTUnchanged(t *testing.T) {
	s := makeSample(t, "valid-3-hop")
	s.trust.WPT.Fresh = true
	s.trust.WPT.Covers = []string{"Pedigree", "Pedigree-Invocation"}
	got := rfVerify(s)
	want := []string{policyLabel, consentLabel, wptLabel + "+Pedigree-Invocation"}
	if got.Outcome != "permit" || !slices.Equal(got.TrustedInputsUsed, want) {
		t.Errorf("got %q %q, want permit %q", got.Outcome, got.TrustedInputsUsed, want)
	}
}

// TestBuilderStaleWPTKeepsInvocationUnused checks that a refusal for a stale
// assumption does not mark the invocation as used.
func TestBuilderStaleWPTKeepsInvocationUnused(t *testing.T) {
	s := makeSample(t, "valid-3-hop")
	s.trust.WPT.Fresh = false
	if got := rfVerify(s).Outcome; got != "holder_binding_failed" {
		t.Fatalf("stale outcome = %q, want holder_binding_failed", got)
	}
	s.trust.WPT.Fresh = true
	if got := rfVerify(s).Outcome; got != "permit" {
		t.Errorf("fresh outcome after stale refusal = %q, want permit", got)
	}
}
