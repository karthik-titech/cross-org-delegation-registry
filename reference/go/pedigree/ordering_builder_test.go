package pedigree

import (
	"slices"
	"testing"
)

// TestBuilderTrustedInputOrder checks when each trusted input first appears.
func TestBuilderTrustedInputOrder(t *testing.T) {
	t.Run("mandates present", func(t *testing.T) {
		checkOrderingResult(t, makeSample(t, "valid-3-hop"), "permit", []string{orPolicy, orConsent, orWPT})
	})

	for _, tc := range []struct {
		name, action, outcome string
		mutate                func(*sample)
		labels                []string
	}{
		{"ceiling reference differs", "read", "unsupported_fixture_policy", func(s *sample) {
			ceiling := []byte("{}")
			ref := ceilingDigest(ceiling)
			s.cfg.AcceptedCeilings[ref] = ceiling
			s.claims[2]["ceiling_ref"] = ref
			rfResign(s)
		}, []string{orConsent, orWPT, orPolicy}},
		{"permit", "read", "permit", nil, []string{orConsent, orWPT, orPolicy}},
		{"step 8 consent revoked", "read", "revoked", func(s *sample) {
			s.trust.Consent[0].Active = false
		}, []string{orConsent}},
		{"step 10 invocation missing", "read", "invocation_invalid", func(s *sample) {
			s.p.Invocation = ""
		}, []string{orConsent, orWPT}},
		{"step 11 action outside grants", "delete", "scope_not_granted", nil, []string{orConsent, orWPT}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := orMandateFree(t, tc.action, 500)
			if tc.mutate != nil {
				tc.mutate(&s)
			}
			checkOrderingResult(t, s, tc.outcome, tc.labels)
		})
	}
}

// TestBuilderAttenuationOrder checks the precedence of the step 5 checks.
func TestBuilderAttenuationOrder(t *testing.T) {
	unknownEffect := func(s *sample) {
		s.claims[2]["mandate"] = object{
			"format": "cedar", "policy_set": []string{"permit(principal, action, resource);"},
		}
	}
	for _, tc := range []struct {
		name, outcome string
		mutations     []func(*sample)
	}{
		{"unknown effect after grant failure", "unsupported_fixture_policy", []func(*sample){orWiden(1), unknownEffect}},
		{"grant failure only", "scope_widened", []func(*sample){orWiden(2)}},
		{"narrowing failure only", "mandate_not_narrower", []func(*sample){orDropMandate(2)}},
		{"both failures on one hop", "scope_widened", []func(*sample){orWiden(2), orDropMandate(2)}},
		{"narrowing failure before grant failure", "scope_widened", []func(*sample){orDropMandate(1), orWiden(2)}},
		{"grant failure before narrowing failure", "scope_widened", []func(*sample){orWiden(1), orDropMandate(2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := orStep5Sample(t, tc.mutations...)
			checkOrderingResult(t, s, tc.outcome, []string{orPolicy})
		})
	}

	t.Run("mandate-free hop re-adds a scope", func(t *testing.T) {
		s := orMandateFree(t, "read", 500)
		s.claims[1]["grants"].([]object)[0]["scopes"] = []string{"read"}
		rfResign(&s)
		checkOrderingResult(t, s, "scope_widened", []string{})
	})
}

func checkOrderingResult(t *testing.T, s sample, outcome string, labels []string) {
	t.Helper()
	got := rfVerify(s)
	if got.Outcome != outcome {
		t.Errorf("outcome = %q, want %q", got.Outcome, outcome)
	}
	if got.TrustedInputsUsed == nil || !slices.Equal(got.TrustedInputsUsed, labels) {
		t.Errorf("trusted inputs = %#v, want %#v", got.TrustedInputsUsed, labels)
	}
}
