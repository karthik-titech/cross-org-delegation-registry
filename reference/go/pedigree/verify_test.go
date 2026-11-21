package pedigree

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestVerifyJCS(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"surrogate pair", `{"a":"\ud83d\ude00"}`, "non_canonical"},
		{"lone high surrogate", `{"a":"\ud83d"}`, "malformed"},
		{"lone low surrogate", `{"a":"\ude00"}`, "malformed"},
		{"escaped member alias", `{"a":1,"\u0061":2}`, "malformed"},
		{"unsafe exponential integer", `{"n":9.007199254740992e15}`, "malformed"},
		{"unsafe negative integer", `{"n":-9007199254740992.0}`, "malformed"},
		{"nonfinite", `{"n":1e400}`, "malformed"},
		{"safe integer", `{"n":9007199254740991}`, ""},
		{"fractional numeric date", `{"n":1792310400.5}`, ""},
		{"trailing object", `{"a":1}{}`, "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := decodeObject([]byte(tc.raw)); got != tc.want {
				t.Fatalf("outcome %q, want %q", got, tc.want)
			}
		})
	}
	for _, v := range []any{math.Inf(1), math.NaN(), "\xff", json.Number("null")} {
		if _, err := serializeJCS(v); err == nil {
			t.Errorf("accepted invalid input %v", v)
		}
	}
}

func TestVerifyResourceURI(t *testing.T) {
	for _, s := range []string{"urn:example:a", "file:///path", "x://[2001:db8::1]:123/a?q=%7B", "x://[v1.name]/"} {
		if !absoluteURI(s) {
			t.Errorf("rejected %q", s)
		}
	}
	for _, s := range []string{"local", "x:a#fragment", "x:a b", "x:a%2", "x://[broken]/", "x://host:bad", "x:a[b]"} {
		if absoluteURI(s) {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestVerifyVerificationOrder(t *testing.T) {
	for _, tc := range []struct {
		name    string
		change  func(*sample)
		outcome string
		used    []string
	}{
		{"parse before signatures", func(s *sample) {
			s.cfg.AcceptedAlgs = nil
			s.p.Chain[2] = "broken"
		}, "malformed", nil},
		{"algorithm allowance", func(s *sample) {
			s.cfg.AcceptedAlgs = []string{"EdDSA"}
		}, "signature_invalid", nil},
		{"root issuer anchor", func(s *sample) {
			s.claims[0]["iss"] = "unconfigured-issuer"
			s.p.Chain[0] = signBytes(1, raw(s.heads[0]), raw(s.claims[0]))
		}, "signature_invalid", nil},
		{"linkage before shape", func(s *sample) {
			s.claims[2]["parent_chain"] = []string{"token-1", "token-0"}
			s.claims[2]["consent_chain"] = []string{"other"}
			s.p.Chain[2] = signBytes(3, raw(s.heads[2]), raw(s.claims[2]))
		}, "linkage_invalid", nil},
		{"consent shape before attenuation", func(s *sample) {
			s.claims[2]["consent_chain"] = []string{"other"}
			s.p.Chain[2] = signBytes(3, raw(s.heads[2]), raw(s.claims[2]))
			s.trust.Policies.Effects = nil
		}, "consent_altered", nil},
		{"missing effect before time", func(s *sample) {
			s.trust.Policies.Effects = nil
			s.cfg.AcceptedCeilings = nil
		}, fixtureStop, []string{policyLabel}},
		{"ceiling before status", func(s *sample) {
			s.cfg.AcceptedCeilings = nil
			s.trust.Consent = nil
		}, "ceiling_unknown", []string{policyLabel}},
		{"consent ties to anchor", func(s *sample) {
			s.trust.Consent[0].TrustAnchorKid = "other"
		}, "status_unknown", []string{policyLabel, consentLabel}},
		{"consent ties to instant", func(s *sample) {
			s.trust.Consent[0].ValidAt = instant.Add(time.Nanosecond)
		}, "status_unknown", []string{policyLabel, consentLabel}},
		{"coverage before invocation parse", func(s *sample) {
			s.p.Invocation = "broken"
			s.trust.WPT.Covers = []string{"Pedigree"}
		}, "holder_binding_failed", []string{policyLabel, consentLabel, wptLabel + "+Pedigree-Invocation"}},
		{"replay before argument binding", func(s *sample) {
			s.p.Args = object{"max_records": 501}
			s.cfg.ReplayCache.Check(verifier, "invocation", instant.Add(time.Minute))
		}, "invocation_replayed", []string{policyLabel, consentLabel, wptLabel + "+Pedigree-Invocation"}},
		{"a mandate evaluation error denies", func(s *sample) {
			for i := range s.trust.Policies.Decisions {
				if s.trust.Policies.Decisions[i].PolicyID == "mandate" {
					s.trust.Policies.Decisions[i].Decision = "error"
				}
			}
		}, "mandate_denied", []string{policyLabel, consentLabel, wptLabel + "+Pedigree-Invocation"}},
		{"unlisted request stops at policy", func(s *sample) {
			s.p.Args = object{"max_records": 501}
			s.inv["args"] = object{"sha256": digest(raw(s.p.Args))}
			s.signInvocation()
		}, fixtureStop, []string{policyLabel, consentLabel, wptLabel + "+Pedigree-Invocation"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, "valid-3-hop")
			tc.change(&s)
			got := Verify(s.p, s.trust, s.cfg, instant)
			if got.Outcome != tc.outcome || !slices.Equal(got.TrustedInputsUsed, tc.used) {
				t.Fatalf("got %+v, want %s %v", got, tc.outcome, tc.used)
			}
		})
	}
}

func TestVerifyRejectsSmallOrderEd25519Keys(t *testing.T) {
	for _, encodedY := range []string{
		"00" + strings.Repeat("00", 31),
		"01" + strings.Repeat("00", 31),
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ec" + strings.Repeat("ff", 30) + "7f",
		"ed" + strings.Repeat("ff", 30) + "7f",
		"ee" + strings.Repeat("ff", 30) + "7f",
	} {
		key, err := hex.DecodeString(encodedY)
		if err != nil || len(key) != ed25519.PublicKeySize {
			t.Fatalf("bad test key %s: %v", encodedY, err)
		}
		if !smallOrderEd25519([ed25519.PublicKeySize]byte(key)) {
			t.Errorf("accepted small-order key %x", key)
		}
		key[ed25519.PublicKeySize-1] |= 0x80
		if !smallOrderEd25519([ed25519.PublicKeySize]byte(key)) {
			t.Errorf("accepted small-order key %x", key)
		}
	}

	identity := make(ed25519.PublicKey, ed25519.PublicKeySize)
	identity[0] = 0x01
	signature := make([]byte, ed25519.SignatureSize)
	copy(signature, identity)
	replaceSignature := func(t *testing.T, compact string) string {
		t.Helper()
		input := compact[:strings.LastIndexByte(compact, '.')]
		if !ed25519.Verify(identity, []byte(input), signature) {
			t.Fatal("crypto/ed25519 rejected the neutral-element fixture")
		}
		return input + "." + b64(signature)
	}

	t.Run("root token", func(t *testing.T) {
		s := makeSample(t, "valid-3-hop")
		s.cfg.TrustAnchors["anchor"] = identity
		s.p.Chain[0] = replaceSignature(t, s.p.Chain[0])
		if got := Verify(s.p, s.trust, s.cfg, instant); got.Outcome != "signature_invalid" {
			t.Fatalf("outcome %q, want signature_invalid", got.Outcome)
		}
	})

	t.Run("invocation", func(t *testing.T) {
		s := makeSample(t, "valid-3-hop")
		s.trust.WPT.HolderKey = identity
		holder := jwk(4)
		holder["x"] = b64(identity)
		s.claims[2]["cnf"] = object{"jkt": digest(raw(holder))}
		s.p.Chain[2] = signBytes(3, raw(s.heads[2]), raw(s.claims[2]))
		s.inv["tok"] = tokenHash(s.p.Chain[2])
		s.signInvocation()
		s.p.Invocation = replaceSignature(t, s.p.Invocation)
		if got := Verify(s.p, s.trust, s.cfg, instant); got.Outcome != "invocation_invalid" {
			t.Fatalf("outcome %q, want invocation_invalid", got.Outcome)
		}
	})
}

func TestVerifyNonNarrowingMandateWithProof(t *testing.T) {
	s := makeSample(t, "valid-3-hop")
	child := s.claims[2]
	child["mandate"] = object{
		"format":     "cedar",
		"policy_set": append(slices.Clone(s.trust.Policies.Mandate), loadFixture(t).ExtraPermit),
	}
	child["narrowing_proof"] = object{"format": "example-proof", "hash": s.trust.Policies.CeilingRef}
	s.p.Chain[2] = signBytes(3, raw(s.heads[2]), raw(child))
	if got := Verify(s.p, s.trust, s.cfg, instant); got.Outcome != "mandate_not_narrower" {
		t.Fatalf("outcome %q, want mandate_not_narrower", got.Outcome)
	}
}

func TestVerifyWindow(t *testing.T) {
	start, end := float64(epoch)+0.25, float64(epoch)+0.5
	for _, tc := range []struct {
		nanos int64
		valid bool
	}{
		{249999999, false}, {250000000, true}, {499999999, true}, {500000000, false},
	} {
		if got := inWindow(time.Unix(epoch, tc.nanos), start, end); got != tc.valid {
			t.Errorf("window at %d ns: got %v, want %v", tc.nanos, got, tc.valid)
		}
	}
}

func TestVerifyMandateSubset(t *testing.T) {
	effects := map[string]string{"p": "permit", "q": "permit", "f": "forbid", "g": "forbid"}
	parent := []string{"p", "f"}
	for _, tc := range []struct {
		child []string
		ok    bool
	}{
		{nil, false}, {[]string{"p", "f", "g"}, true}, {[]string{"f"}, true},
		{[]string{"p"}, false}, {[]string{"p", "q", "f"}, false},
	} {
		if got := mandateNarrows(parent, tc.child, effects); got != tc.ok {
			t.Errorf("mandate %v: got %v, want %v", tc.child, got, tc.ok)
		}
	}
}

func TestVerifyWPTIndex(t *testing.T) {
	c := fixtureCase{ID: "example", Presentations: make([]casePresentation, 2)}
	for _, indexes := range [][]int{{1}, {1, 1}, {0, 2}, {1, 3}, {1, 2, 3}} {
		c.WPT = nil
		for _, i := range indexes {
			c.WPT = append(c.WPT, WPTAssumption{PresentationIndex: i})
		}
		if _, err := c.assumptions(); err == nil || !strings.Contains(err.Error(), "WPT") {
			t.Errorf("expected WPT error for indexes %v, got %v", indexes, err)
		}
	}
	c.WPT = []WPTAssumption{{PresentationIndex: 2}, {PresentationIndex: 1}}
	got, err := c.assumptions()
	if err != nil || got[0].PresentationIndex != 1 || got[1].PresentationIndex != 2 {
		t.Fatalf("expected WPTs in presentation order, got %v (%v)", got, err)
	}
}
