package pedigree

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// TestBuilderWPTLabel checks that the label lists each known covered field once.
func TestBuilderWPTLabel(t *testing.T) {
	for _, tc := range []struct {
		name, outcome, label string
		covers               []string
		omitInvocation       bool
	}{
		{"unknown coverage", "holder_binding_failed", "wpt_assumed:fresh,covers=", []string{"Other"}, false},
		{"invocation only", "holder_binding_failed", "wpt_assumed:fresh,covers=Pedigree-Invocation", []string{"Pedigree-Invocation"}, false},
		{"duplicates", "permit", "wpt_assumed:fresh,covers=Pedigree+Pedigree-Invocation", []string{"Pedigree", "Pedigree", "Pedigree-Invocation", "Pedigree-Invocation"}, false},
		{"reversed", "permit", "wpt_assumed:fresh,covers=Pedigree+Pedigree-Invocation", []string{"Pedigree-Invocation", "Pedigree"}, false},
		{"invocation absent", "invocation_invalid", "wpt_assumed:fresh,covers=Pedigree+Pedigree-Invocation", []string{"Pedigree", "Pedigree-Invocation"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, "valid-3-hop")
			s.trust.WPT.Covers = tc.covers
			if tc.omitInvocation {
				s.p.Invocation = ""
			}
			got := rfVerify(s)
			if got.Outcome != tc.outcome {
				t.Errorf("outcome = %q, want %q", got.Outcome, tc.outcome)
			}
			labels := got.TrustedInputsUsed
			if len(labels) == 0 || labels[len(labels)-1] != tc.label {
				t.Errorf("labels = %q, want last label %q", labels, tc.label)
			}
		})
	}
}

// TestBuilderJWKMembers checks private members, registered types and header parsing.
func TestBuilderJWKMembers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		extra   object
		outcome string
	}{
		{"symmetric key member", object{"k": "ZHVtbXk"}, "malformed"},
		{"numeric kid", object{"kid": 1}, "malformed"},
		{"string key_ops", object{"key_ops": "verify"}, "malformed"},
		{"numeric key_ops entry", object{"key_ops": []any{"verify", 1}}, "malformed"},
		{"valid metadata and extension", object{"kid": "k1", "key_ops": []string{"verify"}, "ext": "v"}, "permit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := rfJWKSample(t, tc.extra)
			if got := rfVerify(s).Outcome; got != tc.outcome {
				t.Errorf("outcome = %q, want %q", got, tc.outcome)
			}
		})
	}
	t.Run("range rule covers extensions", func(t *testing.T) {
		s := rfJWKSample(t, object{"ext": object{"n": json.Number("9007199254740992")}})
		compact := s.p.Chain[1]
		headerSegment, _, _ := strings.Cut(compact, ".")
		headerBytes, ok := decodeBase64URL(headerSegment)
		if !ok {
			t.Fatal("invalid test header encoding")
		}
		header := builderDecodeNumber(t, string(headerBytes)).(object)
		if key := readPublicJWK(header["jwk"]); !pub(2).Equal(key) {
			t.Error("readPublicJWK did not return the sample key")
		}
		if _, outcome := decodeObject(headerBytes); outcome != "malformed" {
			t.Errorf("header parse outcome = %q, want malformed", outcome)
		}
		if _, _, outcome := decodeJWS(compact, "pedigree+jwt", true); outcome != "malformed" {
			t.Errorf("JWS parse outcome = %q, want malformed", outcome)
		}
		if got := rfVerify(s).Outcome; got != "malformed" {
			t.Errorf("outcome = %q, want malformed", got)
		}
	})
}

func builderDecodeNumber(t *testing.T, input string) any {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(input))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestBuilderArgsNumbers checks rounding for argument encodings and bindings.
func TestBuilderArgsNumbers(t *testing.T) {
	for _, tc := range []struct {
		spelling, want string
		native         []any
	}{
		{"9007199254740991", "9007199254740991", []any{int64(9007199254740991), uint64(9007199254740991)}},
		{"9007199254740992", "9007199254740992", []any{int64(9007199254740992), uint64(9007199254740992)}},
		{"9007199254740993", "9007199254740992", []any{int64(9007199254740993), uint64(9007199254740993)}},
		{"-9007199254740993", "-9007199254740992", []any{int64(-9007199254740993)}},
		{"1e21", "1e+21", []any{float64(1e21)}},
		{"0.50000000000000001", "0.5", []any{float32(0.5)}},
	} {
		t.Run(tc.spelling, func(t *testing.T) {
			decoded := builderDecodeNumber(t, tc.spelling).(json.Number)
			for _, input := range append([]any{decoded}, tc.native...) {
				if got, err := serializeArgsJCS(input); err != nil || string(got) != tc.want {
					t.Errorf("serializeArgsJCS(%T %v) = %q, %v, want %q", input, input, got, err, tc.want)
				}
			}
		})
	}
	decoded := builderDecodeNumber(t, `{"a":{"b":[9007199254740993]}}`)
	for _, input := range []any{
		decoded,
		object{"a": object{"b": []int64{9007199254740993}}},
		object{"a": object{"b": [1]uint64{9007199254740993}}},
	} {
		const want = `{"a":{"b":[9007199254740992]}}`
		if got, err := serializeArgsJCS(input); err != nil || string(got) != want {
			t.Errorf("nested encoding of %#v = %q, %v, want %q", input, got, err, want)
		}
	}
	for _, input := range []any{
		builderDecodeNumber(t, "1e400"), json.Number("01"), json.Number("0x1p0"), math.NaN(), math.Inf(1), math.Inf(-1),
	} {
		if got, err := serializeArgsJCS(input); err == nil {
			t.Errorf("serializeArgsJCS(%T %v) accepted as %q", input, input, got)
		}
	}
	for _, input := range []any{builderDecodeNumber(t, "9007199254740992"), int64(9007199254740992), uint64(9007199254740992)} {
		if got, err := serializeJCS(input); err == nil {
			t.Errorf("serializeJCS(%T %v) accepted as %q", input, input, got)
		}
	}

	for _, tc := range []struct {
		name    string
		args    object
		outcome string
	}{
		{"decoded", builderDecodeNumber(t, `{"max_records":500,"big":9007199254740993}`).(object), "unsupported_fixture_policy"},
		{"signed", object{"max_records": 500, "big": int64(9007199254740993)}, "unsupported_fixture_policy"},
		{"unsigned", object{"max_records": 500, "big": uint64(9007199254740993)}, "unsupported_fixture_policy"},
		{"overflow", builderDecodeNumber(t, `{"max_records":500,"big":1e400}`).(object), "invocation_invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, "valid-3-hop")
			s.p.Args = tc.args
			s.inv["args"] = object{"sha256": digest([]byte(`{"big":9007199254740992,"max_records":500}`))}
			s.signInvocation()
			if got := rfVerify(s).Outcome; got != tc.outcome {
				t.Errorf("outcome = %q, want %q", got, tc.outcome)
			}
		})
	}
}

// TestBuilderArgsDecision checks that decision rows and requests use the same binding bytes.
func TestBuilderArgsDecision(t *testing.T) {
	const large = `{"max_records":500,"big":9007199254740993}`
	const rounded = `{"max_records":500,"big":9007199254740992}`
	decoded := builderDecodeNumber(t, large).(object)
	for _, tc := range []struct {
		name, request, mandate, outcome string
		rowArgs                         object
	}{
		{"permit", large, "permit", "permit", decoded},
		{"mandate deny", large, "deny", "mandate_denied", decoded},
		{"equivalent spellings", rounded, "permit", "permit", decoded},
		{"native row", large, "permit", "permit", object{"max_records": 500, "big": int64(9007199254740993)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := makeSample(t, "valid-3-hop")
			s.p.Args = builderDecodeNumber(t, tc.request).(object)
			s.inv["args"] = object{"sha256": digest([]byte(`{"big":9007199254740992,"max_records":500}`))}
			s.signInvocation()

			p := &s.trust.Policies
			p.Decisions = append(p.Decisions,
				FixtureDecision{PolicyID: "mandate", Action: str(s.inv, "action"), Resource: str(s.inv, "resource"), Args: tc.rowArgs, Decision: tc.mandate},
				FixtureDecision{PolicyID: str(s.claims[2], "ceiling_ref"), Action: str(s.inv, "action"), Resource: str(s.inv, "resource"), Args: tc.rowArgs, Decision: "permit"},
			)
			if got := rfVerify(s).Outcome; got != tc.outcome {
				t.Errorf("outcome = %q, want %q", got, tc.outcome)
			}
		})
	}
}

// TestBuilderInvocationRange isolates the integer limit in the invocation parser.
func TestBuilderInvocationRange(t *testing.T) {
	s := makeSample(t, "valid-3-hop")
	binding := object{"sha256": digest([]byte(`{"max_records":500}`)), "n": json.Number("9007199254740991")}
	s.inv["args"] = binding
	s.signInvocation()
	if _, _, ok := parseInvocation(s.p.Invocation); !ok {
		t.Error("parseInvocation refused 9007199254740991")
	}

	binding["n"] = json.Number("9007199254740992")
	s.signInvocation()
	if _, _, ok := parseInvocation(s.p.Invocation); ok {
		t.Error("parseInvocation accepted 9007199254740992")
	}
	if got := rfVerify(s).Outcome; got != "invocation_invalid" {
		t.Errorf("outcome = %q, want invocation_invalid", got)
	}
}
