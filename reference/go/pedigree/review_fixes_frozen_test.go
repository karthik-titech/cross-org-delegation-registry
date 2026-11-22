package pedigree

// Frozen tests RF1 to RF6. Source: review of the reference verifier against
// the draft (draft-rampalli-pedigree-01), RFC 7517 Section 4 and RFC 8785.
//
// The rows pin three points:
//
//   - RF1, RF2: the WPT trusted-input label names what the assumed WPT
//     covers, not what the presentation carries. The published result lines
//     do not change.
//   - RF3, RF4: a header "jwk" may carry members the verifier does not
//     understand (they are ignored), but never private key members.
//   - RF5, RF6: the integer range rule of Section 4.4 applies to protected
//     headers and payloads. It does not apply to the request arguments, which
//     are serialized per RFC 8785 for the arguments binding.
//
// Inputs are minted here with the published TEST ONLY seeds through the
// helpers of conformance_frozen_test.go.

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// rfResign signs every token of the sample again with its base chain key,
// gives each descendant a new par_hash, and signs the invocation again over
// the new leaf (the reconstruction rule of Appendix A).
func rfResign(s *sample) {
	for i := range s.p.Chain {
		if i > 0 {
			s.claims[i]["par_hash"] = tokenHash(s.p.Chain[i-1])
		}
		s.p.Chain[i] = signBytes(i+1, raw(s.heads[i]), raw(s.claims[i]))
	}
	s.inv["tok"] = tokenHash(s.p.Chain[len(s.p.Chain)-1])
	s.signInvocation()
}

// rfJWKSample returns the valid-3-hop sample with extra members added to the
// header "jwk" of T_1, signed again.
func rfJWKSample(t *testing.T, extra object) sample {
	t.Helper()
	s := makeSample(t, "valid-3-hop")
	key := s.heads[1]["jwk"].(object)
	for name, value := range extra {
		key[name] = value
	}
	rfResign(&s)
	return s
}

func rfVerify(s sample) Result { return Verify(s.p, s.trust, s.cfg, instant) }

// TestRF1 pins the WPT label to the coverage of the assumed WPT. The
// invocation is present, so a label derived from the presentation would name
// Pedigree-Invocation, which this WPT does not cover.
func TestRF1(t *testing.T) {
	const wantLabel = "wpt_assumed:fresh,covers=Pedigree"
	s := makeSample(t, "valid-3-hop")
	// Key 5 is not the holder key (key 4).
	s.p.Invocation = signBytes(5, raw(object{"typ": "pedigree-inv+jwt", "alg": "Ed25519"}), raw(s.inv))
	s.trust.WPT = WPTAssumption{PresentationIndex: 1, HolderKey: pub(4), Fresh: true, Covers: []string{"Pedigree"}}
	got := rfVerify(s)
	if got.Outcome != "holder_binding_failed" {
		t.Errorf("RF1 outcome: want holder_binding_failed, got %s", got.Outcome)
	}
	if n := len(got.TrustedInputsUsed); n == 0 || got.TrustedInputsUsed[n-1] != wantLabel {
		t.Errorf("RF1 labels: want last label %q, got %q", wantLabel, got.TrustedInputsUsed)
	}
}

// rfLine is one result line of the runner for a case that is not a fixture
// stop. The member order is the published line format.
type rfLine struct {
	ID                string   `json:"id"`
	Presentation      int      `json:"presentation"`
	Expected          string   `json:"expected"`
	Got               string   `json:"got"`
	TrustedInputsUsed []string `json:"trusted_inputs_used"`
	Status            string   `json:"status"`
}

// TestRF2 runs every public case through the runner and compares each
// result line, byte for byte, with the line that its expected.json row
// determines.
func TestRF2(t *testing.T) {
	const publicLines = 28
	pin := expectations(t)
	if len(pin) != publicLines {
		t.Fatalf("RF2 expected.json: want %d rows, got %d", publicLines, len(pin))
	}
	var out bytes.Buffer
	if err := RunVectors(vectorDir, &out); err != nil {
		t.Errorf("RF2 runner: %v", err)
	}
	type index struct {
		id string
		n  int
	}
	lines := map[index][]byte{}
	for _, line := range bytes.Split(bytes.TrimSpace(out.Bytes()), []byte{'\n'}) {
		var r rfLine
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("RF2 invalid result line %q", line)
		}
		key := index{r.ID, r.Presentation}
		if _, ok := lines[key]; ok {
			t.Fatalf("RF2 duplicate result line %v", key)
		}
		lines[key] = line
	}
	if len(lines) != publicLines {
		t.Fatalf("RF2 runner: want %d result lines, got %d", publicLines, len(lines))
	}
	for _, e := range pin {
		if e.TrustedInputsUsed == nil {
			t.Fatalf("RF2 %s[%d]: expected.json row has no label list", e.ID, e.Presentation)
		}
		want, err := json.Marshal(rfLine{e.ID, e.Presentation, e.Outcome, e.Outcome, e.TrustedInputsUsed, "PASS"})
		if err != nil {
			t.Fatal(err)
		}
		if got := lines[index{e.ID, e.Presentation}]; !bytes.Equal(got, want) {
			t.Errorf("RF2 %s[%d]:\nwant %s\ngot  %s", e.ID, e.Presentation, want, got)
		}
	}
}

// TestRF3 pins RFC 7517 Section 4: a JWK member that the verifier does not
// understand is ignored, whatever its value.
func TestRF3(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"string value", "v"},
		{"object value", object{"a": []int{1, 2}}},
	} {
		got := rfVerify(rfJWKSample(t, object{"ext": tc.value}))
		if got.Outcome != "permit" {
			t.Errorf("RF3 %s: want permit, got %s", tc.name, got.Outcome)
		}
	}
}

// TestRF4 pins Section 4.1: a header "jwk" with a private key member is
// refused, alone or next to an ignored member.
func TestRF4(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra object
	}{
		{"d", object{"d": "ZHVtbXk"}},
		{"p", object{"p": "ZHVtbXk"}},
		{"ext and d", object{"ext": "v", "d": "ZHVtbXk"}},
		{"ext and p", object{"ext": "v", "p": "ZHVtbXk"}},
	} {
		got := rfVerify(rfJWKSample(t, tc.extra))
		if got.Outcome != "malformed" {
			t.Errorf("RF4 %s: want malformed, got %s", tc.name, got.Outcome)
		}
	}
}

// TestRF5 pins the scope of the Section 4.4 integer range rule: request
// arguments are not a protected header or payload. The binding is the digest
// of the RFC 8785 text, written out here, so the check passes and the fixture
// table (which has no row for these arguments) stops the run.
func TestRF5(t *testing.T) {
	const argsJSON = `{"max_records":500,"big":1e21}`
	const argsJCS = `{"big":1e+21,"max_records":500}`
	// The runner decodes case files with UseNumber, so arguments reach the
	// verifier as json.Number values that keep their decimal spelling.
	var decoded map[string]any
	d := json.NewDecoder(strings.NewReader(argsJSON))
	d.UseNumber()
	if err := d.Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["big"].(json.Number); !ok {
		t.Fatalf("RF5 setup: want json.Number, got %T", decoded["big"])
	}
	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{"decoded numbers", decoded},
		{"native numbers", object{"max_records": 500, "big": 1e21}},
	} {
		s := makeSample(t, "valid-3-hop")
		s.p.Args = tc.args
		s.inv["args"] = object{"sha256": digest([]byte(argsJCS))}
		s.signInvocation()
		got := rfVerify(s)
		if got.Outcome != "unsupported_fixture_policy" {
			t.Errorf("RF5 %s: want unsupported_fixture_policy, got %s", tc.name, got.Outcome)
		}
	}
}

// TestRF6 pins that the integer range rule still applies to token payloads.
// The status member is used because its value is otherwise unconstrained at
// parse, so the range rule alone separates the refused value from the control.
func TestRF6(t *testing.T) {
	status := func(idx int) object {
		return object{"status_list": object{"idx": idx, "uri": verifier + "/status"}}
	}
	for _, tc := range []struct {
		name   string
		mutate func(s *sample)
		want   string
	}{
		{"root iat 2^53", func(s *sample) { s.claims[0]["iat"] = 1 << 53 }, "malformed"},
		{"leaf status idx 2^53", func(s *sample) { s.claims[2]["status"] = status(1 << 53) }, "malformed"},
		{"leaf status idx -2^53", func(s *sample) { s.claims[2]["status"] = status(-(1 << 53)) }, "malformed"},
		{"control: leaf status idx 2^53-1", func(s *sample) { s.claims[2]["status"] = status(1<<53 - 1) }, "status_unknown"},
	} {
		s := makeSample(t, "valid-3-hop")
		tc.mutate(&s)
		rfResign(&s)
		if tc.want == "malformed" && !slices.ContainsFunc(s.p.Chain, func(c string) bool {
			payload, ok := decodeBase64URL(strings.Split(c, ".")[1])
			return ok && bytes.Contains(payload, []byte("9007199254740992"))
		}) {
			t.Fatalf("RF6 %s setup: no payload carries 9007199254740992", tc.name)
		}
		got := rfVerify(s)
		if got.Outcome != tc.want {
			t.Errorf("RF6 %s: want %s, got %s", tc.name, tc.want, got.Outcome)
		}
	}
}
