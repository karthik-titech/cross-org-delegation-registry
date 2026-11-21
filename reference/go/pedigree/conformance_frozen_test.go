package pedigree

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type object = map[string]any

const vectorDir = "../../../vectors/pedigree-01"
const epoch = 1792310400
const verifier = "https://records.example.net"

var instant = time.Unix(epoch+15, 0).UTC()

// These helpers mint the restricted ASCII-key test objects independently.
func raw(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func b64(v []byte) string    { return base64.RawURLEncoding.EncodeToString(v) }
func digest(v []byte) string { d := sha256.Sum256(v); return b64(d[:]) }
func testKey(i int) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("pedigree-01 test key " + strconv.Itoa(i)))
	return ed25519.NewKeyFromSeed(seed[:])
}
func pub(i int) ed25519.PublicKey { return testKey(i).Public().(ed25519.PublicKey) }
func jwk(i int) object            { return object{"crv": "Ed25519", "kty": "OKP", "x": b64(pub(i))} }
func signBytes(i int, h, p []byte) string {
	input := b64(h) + "." + b64(p)
	return input + "." + b64(ed25519.Sign(testKey(i), []byte(input)))
}
func tokenHash(s string) string {
	return digest([]byte(s[:strings.LastIndexByte(s, '.')]))
}
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	if e := json.Unmarshal(readFile(t, path), v); e != nil {
		t.Fatalf("%s: %v", path, e)
	}
}

type fixture struct {
	FixturePolicies
	Resource    string
	ExtraPermit string `json:"extra_permit"`
}

func loadFixture(t *testing.T) fixture {
	var f fixture
	readJSON(t, "testdata/fixtures.json", &f)
	if fmt.Sprintf("sha256:%x", sha256.Sum256(raw(f.Ceiling))) != f.CeilingRef {
		t.Fatal("invalid ceiling fixture digest")
	}
	return f
}

type memoryCache map[[2]string]bool

func (c memoryCache) Check(audience, jti string, _ time.Time) ReplayState {
	if c == nil {
		return Unknown
	}
	k := [2]string{audience, jti}
	if c[k] {
		return Replay
	}
	c[k] = true
	return FirstUse
}

type sample struct {
	p             Presentation
	trust         Trusted
	cfg           Config
	heads, claims []object
	inv           object
}

func makeSample(t *testing.T, id string) sample {
	t.Helper()
	f := loadFixture(t)
	s := sample{}
	s.cfg = Config{TrustAnchors: map[string]ed25519.PublicKey{"anchor": pub(1)}, AcceptedAlgs: []string{"Ed25519"}, VerifierIDs: []string{verifier}, AcceptedCeilings: map[string][]byte{f.CeilingRef: raw(f.Ceiling)}, MaxTokens: 8, MaxBytes: 1 << 18, MaxInvocationLifetime: time.Minute, ReplayCache: memoryCache{}}
	s.trust = Trusted{WPT: WPTAssumption{1, pub(4), true, []string{"Pedigree", "Pedigree-Invocation"}}, Consent: []ConsentAnswer{{"anchor", "consent", instant, true}}, Policies: f.FixturePolicies}
	parents := []string{}
	issuer := "anchor"
	for i := 0; i < 3; i++ {
		h := object{"typ": "pedigree+jwt", "alg": "Ed25519"}
		client := "agent-" + strconv.Itoa(i)
		grant := object{"resource": f.Resource, "scopes": []string{"read", "export"}}
		p := object{"iss": issuer, "client_id": client, "sub": "principal", "aud": verifier, "jti": "token-" + strconv.Itoa(i), "iat": epoch, "exp": epoch + 300, "cnf": object{"jkt": digest(raw(jwk(i + 2)))}, "del_depth": i, "parent_chain": slices.Clone(parents), "grants": []object{grant}, "consent_chain": []string{"consent"}, "ceiling_ref": f.CeilingRef}
		signer := i + 1
		if i == 0 {
			h["kid"] = "anchor"
		} else {
			if i == 1 && id == "local-wrong-signer" {
				signer = 5
			}
			h["jwk"] = jwk(signer)
			p["par_hash"] = tokenHash(s.p.Chain[i-1])
			p["mandate"] = object{"format": "cedar", "policy_set": f.Mandate}
		}
		if id == "local-ceiling-unknown" {
			p["ceiling_ref"] = "sha256:" + strings.Repeat("0", 64)
		}
		if i > 0 && id == "local-expired" {
			p["exp"] = epoch + 10
		}
		if i == 2 {
			switch id {
			case "depth-out-of-sequence":
				p["del_depth"] = 3
			case "mandate-dropped":
				delete(p, "mandate")
			case "principal-altered":
				p["sub"] = "another-principal"
			case "grant-widened":
				grant["scopes"] = []string{"read", "export", "delete"}
			case "grant-new-resource":
				p["grants"] = []object{grant, {"resource": f.Resource + "/other", "scopes": []string{"read"}}}
			case "local-audience-mismatch":
				p["aud"] = verifier + "/other"
			case "local-status-present":
				p["status"] = object{"status_list": object{"idx": 1, "uri": verifier + "/status"}}
			}
		}
		s.heads = append(s.heads, h)
		s.claims = append(s.claims, p)
		s.p.Chain = append(s.p.Chain, signBytes(signer, raw(h), raw(p)))
		parents = append(parents, p["jti"].(string))
		issuer = client
	}
	count := 500
	if id == "local-service-denies-50000" {
		count = 50000
	}
	s.p.Args = object{"max_records": count}
	action := "read"
	if strings.HasPrefix(id, "local-service-") {
		action = "export"
	}
	if id == "invoked-action-not-granted" {
		action = "delete"
	}
	s.inv = object{"iss": issuer, "aud": s.claims[2]["aud"], "jti": "invocation", "iat": epoch, "exp": epoch + 45, "tok": tokenHash(s.p.Chain[2]), "action": action, "resource": f.Resource, "args": object{"sha256": digest(raw(s.p.Args))}}
	if id == "local-expired" {
		s.inv["exp"] = epoch + 10
	}
	if strings.HasPrefix(id, "local-service-") {
		s.inv["jti"] = id
	}
	if id == "invocation-other-leaf" {
		other := s.claims[2]
		old := other["jti"]
		other["jti"] = "other-leaf"
		s.inv["tok"] = tokenHash(signBytes(3, raw(s.heads[2]), raw(other)))
		other["jti"] = old
	}
	s.signInvocation()
	switch id {
	case "parent-swap", "reissued-parent":
		p := s.claims[1]
		if id == "parent-swap" {
			p["mandate"] = object{"format": "cedar", "policy_set": append(slices.Clone(f.Mandate), f.ExtraPermit)}
		} else {
			p["jti"] = "reissue"
			p["exp"] = epoch + 299
		}
		s.p.Chain[1] = signBytes(2, raw(s.heads[1]), raw(p))
	case "no-invocation":
		s.p.Invocation = ""
		s.trust.WPT.Covers = []string{"Pedigree"}
	case "token-as-invocation":
		s.p.Invocation = s.p.Chain[2]
	case "invocation-as-parent":
		s.p.Chain = append(s.p.Chain, s.p.Invocation)
	case "args-altered":
		s.p.Args = object{"max_records": 50000}
	case "local-consent-missing":
		s.trust.Consent = nil
	case "local-consent-other-id":
		s.trust.Consent[0].ConsentID = "other"
	case "local-consent-revoked":
		s.trust.Consent[0].Active = false
	case "local-holder-key-mismatch":
		s.trust.WPT.HolderKey = pub(5)
	case "local-replay-state-unavailable":
		s.cfg.ReplayCache = memoryCache(nil)
	}
	return s
}
func (s *sample) signInvocation() {
	s.p.Invocation = signBytes(4, raw(object{"typ": "pedigree-inv+jwt", "alg": "Ed25519"}), raw(s.inv))
}

func TestRow1Serialization(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"negative zero", math.Float64frombits(0x8000000000000000), "0"},
		{"smallest subnormal", math.Float64frombits(1), "5e-324"},
		{"largest finite", math.MaxFloat64, "1.7976931348623157e+308"},
		{"round to nearest", math.Float64frombits(0x41b3de4355555555), "333333333.3333333"},
		{"fixed threshold", 1e-6, "0.000001"}, {"scientific threshold", 1e-7, "1e-7"},
		{"string", "\x01\b\t\n\f\r\"\\/<>&", `"\u0001\b\t\n\f\r\"\\/<>&"`},
		{"nested UTF-16", object{"z": []object{{"\ue000": 1, "😀": 2}}}, `{"z":[{"😀":2,"":1}]}`},
	} {
		got, err := serializeJCS(tc.v)
		if err != nil || string(got) != tc.want {
			t.Errorf("Row 1 %s: want %q, got %q (%v)", tc.name, tc.want, got, err)
		}
	}
}
func TestRow2Parse(t *testing.T) {
	s := makeSample(t, "valid-3-hop")
	p := s.claims[0]
	canonical := string(raw(p))
	for _, tc := range []struct{ name, body, want string }{
		{"duplicate", strings.Replace(canonical, `"iat":`, `"iat":0,"iat":`, 1), "malformed"},
		{"unsafe integer", strings.Replace(canonical, "1792310400", "9007199254740992", 1), "malformed"},
		{"fractional iat", strings.Replace(canonical, "1792310400", "1792310400.5", 1), ""},
		{"whitespace", " " + canonical, "non_canonical"},
	} {
		got := parseToken(signBytes(1, raw(s.heads[0]), []byte(tc.body)), 0)
		if got != tc.want {
			t.Errorf("Row 2 %s: want %q, got %q", tc.name, tc.want, got)
		}
	}
}
func TestRow3Thumbprint(t *testing.T) {
	k := pub(1)
	if got := publicJWKX(k); got != "objtVgOoVyOQvCjA245nWeTayaEKkNx6qU_i8Lm_THA" {
		t.Errorf("Row 3 public x: got %q", got)
	}
	if got := thumbprint(k); got != "cf8YxbFdYDztN3LloLpmXSxxJrk50bL4zszPsKBaWnw" {
		t.Errorf("Row 3 thumbprint: got %q", got)
	}
}
func TestRow4ProtectedHeaders(t *testing.T) {
	for _, id := range []string{"unknown", "crit", "root jwk", "private member"} {
		s := makeSample(t, "valid-3-hop")
		i := 0
		switch id {
		case "unknown":
			s.heads[0]["unknown"] = true
		case "crit":
			s.heads[0]["crit"] = []string{"unknown"}
		case "root jwk":
			s.heads[0]["jwk"] = jwk(1)
		case "private member":
			i = 1
			s.heads[1]["jwk"].(object)["d"] = "ZHVtbXk"
		}
		got := parseToken(signBytes(i+1, raw(s.heads[i]), raw(s.claims[i])), i)
		if got != "malformed" {
			t.Errorf("Row 4 %s: want malformed, got %s", id, got)
		}
	}
}

type expectedEntry struct {
	ID, Source   string
	Presentation int
	Result
}

func expectations(t *testing.T) []expectedEntry {
	t.Helper()
	var pin struct{ Cases []expectedEntry }
	readJSON(t, filepath.Join(vectorDir, "expected.json"), &pin)
	return pin.Cases
}
func checkCases(t *testing.T, row string, ids ...string) {
	t.Helper()
	pin := expectations(t)
	for _, id := range ids {
		s := makeSample(t, id)
		n := 0
		for _, want := range pin {
			if want.ID != id {
				continue
			}
			n++
			s.trust.WPT.PresentationIndex = n
			got := Verify(s.p, s.trust, s.cfg, instant)
			if got.Outcome != want.Outcome || !slices.Equal(got.TrustedInputsUsed, want.TrustedInputsUsed) {
				t.Errorf("%s %s[%d]: want %s %v, got %s %v", row, id, n, want.Outcome, want.TrustedInputsUsed, got.Outcome, got.TrustedInputsUsed)
			}
		}
		if n == 0 {
			t.Fatalf("%s no expectation for %s", row, id)
		}
	}
}
func TestRow5Delegation(t *testing.T) {
	checkCases(t, "Row 5", "valid-3-hop", "parent-swap", "reissued-parent", "depth-out-of-sequence", "mandate-dropped", "principal-altered", "grant-widened", "grant-new-resource")
}
func TestRow6Invocation(t *testing.T) {
	ids := []string{"no-invocation", "token-as-invocation", "invocation-as-parent", "invocation-other-leaf", "invocation-replay", "args-altered"}
	checkCases(t, "Row 6", ids...)
	if t.Failed() {
		return
	}
	checkPublished(t, "Row 6", ids)
}
func TestRow7LocalFailures(t *testing.T) {
	checkCases(t, "Row 7", "local-expired", "local-audience-mismatch", "local-ceiling-unknown", "local-wrong-signer")
}
func TestRow10ServiceDecision(t *testing.T) {
	checkCases(t, "Row 10", "local-service-denies-50000", "local-service-permits-500")
}
func TestRow11GrantDecision(t *testing.T) { checkCases(t, "Row 11", "invoked-action-not-granted") }
func TestRow12TrustedInputs(t *testing.T) {
	checkCases(t, "Row 12", "local-status-present", "local-consent-missing", "local-consent-other-id", "local-consent-revoked", "local-holder-key-mismatch", "local-replay-state-unavailable")
}

// Build separately so compiler errors cannot serve as CLI outcome evidence.
func command(t *testing.T, row, name string, args ...string) []byte {
	t.Helper()
	binary := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", binary, "../cmd/"+name)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v: %s", name, err, b)
	}
	b, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: want exit 0, got %v: %s", row, name, err, bytes.TrimSpace(b))
	}
	return b
}
func fileSet(t *testing.T, row, dir string, want map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.Type().IsRegular() || !want[e.Name()] {
			t.Fatalf("%s unexpected file %s", row, e.Name())
		}
		seen[e.Name()] = true
	}
	for name := range want {
		if !seen[name] {
			t.Fatalf("%s missing %s", row, name)
		}
	}
}
func owned(pin []expectedEntry) map[string]bool {
	names := map[string]bool{"manifest.json": true}
	for _, entry := range pin {
		names[entry.ID+".json"] = true
	}
	return names
}
func TestRow8Generator(t *testing.T) {
	dir := t.TempDir()
	command(t, "Row 8", "pedigree-vectors", "-out", dir)
	files := owned(expectations(t))
	fileSet(t, "Row 8", dir, files)
	for name := range files {
		if !bytes.Equal(readFile(t, filepath.Join(dir, name)), readFile(t, filepath.Join(vectorDir, name))) {
			t.Errorf("Row 8 generated bytes differ for %s", name)
		}
	}
}

// Case files carry presentation results alongside their request fields.
// The CLI emits one JSON object per presentation with id, presentation,
// expected, got, trusted_inputs_used and status ("PASS" or "FAIL").
type reportLine struct {
	ID, Expected, Got, Status string
	Presentation              int
	TrustedInputsUsed         []string `json:"trusted_inputs_used"`
}
type vectorPresentation struct {
	Presentation
	Result
}
type vectorCase struct {
	ID, Source    string
	Presentations []vectorPresentation
	WPT           []WPTAssumption
	Consent       []ConsentAnswer
	At            time.Time
	TrustAnchors  map[string]ed25519.PublicKey `json:"trust_anchors"`
	VerifierIDs   []string                     `json:"verifier_ids"`
}

func checkPublished(t *testing.T, row string, subset []string) {
	t.Helper()
	output := command(t, row, "pedigree-verify", "-dir", vectorDir)
	pin := expectations(t)
	files := owned(pin)
	files["expected.json"] = true
	fileSet(t, row, vectorDir, files)
	type index struct {
		id string
		n  int
	}
	lines := map[index]reportLine{}
	for _, line := range bytes.Split(bytes.TrimSpace(output), []byte{'\n'}) {
		var r reportLine
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("%s invalid CLI result %q", row, line)
		}
		key := index{r.ID, r.Presentation}
		if _, ok := lines[key]; ok {
			t.Fatalf("%s duplicate CLI result %v", row, key)
		}
		lines[key] = r
	}
	if len(lines) != len(pin) {
		t.Fatalf("%s want %d CLI results, got %d", row, len(pin), len(lines))
	}
	groups := map[string][]expectedEntry{}
	for _, e := range pin {
		groups[e.ID] = append(groups[e.ID], e)
	}
	for id, entries := range groups {
		if subset != nil && !slices.Contains(subset, id) {
			continue
		}
		var v vectorCase
		readJSON(t, filepath.Join(vectorDir, id+".json"), &v)
		if v.ID != id || v.Source != entries[0].Source || len(v.Presentations) != len(entries) || len(v.WPT) != len(entries) {
			t.Fatalf("%s %s case metadata mismatch", row, id)
		}
		s := makeSample(t, id)
		s.cfg.TrustAnchors = v.TrustAnchors
		s.cfg.VerifierIDs = v.VerifierIDs
		s.trust.Consent = v.Consent
		seen := map[int]bool{}
		for _, w := range v.WPT {
			if w.PresentationIndex < 1 || w.PresentationIndex > len(entries) || seen[w.PresentationIndex] {
				t.Fatalf("%s %s invalid WPT index %d", row, id, w.PresentationIndex)
			}
			seen[w.PresentationIndex] = true
		}
		for _, want := range entries {
			i := want.Presentation
			p := v.Presentations[i-1]
			for _, w := range v.WPT {
				if w.PresentationIndex == i {
					s.trust.WPT = w
				}
			}
			r := lines[index{id, i}]
			api := Verify(p.Presentation, s.trust, s.cfg, v.At)
			if r.TrustedInputsUsed == nil || r.Status != "PASS" || r.Expected != want.Outcome || r.Got != want.Outcome || !slices.Equal(r.TrustedInputsUsed, want.TrustedInputsUsed) {
				t.Errorf("%s %s[%d] CLI result differs: %+v", row, id, i, r)
			}
			if p.TrustedInputsUsed == nil {
				t.Errorf("%s %s[%d] missing vector input list", row, id, i)
			}
			for _, got := range []Result{p.Result, api} {
				if got.Outcome != want.Outcome || !slices.Equal(got.TrustedInputsUsed, want.TrustedInputsUsed) {
					t.Errorf("%s %s[%d] want %+v, got %+v", row, id, i, want.Result, got)
				}
			}
		}
	}
}
func TestRow9VerifierCLI(t *testing.T) { checkPublished(t, "Row 9", nil) }
