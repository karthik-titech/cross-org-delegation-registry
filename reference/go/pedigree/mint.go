package pedigree

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

//go:embed testdata/fixtures.json
var fixtureData []byte

const fixtureEpoch = 1792310400
const fixtureVerifier = "https://records.example.net"

type fixtureKey struct {
	Label   string `json:"label"`
	Index   int    `json:"index"`
	SeedHex string `json:"seed_hex"`
}

type fixtureSpec struct {
	FixturePolicies
	Resource    string
	ExtraPermit string `json:"extra_permit"`
	Keys        []fixtureKey
}

func loadFixtureSpec() (fixtureSpec, error) {
	var f fixtureSpec
	err := json.Unmarshal(fixtureData, &f)
	return f, err
}

type casePresentation struct {
	Presentation
	Result
}

type fixtureCase struct {
	ID              string                       `json:"id"`
	Source          string                       `json:"source"`
	Presentations   []casePresentation           `json:"presentations"`
	WPT             []WPTAssumption              `json:"wpt"`
	Consent         []ConsentAnswer              `json:"consent"`
	At              time.Time                    `json:"at"`
	TrustAnchors    map[string]ed25519.PublicKey `json:"trust_anchors"`
	VerifierIDs     []string                     `json:"verifier_ids"`
	ReplayAvailable bool                         `json:"replay_available"`
	Keys            []fixtureKey                 `json:"keys"`
}

type caseCache map[[2]string]struct{}

func (c caseCache) Check(audience, jti string, _ time.Time) ReplayState {
	key := [2]string{audience, jti}
	if _, seen := c[key]; seen {
		return Replay
	}
	c[key] = struct{}{}
	return FirstUse
}

func (c fixtureCase) config(f fixtureSpec) (Config, error) {
	doc, err := serializeJCS(f.Ceiling)
	if err != nil || ceilingDigest(doc) != f.CeilingRef {
		return Config{}, fmt.Errorf("invalid fixture ceiling")
	}
	cfg := Config{
		TrustAnchors: c.TrustAnchors, AcceptedAlgs: []string{ed25519Alg}, VerifierIDs: c.VerifierIDs,
		AcceptedCeilings: map[string][]byte{f.CeilingRef: doc},
		MaxTokens:        8, MaxBytes: 1 << 18, MaxInvocationLifetime: time.Minute,
	}
	if c.ReplayAvailable {
		cfg.ReplayCache = caseCache{}
	}
	return cfg, nil
}

func fixtureSeed(i int) [32]byte {
	return sha256.Sum256([]byte("pedigree-01 test key " + strconv.Itoa(i)))
}

func fixturePrivateKey(i int) ed25519.PrivateKey {
	seed := fixtureSeed(i)
	return ed25519.NewKeyFromSeed(seed[:])
}

func fixturePublicKey(i int) ed25519.PublicKey {
	return fixturePrivateKey(i).Public().(ed25519.PublicKey)
}

type claims = map[string]any

func signFixture(i int, header, payload claims) string {
	h, err := serializeJCS(header)
	if err != nil {
		panic(err)
	}
	p, err := serializeJCS(payload)
	if err != nil {
		panic(err)
	}
	input := base64URL.EncodeToString(h) + "." + base64URL.EncodeToString(p)
	sig := ed25519.Sign(fixturePrivateKey(i), []byte(input))
	return input + "." + base64URL.EncodeToString(sig)
}

func signingInputDigest(compact string) string {
	return sha256URL([]byte(compact[:strings.LastIndexByte(compact, '.')]))
}

func newFixtureCase(f fixtureSpec, id, source string) fixtureCase {
	at := time.Unix(fixtureEpoch+15, 0).UTC()
	return fixtureCase{
		ID: id, Source: source, At: at, Keys: f.Keys,
		TrustAnchors: map[string]ed25519.PublicKey{"anchor": fixturePublicKey(1)},
		VerifierIDs:  []string{fixtureVerifier}, ReplayAvailable: id != "local-replay-state-unavailable",
		Consent: []ConsentAnswer{{"anchor", "consent", at, true}},
	}
}

func mintCase(f fixtureSpec, id, source string) (fixtureCase, error) {
	c := newFixtureCase(f, id, source)
	chain, leaf, otherLeaf := mintChain(f, id)
	p := Presentation{Chain: chain}
	p.Invocation, p.Args = mintInvocation(f, id, leaf, signingInputDigest(chain[2]), otherLeaf)
	wpt := WPTAssumption{1, fixturePublicKey(4), true, []string{"Pedigree", "Pedigree-Invocation"}}
	switch id {
	case "no-invocation":
		p.Invocation = ""
		wpt.Covers = []string{"Pedigree"}
	case "token-as-invocation":
		p.Invocation = chain[2]
	case "invocation-as-parent":
		p.Chain = append(chain, p.Invocation)
	case "args-altered":
		p.Args = claims{"max_records": 50000}
	case "local-consent-missing":
		c.Consent = []ConsentAnswer{}
	case "local-consent-other-id":
		c.Consent[0].ConsentID = "other"
	case "local-consent-revoked":
		c.Consent[0].Active = false
	case "local-holder-key-mismatch":
		wpt.HolderKey = fixturePublicKey(5)
	}
	c.WPT = []WPTAssumption{wpt}
	if id == "invocation-replay" {
		wpt.PresentationIndex = 2
		c.WPT = append(c.WPT, wpt)
	}
	cfg, err := c.config(f)
	if err != nil {
		return c, err
	}
	for _, assumed := range c.WPT {
		trusted := Trusted{WPT: assumed, Consent: c.Consent, Policies: f.FixturePolicies}
		c.Presentations = append(c.Presentations, casePresentation{p, Verify(p, trusted, cfg, c.At)})
	}
	return c, nil
}

func mintChain(f fixtureSpec, id string) ([]string, claims, string) {
	var chain []string
	var leaf claims
	var otherLeaf, replacedParent string
	parents := []string{}
	issuer := "anchor"
	for i := 0; i < 3; i++ {
		signer := i + 1
		header := claims{"typ": tokenType, "alg": ed25519Alg}
		client := "agent-" + strconv.Itoa(i)
		grant := claims{"resource": f.Resource, "scopes": []string{"read", "export"}}
		p := claims{
			"iss": issuer, "sub": "principal", "aud": fixtureVerifier, "client_id": client,
			"jti": "token-" + strconv.Itoa(i), "iat": fixtureEpoch, "exp": fixtureEpoch + 300,
			"cnf": claims{"jkt": thumbprint(fixturePublicKey(i + 2))}, "del_depth": i,
			"parent_chain": slices.Clone(parents), "grants": []claims{grant},
			"consent_chain": []string{"consent"}, "ceiling_ref": f.CeilingRef,
		}
		if i == 0 {
			header["kid"] = "anchor"
		} else {
			if i == 1 && id == "local-wrong-signer" {
				signer = 5
			}
			header["jwk"] = publicJWK(fixturePublicKey(signer))
			p["par_hash"] = signingInputDigest(chain[i-1])
			p["mandate"] = fixtureMandate(f.Mandate)
		}
		if id == "local-ceiling-unknown" {
			p["ceiling_ref"] = "sha256:" + strings.Repeat("0", 64)
		}
		if i > 0 && id == "local-expired" {
			p["exp"] = fixtureEpoch + 10
		}
		if i == 2 {
			mutateLeaf(id, f, p, grant)
			leaf = p
		}
		chain = append(chain, signFixture(signer, header, p))
		parents = append(parents, p["jti"].(string))
		issuer = client
		if i == 1 {
			replacedParent = mintReplacement(id, f, header, p)
		}
		if i == 2 && id == "invocation-other-leaf" {
			p["jti"] = "other-leaf"
			otherLeaf = signingInputDigest(signFixture(signer, header, p))
			p["jti"] = "token-2"
		}
	}
	if replacedParent != "" {
		chain[1] = replacedParent
	}
	return chain, leaf, otherLeaf
}

func fixtureMandate(policies []string) claims {
	return claims{"format": "cedar", "policy_set": policies}
}

func mintReplacement(id string, f fixtureSpec, h, p claims) string {
	switch id {
	case "parent-swap":
		p["mandate"] = fixtureMandate(append(slices.Clone(f.Mandate), f.ExtraPermit))
	case "reissued-parent":
		p["jti"] = "reissue"
		p["exp"] = fixtureEpoch + 299
	default:
		return ""
	}
	return signFixture(2, h, p)
}

func mutateLeaf(id string, f fixtureSpec, p, grant claims) {
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
		p["grants"] = []claims{grant, {"resource": f.Resource + "/other", "scopes": []string{"read"}}}
	case "local-audience-mismatch":
		p["aud"] = fixtureVerifier + "/other"
	case "local-status-present":
		p["status"] = claims{"status_list": claims{"idx": 1, "uri": fixtureVerifier + "/status"}}
	}
}

func mintInvocation(f fixtureSpec, id string, leaf claims, leafDigest, otherLeaf string) (string, claims) {
	action := "read"
	jti := "invocation"
	count := 500
	exp := fixtureEpoch + 45
	switch id {
	case "local-service-denies-50000":
		action, count, jti = "export", 50000, id
	case "local-service-permits-500":
		action, jti = "export", id
	case "invoked-action-not-granted":
		action = "delete"
	case "local-expired":
		exp = fixtureEpoch + 10
	case "invocation-other-leaf":
		leafDigest = otherLeaf
	}
	args := claims{"max_records": count}
	jcs, err := serializeJCS(args)
	if err != nil {
		panic(err)
	}
	p := claims{
		"iss": leaf["client_id"], "aud": leaf["aud"], "jti": jti, "iat": fixtureEpoch, "exp": exp,
		"tok": leafDigest, "action": action, "resource": f.Resource, "args": claims{"sha256": sha256URL(jcs)},
	}
	return signFixture(4, claims{"typ": invocationType, "alg": ed25519Alg}, p), args
}

var caseIDs = []string{
	"valid-3-hop", "parent-swap", "reissued-parent", "depth-out-of-sequence", "mandate-dropped", "principal-altered",
	"grant-widened", "grant-new-resource", "no-invocation", "token-as-invocation", "invocation-as-parent",
	"invocation-other-leaf", "invocation-replay", "args-altered", "invoked-action-not-granted",
	"local-expired", "local-audience-mismatch", "local-ceiling-unknown", "local-wrong-signer",
	"local-service-denies-50000", "local-service-permits-500", "local-status-present", "local-consent-missing",
	"local-consent-other-id", "local-consent-revoked", "local-holder-key-mismatch", "local-replay-state-unavailable",
}

type manifestCase struct {
	ID     string `json:"id"`
	File   string `json:"file"`
	Source string `json:"source"`
	Digest string `json:"digest"`
}

type vectorManifest struct {
	Profile          string         `json:"profile"`
	ArgumentsBinding string         `json:"arguments_binding"`
	WPT              string         `json:"wpt"`
	Policy           string         `json:"policy"`
	CeilingRef       string         `json:"ceiling_ref"`
	Ceiling          []string       `json:"ceiling"`
	Cases            []manifestCase `json:"cases"`
}

// GenerateVectors writes deterministic PEDIGREE -01 cases and their manifest.
func GenerateVectors(dir string) error {
	f, err := loadFixtureSpec()
	if err != nil {
		return err
	}
	if len(f.Keys) != 5 {
		return fmt.Errorf("invalid fixture key count")
	}
	for i, key := range f.Keys {
		seed := fixtureSeed(i + 1)
		if key.Label != "TEST ONLY" || key.Index != i+1 || key.SeedHex != hex.EncodeToString(seed[:]) {
			return fmt.Errorf("invalid fixture key %d", i+1)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	manifest := vectorManifest{
		Profile:          "PEDIGREE -01 Ed25519 fixture profile",
		ArgumentsBinding: "Illustrative profile: sha256 is base64url(SHA-256(JCS(arguments object))).",
		WPT:              "Each presentation has its own assumed fresh WPT with the listed coverage and holder key.",
		Policy:           "Fixture lookups use pinned Cedar policy effects and request decisions.",
		CeilingRef:       f.CeilingRef, Ceiling: f.Ceiling,
	}
	for _, id := range caseIDs {
		source := "appendix_a"
		if strings.HasPrefix(id, "local-") {
			source = "local"
		}
		c, err := mintCase(f, id, source)
		if err != nil {
			return err
		}
		file := id + ".json"
		b, err := writeVector(filepath.Join(dir, file), c)
		if err != nil {
			return err
		}
		manifest.Cases = append(manifest.Cases, manifestCase{id, file, source, ceilingDigest(b)})
	}
	_, err = writeVector(filepath.Join(dir, "manifest.json"), manifest)
	return err
}

func writeVector(path string, value any) ([]byte, error) {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pedigree-vector-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	writeErr := tmp.Chmod(0o644)
	if writeErr == nil {
		_, writeErr = tmp.Write(b)
	}
	closeErr := tmp.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return b, os.Rename(tmp.Name(), path)
}
