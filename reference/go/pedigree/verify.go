package pedigree

import (
	"crypto/subtle"
	"math"
	"slices"
	"time"
)

const (
	policyLabel    = "policy_fixture"
	consentLabel   = "consent_fixture"
	wptLabelPrefix = "wpt_assumed:fresh,covers="
	wptLabel       = wptLabelPrefix + "Pedigree"
	fixtureStop    = "unsupported_fixture_policy"
)

type inputUse struct {
	policy, consent bool
	wpt             string
}

func (u inputUse) result(outcome string) Result {
	inputs := make([]string, 0, 3)
	if u.policy {
		inputs = append(inputs, policyLabel)
	}
	if u.consent {
		inputs = append(inputs, consentLabel)
	}
	if u.wpt != "" {
		inputs = append(inputs, u.wpt)
	}
	return Result{Outcome: outcome, TrustedInputsUsed: inputs}
}

// Verify evaluates one presentation at the supplied instant. An
// unsupported_fixture_policy outcome is a fixture stop outside Section 5.6.
func Verify(p Presentation, t Trusted, cfg Config, at time.Time) Result {
	var used inputUse
	chain, outcome := parseChain(p.Chain, cfg.MaxTokens, cfg.MaxBytes)
	if outcome != "" {
		return used.result(outcome)
	}
	anchor := chain[0].issuer
	if !verifySignatures(chain, cfg) {
		return used.result("signature_invalid")
	}
	if outcome := verifyLinkage(chain); outcome != "" {
		return used.result(outcome)
	}
	if outcome := verifyShape(chain); outcome != "" {
		return used.result(outcome)
	}
	if outcome := checkAttenuation(chain, t.Policies, &used); outcome != "" {
		return used.result(outcome)
	}
	if !verifyTime(chain, at) {
		return used.result("expired")
	}
	for _, token := range chain {
		if _, ok := cfg.AcceptedCeilings[token.ceiling]; !ok {
			return used.result("ceiling_unknown")
		}
	}
	if outcome := checkStatus(chain, anchor, t.Consent, at, &used); outcome != "" {
		return used.result(outcome)
	}
	leaf := chain[len(chain)-1]
	if !intersects(leaf.audience, cfg.VerifierIDs) {
		return used.result("audience_mismatch")
	}
	inv, args, outcome := checkInvocation(p, leaf, t.WPT, cfg, at, &used)
	if outcome != "" {
		return used.result(outcome)
	}
	outcome = decide(chain, inv, args, cfg.AcceptedCeilings[leaf.ceiling], t.Policies, &used)
	return used.result(outcome)
}

func parseChain(compacts []string, maxTokens, maxBytes int) ([]token, string) {
	if len(compacts) == 0 || len(compacts) > maxTokens || maxBytes <= 0 {
		return nil, "malformed"
	}
	for _, compact := range compacts {
		if len(compact) > maxBytes {
			return nil, "malformed"
		}
		maxBytes -= len(compact)
	}
	chain := make([]token, len(compacts))
	for i, compact := range compacts {
		t, outcome := decodeToken(compact, i)
		if outcome != "" {
			return nil, outcome
		}
		chain[i] = t
	}
	return chain, ""
}

func verifySignatures(chain []token, cfg Config) bool {
	root := chain[0]
	// This profile indexes the configured anchors by root issuer. The JOSE
	// kid is optional metadata and cannot select an unrelated issuer's key.
	if !root.jws.verifies(cfg.TrustAnchors[root.issuer], cfg.AcceptedAlgs) {
		return false
	}
	for i, child := range chain[1:] {
		parent := chain[i]
		if child.issuer != parent.client || thumbprint(child.jws.key) != parent.holder ||
			!child.jws.verifies(child.jws.key, cfg.AcceptedAlgs) {
			return false
		}
	}
	return true
}

func verifyLinkage(chain []token) string {
	if chain[0].depth != 0 || len(chain[0].parents) != 0 {
		return "linkage_invalid"
	}
	for i, child := range chain[1:] {
		parent := chain[i]
		if !digestEqual(child.parentHash, sha256URL([]byte(parent.jws.input))) {
			return "par_hash_mismatch"
		}
		if child.depth != parent.depth+1 || int64(len(child.parents)) != child.depth ||
			!slices.Equal(child.parents[:i], parent.parents) || child.parents[i] != parent.id {
			return "linkage_invalid"
		}
	}
	return ""
}

func verifyShape(chain []token) string {
	root := chain[0]
	for _, child := range chain[1:] {
		if child.principal != root.principal {
			return "principal_altered"
		}
	}
	for _, child := range chain[1:] {
		if !slices.Equal(child.consents, root.consents) {
			return "consent_altered"
		}
	}
	return ""
}

func verifyTime(chain []token, at time.Time) bool {
	for i, t := range chain {
		if !inWindow(at, t.iat, t.exp) || t.nbf != nil && instantBefore(at, *t.nbf) {
			return false
		}
		if i > 0 && (t.iat < chain[i-1].iat || t.exp > chain[i-1].exp) {
			return false
		}
	}
	return true
}

func inWindow(at time.Time, start, end float64) bool {
	return !instantBefore(at, start) && instantBefore(at, end)
}

func instantBefore(at time.Time, date float64) bool {
	sec, fraction := math.Modf(date)
	// Keep the fractional part separate from Unix seconds to retain the
	// evaluation instant's nanosecond precision at current epoch values.
	if fraction < 0 {
		sec--
		fraction++
	}
	if at.Unix() != int64(sec) {
		return at.Unix() < int64(sec)
	}
	return float64(at.Nanosecond())/1e9 < fraction
}

func digestEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func intersects(a, b []string) bool {
	for _, s := range a {
		if slices.Contains(b, s) {
			return true
		}
	}
	return false
}

type invocation struct {
	issuer, audience, id, tokenHash, action, resource string
	iat, exp                                          float64
	binding                                           map[string]any
}

func parseInvocation(compact string) (compactJWS, invocation, bool) {
	j, o, outcome := decodeJWS(compact, invocationType, false)
	var inv invocation
	if outcome != "" || len(o) != 9 ||
		!onlyMembers(o, "iss", "aud", "jti", "iat", "exp", "tok", "action", "resource", "args") {
		return j, inv, false
	}
	inv.issuer, inv.audience, inv.id = str(o, "iss"), str(o, "aud"), str(o, "jti")
	inv.tokenHash, inv.action, inv.resource = str(o, "tok"), str(o, "action"), str(o, "resource")
	var iatOK, expOK, argsOK bool
	inv.iat, iatOK = numericDate(o["iat"])
	inv.exp, expOK = numericDate(o["exp"])
	inv.binding, argsOK = o["args"].(map[string]any)
	ok := inv.issuer != "" && inv.audience != "" && inv.id != "" && isDigest(inv.tokenHash) &&
		inv.action != "" && absoluteURI(inv.resource) && iatOK && expOK && argsOK
	return j, inv, ok
}

func checkInvocation(p Presentation, leaf token, wpt WPTAssumption, cfg Config, at time.Time, used *inputUse) (invocation, []byte, string) {
	var inv invocation
	coversPedigree := slices.Contains(wpt.Covers, "Pedigree")
	coversInvocation := slices.Contains(wpt.Covers, "Pedigree-Invocation")
	switch {
	case coversPedigree && coversInvocation:
		used.wpt = wptLabel + "+Pedigree-Invocation"
	case coversPedigree:
		used.wpt = wptLabel
	case coversInvocation:
		used.wpt = wptLabelPrefix + "Pedigree-Invocation"
	default:
		used.wpt = wptLabelPrefix
	}
	if !wpt.Fresh || !coversPedigree || thumbprint(wpt.HolderKey) != leaf.holder {
		return inv, nil, "holder_binding_failed"
	}
	if p.Invocation == "" {
		return inv, nil, "invocation_invalid"
	}
	if !coversInvocation {
		return inv, nil, "holder_binding_failed"
	}
	j, inv, ok := parseInvocation(p.Invocation)
	if !ok || !j.verifies(wpt.HolderKey, cfg.AcceptedAlgs) {
		return inv, nil, "invocation_invalid"
	}
	if inv.issuer != leaf.client || !digestEqual(inv.tokenHash, sha256URL([]byte(leaf.jws.input))) ||
		!slices.Contains(cfg.VerifierIDs, inv.audience) || !slices.Contains(leaf.audience, inv.audience) {
		return inv, nil, "invocation_invalid"
	}
	if !inWindow(at, inv.iat, inv.exp) || inv.exp > leaf.exp ||
		cfg.MaxInvocationLifetime <= 0 || inv.exp-inv.iat > cfg.MaxInvocationLifetime.Seconds() {
		return inv, nil, "invocation_invalid"
	}
	if outcome := recordInvocation(cfg.ReplayCache, inv); outcome != "" {
		return inv, nil, outcome
	}
	args, err := serializeArgsJCS(p.Args)
	if p.Args == nil || err != nil || len(inv.binding) != 1 ||
		!digestEqual(str(inv.binding, "sha256"), sha256URL(args)) {
		return inv, nil, "invocation_invalid"
	}
	return inv, args, ""
}

func recordInvocation(cache ReplayCache, inv invocation) string {
	if cache == nil {
		return "replay_unknown"
	}
	sec, fraction := math.Modf(inv.exp)
	expiry := time.Unix(int64(sec), int64(math.Ceil(fraction*1e9))).UTC()
	switch cache.Check(inv.audience, inv.id, expiry) {
	case FirstUse:
		return ""
	case Replay:
		return "invocation_replayed"
	default:
		return "replay_unknown"
	}
}
