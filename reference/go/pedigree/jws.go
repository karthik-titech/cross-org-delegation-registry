package pedigree

import (
	"crypto/ed25519"
	"encoding/hex"
	"math"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

const (
	tokenType      = "pedigree+jwt"
	invocationType = "pedigree-inv+jwt"
	ed25519Alg     = "Ed25519"
)

type compactJWS struct {
	input     string
	signature []byte
	algorithm string
	key       ed25519.PublicKey
}

func decodeJWS(compact, typ string, child bool) (compactJWS, map[string]any, string) {
	var j compactJWS
	parts := strings.SplitN(compact, ".", 4)
	if len(parts) != 3 {
		return j, nil, "malformed"
	}
	headerBytes, headerOK := decodeBase64URL(parts[0])
	payloadBytes, payloadOK := decodeBase64URL(parts[1])
	signature, sigOK := decodeBase64URL(parts[2])
	if !headerOK || !payloadOK || !sigOK || len(signature) == 0 {
		return j, nil, "malformed"
	}
	header, headerOutcome := decodeObject(headerBytes)
	payload, payloadOutcome := decodeObject(payloadBytes)
	if headerOutcome == "malformed" || payloadOutcome == "malformed" {
		return j, nil, "malformed"
	}
	if headerOutcome != "" || payloadOutcome != "" {
		return j, nil, "non_canonical"
	}
	if !onlyMembers(header, "typ", "alg", "kid", "jwk") || str(header, "typ") != typ || str(header, "alg") == "" {
		// JWS crit cannot name registered JWS parameters. This profile
		// implements no critical extensions.
		return j, nil, "malformed"
	}
	if kid, present := header["kid"]; present {
		if _, ok := kid.(string); !ok {
			return j, nil, "malformed"
		}
	}
	key, present := header["jwk"]
	if present != child {
		return j, nil, "malformed"
	}
	if child {
		j.key = readPublicJWK(key)
		if j.key == nil {
			return j, nil, "malformed"
		}
	}
	j.input = parts[0] + "." + parts[1]
	j.signature = signature
	j.algorithm = str(header, "alg")
	return j, payload, ""
}

func readPublicJWK(value any) ed25519.PublicKey {
	o, ok := value.(map[string]any)
	if !ok || str(o, "kty") != "OKP" || str(o, "crv") != ed25519Alg {
		return nil
	}
	for name, v := range o {
		switch name {
		case "kty", "crv", "x":
		case "kid", "alg", "use", "x5u", "x5t", "x5t#S256":
			if _, ok := v.(string); !ok {
				return nil
			}
		case "key_ops", "x5c":
			if _, ok := stringList(v); !ok {
				return nil
			}
		case "d", "p", "q", "dp", "dq", "qi", "oth", "k":
			return nil
		}
	}
	x, ok := decodeBase64URL(str(o, "x"))
	if !ok || len(x) != ed25519.PublicKeySize {
		return nil
	}
	return ed25519.PublicKey(x)
}

func (j compactJWS) verifies(key ed25519.PublicKey, accepted []string) bool {
	return j.algorithm == ed25519Alg && slices.Contains(accepted, j.algorithm) &&
		len(key) == ed25519.PublicKeySize && !smallOrderEd25519([ed25519.PublicKeySize]byte(key)) &&
		ed25519.Verify(key, []byte(j.input), j.signature)
}

func smallOrderEd25519(key [ed25519.PublicKeySize]byte) bool {
	// The libsodium blocklist compares the encoded y-coordinate. Ignore the
	// x-sign bit to cover both signs, including non-canonical encodings.
	key[31] &= 0x7f
	switch key {
	case [32]byte{}, [32]byte{1}: // y = 0 or 1
		return true
	case [32]byte{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
		0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
		0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	}, [32]byte{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
		0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
		0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	}: // the two y-coordinates of order-eight points
		return true
	}
	// The remaining values are p-1, p, and p+1 for p = 2^255-19.
	return key[0] >= 0xec && key[0] <= 0xee && [31]byte(key[1:]) == [31]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	}
}

type token struct {
	jws                                                        compactJWS
	issuer, principal, client, id, holder, parentHash, ceiling string
	audience, parents, consents, mandate                       []string
	grants                                                     map[string][]string
	depth                                                      int64
	iat, exp                                                   float64
	nbf                                                        *float64
	status                                                     bool
}

// parseToken checks step 1 only. An empty outcome indicates acceptance.
func parseToken(compact string, depth int) string {
	_, outcome := decodeToken(compact, depth)
	return outcome
}

func decodeToken(compact string, position int) (token, string) {
	var t token
	j, o, outcome := decodeJWS(compact, tokenType, position > 0)
	if outcome != "" {
		return t, outcome
	}
	if !onlyMembers(o, "iss", "sub", "client_id", "aud", "jti", "iat", "exp", "nbf", "cnf", "del_depth",
		"par_hash", "parent_chain", "grants", "mandate", "narrowing_proof", "consent_chain", "ceiling_ref",
		"completion_bindable", "status", "act") {
		return t, "malformed"
	}
	t.jws = j
	t.issuer, t.principal, t.client, t.id = str(o, "iss"), str(o, "sub"), str(o, "client_id"), str(o, "jti")
	if t.issuer == "" || t.principal == "" || t.client == "" || t.id == "" {
		return t, "malformed"
	}
	var ok bool
	t.audience, ok = audience(o["aud"])
	if !ok || !t.setTime(o) {
		return t, "malformed"
	}
	cnf, ok := o["cnf"].(map[string]any)
	t.holder = str(cnf, "jkt")
	if !ok || len(cnf) != 1 || !isDigest(t.holder) {
		return t, "malformed"
	}
	depth, ok := o["del_depth"].(float64)
	if !ok || depth < 0 || depth > maxSafeInteger || math.Trunc(depth) != depth {
		return t, "malformed"
	}
	t.depth = int64(depth)
	if v, present := o["par_hash"]; present || position > 0 {
		t.parentHash, ok = v.(string)
		if position == 0 || !ok || !isDigest(t.parentHash) {
			return t, "malformed"
		}
	}
	t.parents, ok = stringList(o["parent_chain"])
	if !ok {
		return t, "malformed"
	}
	t.grants, ok = grants(o["grants"])
	if !ok {
		return t, "malformed"
	}
	t.consents, ok = stringList(o["consent_chain"])
	t.ceiling = str(o, "ceiling_ref")
	if !ok || len(t.consents) == 0 || !isCeilingHash(t.ceiling) {
		return t, "malformed"
	}
	if !t.setOptionalClaims(o, position) {
		return t, "malformed"
	}
	return t, ""
}

func (t *token) setTime(o map[string]any) bool {
	iat, iatOK := numericDate(o["iat"])
	exp, expOK := numericDate(o["exp"])
	if !iatOK || !expOK {
		return false
	}
	t.iat, t.exp = iat, exp
	if v, present := o["nbf"]; present {
		n, ok := numericDate(v)
		if !ok {
			return false
		}
		t.nbf = &n
	}
	return true
}

func (t *token) setOptionalClaims(o map[string]any, position int) bool {
	if v, present := o["mandate"]; present {
		m, ok := v.(map[string]any)
		if !ok || len(m) != 2 || str(m, "format") != "cedar" {
			return false
		}
		t.mandate, ok = stringList(m["policy_set"])
		if !ok || len(t.mandate) == 0 {
			return false
		}
	}
	if v, present := o["narrowing_proof"]; present {
		p, ok := v.(map[string]any)
		if position == 0 || t.mandate == nil || !ok || len(p) != 2 || str(p, "format") == "" || !isCeilingHash(str(p, "hash")) {
			return false
		}
	}
	if v, present := o["act"]; present {
		a, ok := v.(map[string]any)
		if !ok || str(a, "sub") != t.client {
			return false
		}
	}
	if v, present := o["completion_bindable"]; present {
		if _, ok := v.(bool); !ok {
			return false
		}
	}
	_, t.status = o["status"]
	return true
}

func onlyMembers(o map[string]any, names ...string) bool {
	for k := range o {
		if !slices.Contains(names, k) {
			return false
		}
	}
	return true
}

func str(o map[string]any, key string) string {
	s, _ := o[key].(string)
	return s
}

func stringList(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	list := make([]string, len(a))
	for i, item := range a {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		list[i] = s
	}
	return list, true
}

func audience(v any) ([]string, bool) {
	if a, ok := v.(string); ok {
		return []string{a}, a != ""
	}
	a, ok := stringList(v)
	return a, ok && len(a) > 0 && !slices.Contains(a, "")
}

func grants(v any) (map[string][]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) == 0 {
		return nil, false
	}
	g := make(map[string][]string, len(a))
	for _, e := range a {
		o, ok := e.(map[string]any)
		resource := str(o, "resource")
		if !ok || len(o) != 2 || !absoluteURI(resource) || g[resource] != nil {
			return nil, false
		}
		scopes, ok := stringList(o["scopes"])
		if !ok || len(scopes) == 0 {
			return nil, false
		}
		g[resource] = scopes
	}
	return g, true
}

const uriAlpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const uriDigits = "0123456789"
const uriUnreserved = uriAlpha + uriDigits + "-._~"
const uriSubDelims = "!$&'()*+,;="
const uriPChar = uriUnreserved + uriSubDelims + ":%@"

func absoluteURI(s string) bool {
	scheme, rest, ok := strings.Cut(s, ":")
	if !ok || scheme == "" || !strings.ContainsRune(uriAlpha, rune(scheme[0])) ||
		!charsIn(scheme, uriAlpha+uriDigits+"+.-") {
		return false
	}
	// Check percent escapes in every part, including the authority and query.
	if _, err := url.PathUnescape(rest); err != nil {
		return false
	}
	path, query, _ := strings.Cut(rest, "?")
	if authorityPath, ok := strings.CutPrefix(path, "//"); ok {
		end := strings.IndexByte(authorityPath, '/')
		if end == -1 {
			end = len(authorityPath)
		}
		if !uriAuthority(authorityPath[:end]) {
			return false
		}
		path = authorityPath[end:]
	}
	return charsIn(path, uriPChar+"/") && charsIn(query, uriPChar+"/?")
}

func uriAuthority(s string) bool {
	if user, rest, ok := strings.Cut(s, "@"); ok {
		if !charsIn(user, uriUnreserved+uriSubDelims+":%") {
			return false
		}
		s = rest
	}
	if literal, ok := strings.CutPrefix(s, "["); ok {
		literal, port, closed := strings.Cut(literal, "]")
		if !closed || !validIPLiteral(literal) {
			return false
		}
		if port == "" {
			return true
		}
		port, ok := strings.CutPrefix(port, ":")
		return ok && charsIn(port, uriDigits)
	}
	host, port, _ := strings.Cut(s, ":")
	return charsIn(host, uriUnreserved+uriSubDelims+"%") && charsIn(port, uriDigits)
}

func validIPLiteral(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil && addr.Is6() && addr.Zone() == "" {
		return true
	}
	if len(s) < 4 || s[0] != 'v' && s[0] != 'V' {
		return false
	}
	version, address, ok := strings.Cut(s[1:], ".")
	return ok && version != "" && address != "" && charsIn(version, uriDigits+"abcdefABCDEF") &&
		charsIn(address, uriUnreserved+uriSubDelims+":")
}

func charsIn(s, allowed string) bool {
	for _, r := range s {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}

func numericDate(v any) (float64, bool) {
	n, ok := v.(float64)
	return n, ok && math.Abs(n) <= maxSafeInteger
}

func isDigest(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, ok := decodeBase64URL(s)
	return ok && len(b) == 32
}

func isCeilingHash(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
