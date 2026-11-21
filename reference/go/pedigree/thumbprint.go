package pedigree

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

var base64URL = base64.RawURLEncoding.Strict()

func publicJWKX(pub ed25519.PublicKey) string {
	return base64URL.EncodeToString(pub)
}

func publicJWK(pub ed25519.PublicKey) map[string]any {
	return map[string]any{"crv": "Ed25519", "kty": "OKP", "x": publicJWKX(pub)}
}

func thumbprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return ""
	}
	// RFC 7638 uses only the required OKP members, in lexicographic order.
	return sha256URL([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + publicJWKX(pub) + `"}`))
}

func sha256URL(data []byte) string {
	hash := sha256.Sum256(data)
	return base64URL.EncodeToString(hash[:])
}

func decodeBase64URL(s string) ([]byte, bool) {
	b, err := base64URL.DecodeString(s)
	return b, err == nil && base64URL.EncodeToString(b) == s
}
