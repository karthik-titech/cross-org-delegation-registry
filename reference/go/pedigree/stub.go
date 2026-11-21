// Package pedigree verifies PEDIGREE presentations.
package pedigree

import (
	"crypto/ed25519"
	"errors"
	"time"
)

// Presentation contains the fields carried by the request.
type Presentation struct {
	Chain      []string
	Invocation string
	Args       map[string]any
}

// WPTAssumption describes the proof accepted for one presentation.
type WPTAssumption struct {
	PresentationIndex int               `json:"presentation_index"`
	HolderKey         ed25519.PublicKey `json:"holder_key"`
	Fresh             bool
	Covers            []string
}

// ConsentAnswer records a status answer for an anchor, consent and instant.
type ConsentAnswer struct {
	TrustAnchorKid string    `json:"trust_anchor_kid"`
	ConsentID      string    `json:"consent_id"`
	ValidAt        time.Time `json:"valid_at"`
	Active         bool
}

// FixtureDecision binds one policy decision to its request.
type FixtureDecision struct {
	PolicyID         string `json:"policy_id"`
	Action, Resource string
	Args             map[string]any
	Decision         string
}

// FixturePolicies holds the prevalidated texts, parsed effects and decisions.
type FixturePolicies struct {
	Mandate, Ceiling []string
	CeilingRef       string `json:"ceiling_ref"`
	Effects          map[string]string
	Decisions        []FixtureDecision
}

// Trusted supplies the verifier-side inputs for one call.
type Trusted struct {
	WPT      WPTAssumption
	Consent  []ConsentAnswer
	Policies FixturePolicies
}

// ReplayState describes the result of recording an invocation.
type ReplayState int

const (
	// Unknown means the cache cannot rule out a replay.
	Unknown ReplayState = iota
	// FirstUse means the invocation was recorded for the first time.
	FirstUse
	// Replay means the invocation has already been recorded.
	Replay
)

// ReplayCache records an invocation ID for an audience until expiry.
type ReplayCache interface {
	Check(audience, jti string, expires time.Time) ReplayState
}

// Config contains the verifier's limits and accepted trust material.
type Config struct {
	TrustAnchors              map[string]ed25519.PublicKey
	AcceptedAlgs, VerifierIDs []string
	AcceptedCeilings          map[string][]byte
	MaxTokens, MaxBytes       int
	MaxInvocationLifetime     time.Duration
	ReplayCache               ReplayCache
}

// Result reports the outcome and the ordered list of inputs consumed.
type Result struct {
	Outcome           string
	TrustedInputsUsed []string `json:"trusted_inputs_used"`
}

// Verify evaluates one presentation at the supplied instant.
func Verify(p Presentation, t Trusted, cfg Config, at time.Time) Result {
	return Result{Outcome: "unimplemented"}
}

func serializeJCS(v any) ([]byte, error) { return nil, errors.New("unimplemented") }

// parseToken checks step 1 only. An empty outcome indicates acceptance.
func parseToken(compact string, depth int) string { return "unimplemented" }
func publicJWKX(pub ed25519.PublicKey) string     { return "unimplemented" }
func thumbprint(pub ed25519.PublicKey) string     { return "unimplemented" }
