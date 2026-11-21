// Package pedigree verifies PEDIGREE -01 presentations under an illustrative fixture profile: WPT is assumed, Cedar decisions come from a fixture table, narrowing proofs are not checked, and Token Status List is not resolved.
package pedigree

import (
	"crypto/ed25519"
	"time"
)

// Presentation contains the fields carried by the request.
type Presentation struct {
	// Chain contains the compact tokens in root-to-leaf order.
	Chain []string `json:"chain"`
	// Invocation is the compact invocation or an empty string when absent.
	Invocation string `json:"invocation"`
	// Args contains the argument object received by the service.
	Args map[string]any `json:"args"`
}

// WPTAssumption describes the proof accepted for one presentation.
type WPTAssumption struct {
	// PresentationIndex is the one-based position within the case.
	PresentationIndex int `json:"presentation_index"`
	// HolderKey is the assumed signer of the proof.
	HolderKey ed25519.PublicKey `json:"holder_key"`
	// Fresh records whether the proof is assumed to have passed freshness and replay checks.
	Fresh bool `json:"fresh"`
	// Covers lists the request fields covered by the proof.
	Covers []string `json:"covers"`
}

// ConsentAnswer records a status answer for an anchor, consent and instant.
type ConsentAnswer struct {
	// TrustAnchorKid identifies the configured anchor that supplied the answer.
	TrustAnchorKid string `json:"trust_anchor_kid"`
	// ConsentID identifies the consent whose status was checked.
	ConsentID string `json:"consent_id"`
	// ValidAt is the evaluation instant for which the answer was supplied.
	ValidAt time.Time `json:"valid_at"`
	// Active records whether the consent was active at that instant.
	Active bool `json:"active"`
}

// FixtureDecision binds one policy decision to its request.
type FixtureDecision struct {
	// PolicyID selects the mandate or ceiling under evaluation.
	PolicyID string `json:"policy_id"`
	// Action is the requested action.
	Action string
	// Resource is the absolute URI of the requested resource.
	Resource string
	// Args is the argument object for the decision.
	Args map[string]any
	// Decision records the fixture evaluator's permit, deny or error.
	Decision string
}

// FixturePolicies holds the prevalidated texts, parsed effects and decisions.
type FixturePolicies struct {
	// Mandate is the policy set named "mandate" in the decision table.
	Mandate []string
	// Ceiling is the policy set named by CeilingRef.
	Ceiling []string
	// CeilingRef is the SHA-256 reference of the canonical ceiling document.
	CeilingRef string `json:"ceiling_ref"`
	// Effects maps each recognized policy string to its permit or forbid effect.
	Effects map[string]string
	// Decisions lists the request-specific decisions for the supported sets.
	Decisions []FixtureDecision
}

// Trusted supplies the verifier-side inputs for one call.
type Trusted struct {
	// WPT is the proof assumption for this presentation.
	WPT WPTAssumption
	// Consent contains the consent status answers available to the verifier.
	Consent []ConsentAnswer
	// Policies contains the policy effects and request decisions.
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
	// Check atomically records first use or reports replay or unavailable state.
	Check(audience, jti string, expires time.Time) ReplayState
}

// Config contains the verifier's limits and accepted trust material.
type Config struct {
	// TrustAnchors maps configured root issuer IDs to their keys.
	TrustAnchors map[string]ed25519.PublicKey
	// AcceptedAlgs lists permitted JOSE algorithms.
	AcceptedAlgs []string
	// VerifierIDs lists the audience identifiers this verifier accepts.
	VerifierIDs []string
	// AcceptedCeilings maps ceiling references to canonical document bytes.
	AcceptedCeilings map[string][]byte
	// MaxTokens limits the number of compact tokens in a chain.
	MaxTokens int
	// MaxBytes limits the total compact token bytes in a chain.
	MaxBytes int
	// MaxInvocationLifetime limits the time between invocation issue and expiry.
	MaxInvocationLifetime time.Duration
	// ReplayCache supplies invocation replay state. A nil cache reports Unknown.
	ReplayCache ReplayCache
}

// Result reports the outcome and the ordered list of inputs consumed.
type Result struct {
	// Outcome is a Section 5.6 result or unsupported_fixture_policy.
	Outcome string `json:"outcome"`
	// TrustedInputsUsed lists the fixture inputs reached by verification.
	TrustedInputsUsed []string `json:"trusted_inputs_used"`
}
