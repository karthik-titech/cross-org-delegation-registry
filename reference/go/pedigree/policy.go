package pedigree

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
)

func checkAttenuation(chain []token, policies FixturePolicies, used *inputUse) string {
	for _, t := range chain {
		for _, text := range t.mandate {
			used.policy = true
			effect := policies.Effects[text]
			if effect != "permit" && effect != "forbid" {
				return fixtureStop
			}
		}
	}
	for i, child := range chain[1:] {
		parent := chain[i]
		for resource, scopes := range child.grants {
			if !containsAll(parent.grants[resource], scopes) {
				return "scope_widened"
			}
		}
		if parent.mandate != nil && !mandateNarrows(parent.mandate, child.mandate, policies.Effects) {
			return "mandate_not_narrower"
		}
	}
	return ""
}

func containsAll(have, need []string) bool {
	for _, v := range need {
		if !slices.Contains(have, v) {
			return false
		}
	}
	return true
}

func mandateNarrows(parent, child []string, effects map[string]string) bool {
	if child == nil {
		return false
	}
	for _, text := range child {
		if effects[text] == "permit" && !slices.Contains(parent, text) {
			return false
		}
	}
	for _, text := range parent {
		if effects[text] == "forbid" && !slices.Contains(child, text) {
			return false
		}
	}
	return true
}

func decide(chain []token, inv invocation, args, ceiling []byte, p FixturePolicies, used *inputUse) string {
	leaf := chain[len(chain)-1]
	if !slices.Contains(leaf.grants[inv.resource], inv.action) {
		return "scope_not_granted"
	}
	for _, t := range chain {
		if t.mandate == nil {
			continue
		}
		used.policy = true
		if !containsAll(p.Mandate, t.mandate) || !containsAll(t.mandate, p.Mandate) {
			return fixtureStop
		}
		switch p.decision("mandate", inv, args) {
		case "permit":
		case fixtureStop:
			return fixtureStop
		default:
			return "mandate_denied"
		}
	}
	used.policy = true
	if leaf.ceiling != p.CeilingRef {
		return fixtureStop
	}
	pinned, err := serializeJCS(p.Ceiling)
	if err != nil || !bytes.Equal(ceiling, pinned) || ceilingDigest(ceiling) != leaf.ceiling {
		return "ceiling_denied"
	}
	switch p.decision(leaf.ceiling, inv, args) {
	case "permit":
		return "permit"
	case fixtureStop:
		return fixtureStop
	default:
		return "ceiling_denied"
	}
}

func (p FixturePolicies) decision(id string, inv invocation, args []byte) string {
	var decision string
	for _, row := range p.Decisions {
		if row.PolicyID != id || row.Action != inv.action || row.Resource != inv.resource {
			continue
		}
		rowArgs, err := serializeJCS(row.Args)
		if err != nil || !bytes.Equal(rowArgs, args) {
			continue
		}
		if row.Decision != "permit" || decision == "deny" {
			decision = "deny"
		} else {
			decision = "permit"
		}
	}
	if decision == "" {
		return fixtureStop
	}
	return decision
}

func ceilingDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}
