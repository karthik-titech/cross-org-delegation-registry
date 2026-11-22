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
			used.record(policyLabel)
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
	}
	for i, child := range chain[1:] {
		parent := chain[i]
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
	used.record(policyLabel)
	decisions, ok := validateDecisions(p.Decisions)
	if !ok {
		return fixtureStop
	}
	for _, t := range chain {
		if t.mandate == nil {
			continue
		}
		if !containsAll(p.Mandate, t.mandate) || !containsAll(t.mandate, p.Mandate) {
			return fixtureStop
		}
		switch decisions.lookup("mandate", inv, args) {
		case "permit":
		case fixtureStop:
			return fixtureStop
		default:
			return "mandate_denied"
		}
	}
	if leaf.ceiling != p.CeilingRef {
		return fixtureStop
	}
	pinned, err := serializeJCS(p.Ceiling)
	if err != nil || !bytes.Equal(ceiling, pinned) || ceilingDigest(ceiling) != leaf.ceiling {
		return "ceiling_denied"
	}
	switch decisions.lookup(leaf.ceiling, inv, args) {
	case "permit":
		return "permit"
	case fixtureStop:
		return fixtureStop
	default:
		return "ceiling_denied"
	}
}

type decisionKey struct {
	policyID, action, resource, args string
}

type decisionTable map[decisionKey]string

func validateDecisions(rows []FixtureDecision) (decisionTable, bool) {
	decisions := make(decisionTable, len(rows))
	for _, row := range rows {
		if row.Args == nil || (row.Decision != "permit" && row.Decision != "deny") {
			return nil, false
		}
		rowArgs, err := serializeArgsJCS(row.Args)
		if err != nil {
			return nil, false
		}
		key := decisionKey{row.PolicyID, row.Action, row.Resource, string(rowArgs)}
		if prior, ok := decisions[key]; ok && prior != row.Decision {
			return nil, false
		}
		decisions[key] = row.Decision
	}
	return decisions, true
}

func (d decisionTable) lookup(id string, inv invocation, args []byte) string {
	if decision, ok := d[decisionKey{id, inv.action, inv.resource, string(args)}]; ok {
		return decision
	}
	return fixtureStop
}

func ceilingDigest(data []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(data))
}
