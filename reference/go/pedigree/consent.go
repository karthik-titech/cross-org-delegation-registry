package pedigree

import "time"

func checkStatus(chain []token, anchor string, answers []ConsentAnswer, at time.Time, used *inputUse) string {
	for _, t := range chain {
		// At this step, a status claim on any chain token returns status_unknown because Token Status List resolution is unavailable.
		if t.status {
			return "status_unknown"
		}
	}
	used.consent = true
	for _, id := range chain[0].consents {
		found := false
		for _, answer := range answers {
			if answer.TrustAnchorKid != anchor || answer.ConsentID != id || !answer.ValidAt.Equal(at) {
				continue
			}
			if !answer.Active {
				return "revoked"
			}
			found = true
		}
		if !found {
			return "status_unknown"
		}
	}
	return ""
}
