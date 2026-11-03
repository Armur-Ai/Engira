package intel

import (
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// MapSourceClaims emits CWE StandardMappings for source claims that carry a
// proposed CWE. Engira owns standards mapping; the mappings are marked
// "proposed" (review status) and attributed, never silently authoritative. A
// claim may yield zero or several mappings.
func MapSourceClaims(claims []contracts.SourceClaim) []contracts.StandardMapping {
	var out []contracts.StandardMapping
	for _, c := range claims {
		for _, cwe := range c.ProposedCWE {
			id := normalizeCWE(cwe)
			if id == "" {
				continue
			}
			out = append(out, contracts.StandardMapping{
				Subject:     c.Fingerprint,
				System:      "CWE",
				Identifier:  id,
				Rationale:   "proposed by " + c.Tool,
				ReviewState: "proposed",
				Trust:       contracts.TrustAsserted,
			})
		}
	}
	return out
}

// normalizeCWE canonicalizes a CWE reference to the form "CWE-<n>".
func normalizeCWE(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	up := strings.ToUpper(s)
	if strings.HasPrefix(up, "CWE-") {
		return up
	}
	// bare number or "CWE 89" style
	digits := strings.TrimSpace(strings.TrimPrefix(up, "CWE"))
	digits = strings.TrimLeft(digits, " -")
	if digits == "" {
		return ""
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "" // not a clean CWE id; skip rather than guess
		}
	}
	return "CWE-" + digits
}
