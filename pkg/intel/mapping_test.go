package intel

import (
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestMapSourceClaims(t *testing.T) {
	claims := []contracts.SourceClaim{
		{Fingerprint: "f1", Tool: "gosec", ProposedCWE: []string{"CWE-89", "327"}},
		{Fingerprint: "f2", Tool: "x", ProposedCWE: []string{"not-a-cwe"}},
		{Fingerprint: "f3", Tool: "y"}, // no CWE
	}
	m := MapSourceClaims(claims)
	if len(m) != 2 {
		t.Fatalf("want 2 mappings (CWE-89, 327->CWE-327), got %d: %+v", len(m), m)
	}
	ids := map[string]bool{}
	for _, x := range m {
		if x.System != "CWE" || x.ReviewState != "proposed" {
			t.Fatalf("mapping meta wrong: %+v", x)
		}
		ids[x.Identifier] = true
	}
	if !ids["CWE-89"] || !ids["CWE-327"] {
		t.Fatalf("normalized ids wrong: %v", ids)
	}
}

func TestNormalizeCWE(t *testing.T) {
	cases := map[string]string{"CWE-89": "CWE-89", "89": "CWE-89", "cwe-327": "CWE-327", "CWE 22": "CWE-22", "sql": "", "": ""}
	for in, want := range cases {
		if got := normalizeCWE(in); got != want {
			t.Fatalf("normalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
}
