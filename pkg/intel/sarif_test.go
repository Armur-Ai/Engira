package intel

import (
	"encoding/json"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestRenderSARIFSubset(t *testing.T) {
	claims := []contracts.SourceClaim{
		{Fingerprint: "f1", Tool: "gosec", RuleID: "G401", Kind: contracts.ClaimSourceWeakness,
			Severity: "high", Status: contracts.StatusDeclared,
			Locations: []contracts.CodeLocation{{Path: "a.go", StartLine: 10}}},
		{Fingerprint: "f2", Tool: "x", Kind: contracts.ClaimSecretCandidate, Severity: "low"},
	}
	out, err := RenderSARIF("Engira", claims)
	if err != nil {
		t.Fatal(err)
	}
	// must be valid JSON with the SARIF shape
	var log map[string]any
	if err := json.Unmarshal(out, &log); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Fatalf("version = %v", log["version"])
	}
	runs, _ := log["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(runs))
	}
	run0 := runs[0].(map[string]any)
	results, _ := run0["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	// high -> error level; rule falls back to kind when RuleID empty
	r0 := results[0].(map[string]any)
	if r0["level"] != "error" || r0["ruleId"] != "G401" {
		t.Fatalf("result0 wrong: %v", r0)
	}
	r1 := results[1].(map[string]any)
	if r1["ruleId"] != "secret_candidate" {
		t.Fatalf("ruleId should fall back to kind: %v", r1["ruleId"])
	}
}
