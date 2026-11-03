package intel

import (
	"encoding/json"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// RenderSARIF renders source claims as a SARIF 2.1.0 *subset* log — enough for
// standard tooling (code hosts, dashboards) to ingest, not the full spec. Each
// claim becomes one result with a rule id, level, message, and location. The
// claim's status is carried as a property so "declared" vs "adjudicated" isn't
// lost in the SARIF level.
func RenderSARIF(driver string, claims []contracts.SourceClaim) ([]byte, error) {
	results := make([]sarifResult, 0, len(claims))
	for _, c := range claims {
		rule := c.RuleID
		if rule == "" {
			rule = string(c.Kind)
		}
		res := sarifResult{
			RuleID:  rule,
			Level:   sarifLevel(c.Severity),
			Message: sarifMessage{Text: c.Tool + ": " + string(c.Kind)},
			Properties: map[string]string{
				"status":     string(c.Status),
				"confidence": c.Confidence,
			},
		}
		for _, loc := range c.Locations {
			res.Locations = append(res.Locations, sarifLocation{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: loc.Path},
					Region:           sarifRegion{StartLine: loc.StartLine, EndLine: loc.EndLine},
				},
			})
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: driver}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func sarifLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name string `json:"name"`
}
type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
	EndLine   int `json:"endLine,omitempty"`
}
