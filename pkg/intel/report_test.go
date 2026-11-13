package intel

import (
	"strings"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestRenderMarkdownWithAdvisories(t *testing.T) {
	res := contracts.IntelligenceResult{
		ResultID:    "r1",
		SnapshotRef: "snap-1",
		Advisories: []contracts.AdvisoryRef{
			{AdvisoryID: "EXAMPLE-0001", Component: "left-pad@1.2.0", Applicability: "affected", Source: "snap-1"},
			{AdvisoryID: "EXAMPLE-0001", Component: "left-pad@1.4.0", Applicability: "not_affected", Source: "snap-1"},
		},
	}
	md := RenderMarkdown(res)
	if !strings.Contains(md, "1 affected") {
		t.Fatalf("summary should count affected: %q", md)
	}
	if !strings.Contains(md, "EXAMPLE-0001") || !strings.Contains(md, "left-pad@1.2.0") {
		t.Fatal("advisory rows missing")
	}
	if !strings.Contains(md, "not a\n> confirmed exploit") {
		t.Fatal("honesty note missing")
	}
}

func TestRenderMarkdownEmpty(t *testing.T) {
	md := RenderMarkdown(contracts.IntelligenceResult{ResultID: "r2"})
	if !strings.Contains(md, "No advisories matched") {
		t.Fatalf("empty report wording missing: %q", md)
	}
}

func TestRenderMarkdown_KEVSurfacedAndOrderedFirst(t *testing.T) {
	res := contracts.IntelligenceResult{
		ResultID: "r2",
		Advisories: []contracts.AdvisoryRef{
			{AdvisoryID: "LOW-1", Component: "a@1", Applicability: "affected", Source: "s"},
			{AdvisoryID: "KEV-1", Component: "b@1", Applicability: "affected", Rationale: kevRationale, Source: "s"},
		},
	}
	md := RenderMarkdown(res)
	if !strings.Contains(md, "actively exploited") {
		t.Errorf("summary should flag actively-exploited advisories:\n%s", md)
	}
	// KEV-1 must be rendered before LOW-1 (urgency ordering).
	if strings.Index(md, "KEV-1") > strings.Index(md, "LOW-1") {
		t.Errorf("known-exploited advisory should sort first:\n%s", md)
	}
}
