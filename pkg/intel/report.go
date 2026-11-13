package intel

import (
	"fmt"
	"sort"
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// RenderMarkdown renders an IntelligenceResult as a human-readable Markdown
// report. It states applicability honestly (a matched advisory is not a
// confirmed exploit) and preserves the dataset snapshot for attribution.
// advisoryUrgency ranks an advisory for report ordering: actively-exploited and
// applicable (3) > affected (2) > unknown (1) > not_affected (0).
func advisoryUrgency(a contracts.AdvisoryRef) int {
	switch {
	case IsKnownExploited(a):
		return 3
	case a.Applicability == "affected":
		return 2
	case a.Applicability == "unknown":
		return 1
	default:
		return 0
	}
}

func RenderMarkdown(res contracts.IntelligenceResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Intelligence Report\n\n")
	fmt.Fprintf(&b, "- result: `%s`\n", orDash(res.ResultID))
	fmt.Fprintf(&b, "- advisory dataset: `%s`\n", orDash(res.SnapshotRef))
	if !res.GeneratedAt.IsZero() {
		fmt.Fprintf(&b, "- generated: %s\n", res.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	b.WriteString("\n")

	if len(res.Advisories) == 0 {
		b.WriteString("No advisories matched the supplied components.\n")
	} else {
		affected, kev := 0, 0
		for _, a := range res.Advisories {
			if a.Applicability == "affected" {
				affected++
			}
			if IsKnownExploited(a) {
				kev++
			}
		}
		if kev > 0 {
			fmt.Fprintf(&b, "## Advisories (%d matched, %d affected, ⚠️ %d actively exploited)\n\n", len(res.Advisories), affected, kev)
		} else {
			fmt.Fprintf(&b, "## Advisories (%d matched, %d affected)\n\n", len(res.Advisories), affected)
		}
		// Surface the most urgent first: actively-exploited, then affected, then
		// the rest — a KEV hit is the "patch now" signal.
		ordered := append([]contracts.AdvisoryRef(nil), res.Advisories...)
		sort.SliceStable(ordered, func(i, j int) bool {
			return advisoryUrgency(ordered[i]) > advisoryUrgency(ordered[j])
		})
		b.WriteString("| advisory | component | applicability | KEV | source |\n")
		b.WriteString("|---|---|---|:--:|---|\n")
		for _, a := range ordered {
			kevCell := ""
			if IsKnownExploited(a) {
				kevCell = "⚠️"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
				a.AdvisoryID, a.Component, a.Applicability, kevCell, orDash(a.Source))
		}
		b.WriteString("\n")
	}

	if len(res.Scores) > 0 {
		b.WriteString("## Scores\n\n| system | value | vector |\n|---|---|---|\n")
		for _, s := range res.Scores {
			fmt.Fprintf(&b, "| %s %s | %.1f | %s |\n", s.System, s.Version, s.Value, orDash(s.Vector))
		}
		b.WriteString("\n")
	}

	b.WriteString("> Applicability reflects advisory-vs-version matching only; it is not a\n")
	b.WriteString("> confirmed exploit. Reachability and exploitability are separate claims.\n")
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
