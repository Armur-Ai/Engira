package intel

import (
	"fmt"
	"sort"
	"strings"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// This file makes Engira a consumer of Pentest Swarm's AssessmentSnapshot — the
// cross-product wire form emitted by `pentestswarm scan --format snapshot`.
// Triage projects that graph into a prioritized, reviewer-facing summary:
// what's proven vs. merely modeled, and the most-likely path to each objective.
// It is the intake seam a full case store will later build on; today it is a
// pure, offline projection with no storage.

// PathSummary condenses one AttackPath for triage.
type PathSummary struct {
	Objective     string  `json:"objective"`
	Steps         int     `json:"steps"`
	VerifiedSteps int     `json:"verified_steps"`
	Probability   float64 `json:"probability,omitempty"`
	Complete      bool    `json:"complete"`
}

// TriageSummary is Engira's prioritized view of an AssessmentSnapshot. Verified
// edges/steps are demonstrated; the rest are modeled and need confirmation.
type TriageSummary struct {
	SnapshotID    string         `json:"snapshot_id"`
	Revision      string         `json:"revision,omitempty"`
	Nodes         int            `json:"nodes"`
	Edges         int            `json:"edges"`
	VerifiedEdges int            `json:"verified_edges"`
	Paths         []PathSummary  `json:"paths,omitempty"`
	TakenAt       time.Time      `json:"taken_at"`
	Priority      string         `json:"priority"` // critical|high|medium|low|info
}

// TriageSnapshot projects an AssessmentSnapshot into a TriageSummary. Priority
// is driven by the strongest signal: a verified path to an objective is the top
// of the scale, a modeled-but-complete path is next, and so on down to an empty
// graph.
func TriageSnapshot(s contracts.AssessmentSnapshot) TriageSummary {
	t := TriageSummary{
		SnapshotID: s.SnapshotID,
		Revision:   s.Revision,
		Nodes:      len(s.Nodes),
		Edges:      len(s.Edges),
		TakenAt:    s.TakenAt,
	}
	for _, e := range s.Edges {
		if e.Verified {
			t.VerifiedEdges++
		}
	}
	anyVerifiedPath, anyCompletePath := false, false
	for _, p := range s.Paths {
		ps := PathSummary{Objective: p.Objective, Steps: len(p.Steps), Probability: p.Probability, Complete: p.Complete}
		for _, st := range p.Steps {
			if st.Verified {
				ps.VerifiedSteps++
			}
		}
		if ps.Steps > 0 && ps.VerifiedSteps == ps.Steps {
			anyVerifiedPath = true
		}
		if p.Complete {
			anyCompletePath = true
		}
		t.Paths = append(t.Paths, ps)
	}
	// Most dangerous paths first: verified before modeled, then by probability.
	sort.SliceStable(t.Paths, func(i, j int) bool {
		vi := t.Paths[i].Steps > 0 && t.Paths[i].VerifiedSteps == t.Paths[i].Steps
		vj := t.Paths[j].Steps > 0 && t.Paths[j].VerifiedSteps == t.Paths[j].Steps
		if vi != vj {
			return vi
		}
		return t.Paths[i].Probability > t.Paths[j].Probability
	})

	switch {
	case anyVerifiedPath:
		t.Priority = "critical" // a proven path to the crown jewel
	case anyCompletePath:
		t.Priority = "high" // a full modeled path, not yet demonstrated
	case t.VerifiedEdges > 0:
		t.Priority = "medium" // proven primitives, no full path
	case t.Edges > 0:
		t.Priority = "low"
	default:
		t.Priority = "info"
	}
	return t
}

// RenderTriageMarkdown renders a triage summary as a compact reviewer report.
func RenderTriageMarkdown(t TriageSummary) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Triage — %s\n\n", t.SnapshotID)
	if t.Revision != "" {
		fmt.Fprintf(&b, "_Revision_ `%s`  ·  ", t.Revision)
	}
	fmt.Fprintf(&b, "_Priority_ **%s**  ·  taken %s\n\n", strings.ToUpper(t.Priority), t.TakenAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Graph: **%d** nodes, **%d** edges (%d verified)\n", t.Nodes, t.Edges, t.VerifiedEdges)
	fmt.Fprintf(&b, "- Attack paths: **%d**\n\n", len(t.Paths))
	if len(t.Paths) > 0 {
		b.WriteString("| Objective | Steps | Verified | Probability | Complete |\n")
		b.WriteString("|---|---:|---:|---:|:--:|\n")
		for _, p := range t.Paths {
			done := " "
			if p.Complete {
				done = "✓"
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %.2f | %s |\n", p.Objective, p.Steps, p.VerifiedSteps, p.Probability, done)
		}
	}
	return b.String()
}
