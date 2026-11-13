package intel

import (
	"fmt"
	"sort"
	"strings"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// This file makes Engira a consumer of TWO AssessmentSnapshots — a baseline and
// a later run — and reports how the security posture moved between them: which
// weaknesses are new, which were fixed, which persist, and (the signal that
// matters most) which transitions went from merely-modeled to proven. This is
// the "diffing over time / open→closed lifecycle" view — a pure, offline
// projection with no storage.

// EdgeStatus is an edge's lifecycle between the baseline and the head snapshot.
type EdgeStatus string

const (
	EdgeNew        EdgeStatus = "new"        // present in head, absent from baseline
	EdgeFixed      EdgeStatus = "fixed"      // present in baseline, gone from head
	EdgePersisting EdgeStatus = "persisting" // present in both
)

// EdgeDelta describes one transition's change across the two snapshots.
type EdgeDelta struct {
	Key                 string     `json:"key"`
	From                string     `json:"from"`
	To                  string     `json:"to"`
	Kind                string     `json:"kind"`
	Status              EdgeStatus `json:"status"`
	NewlyVerified       bool       `json:"newly_verified,omitempty"`       // became proven since the baseline — an escalation
	NoLongerVerified    bool       `json:"no_longer_verified,omitempty"`   // was proven, now only modeled
	ExploitabilityDelta float64    `json:"exploitability_delta,omitempty"` // head − baseline, for persisting edges
}

// SnapshotDiff is Engira's posture-movement view between two snapshots.
type SnapshotDiff struct {
	BaseID       string    `json:"base_id"`
	HeadID       string    `json:"head_id"`
	BaseRevision string    `json:"base_revision,omitempty"`
	HeadRevision string    `json:"head_revision,omitempty"`
	BaseTakenAt  time.Time `json:"base_taken_at"`
	HeadTakenAt  time.Time `json:"head_taken_at"`

	NewEdges        int `json:"new_edges"`
	FixedEdges      int `json:"fixed_edges"`
	PersistingEdges int `json:"persisting_edges"`
	NewlyVerified   int `json:"newly_verified"` // persisting-or-new edges proven since baseline
	NewlyFixed      int `json:"newly_fixed"`    // same as FixedEdges, named for the report

	NewNodes     int `json:"new_nodes"`
	RemovedNodes int `json:"removed_nodes"`

	// Objectives that gained a fully-proven path (a regression) vs. objectives
	// that lost every path (an improvement).
	NewlyProvenObjectives []string `json:"newly_proven_objectives,omitempty"`
	NewlySafeObjectives   []string `json:"newly_safe_objectives,omitempty"`

	Edges []EdgeDelta `json:"edges"` // regressions first, then new, persisting, fixed

	Regressed bool   `json:"regressed"` // posture got worse (new exposure appeared)
	Improved  bool   `json:"improved"`  // posture got better (exposure removed)
	Priority  string `json:"priority"`  // worst new exposure: critical|high|medium|low|info
}

func edgeKey(e contracts.GraphEdge) string {
	if e.ID != "" {
		return e.ID
	}
	return e.From + "\x00" + e.To + "\x00" + e.Kind
}

// objectivesWithProvenPath returns the set of objectives reachable by at least
// one fully-verified, complete path in the snapshot.
func objectivesWithProvenPath(s contracts.AssessmentSnapshot) map[string]bool {
	out := map[string]bool{}
	for _, p := range s.Paths {
		if !p.Complete || len(p.Steps) == 0 {
			continue
		}
		proven := true
		for _, st := range p.Steps {
			if !st.Verified {
				proven = false
				break
			}
		}
		if proven {
			out[p.Objective] = true
		}
	}
	return out
}

// objectivesWithAnyPath returns the set of objectives that have at least one
// (modeled or proven) path in the snapshot.
func objectivesWithAnyPath(s contracts.AssessmentSnapshot) map[string]bool {
	out := map[string]bool{}
	for _, p := range s.Paths {
		out[p.Objective] = true
	}
	return out
}

// DiffSnapshots compares a baseline snapshot against a later head snapshot and
// reports how the posture moved. The most important signal is NewlyVerified: a
// transition that went from modeled to proven is a genuine regression even if
// the edge already existed.
func DiffSnapshots(base, head contracts.AssessmentSnapshot) SnapshotDiff {
	d := SnapshotDiff{
		BaseID: base.SnapshotID, HeadID: head.SnapshotID,
		BaseRevision: base.Revision, HeadRevision: head.Revision,
		BaseTakenAt: base.TakenAt, HeadTakenAt: head.TakenAt,
	}

	baseEdges := make(map[string]contracts.GraphEdge, len(base.Edges))
	for _, e := range base.Edges {
		baseEdges[edgeKey(e)] = e
	}
	headEdges := make(map[string]contracts.GraphEdge, len(head.Edges))
	for _, e := range head.Edges {
		headEdges[edgeKey(e)] = e
	}

	for k, he := range headEdges {
		be, existed := baseEdges[k]
		delta := EdgeDelta{Key: k, From: he.From, To: he.To, Kind: he.Kind}
		if !existed {
			delta.Status = EdgeNew
			d.NewEdges++
			if he.Verified {
				delta.NewlyVerified = true
				d.NewlyVerified++
			}
		} else {
			delta.Status = EdgePersisting
			d.PersistingEdges++
			delta.ExploitabilityDelta = he.Exploitability - be.Exploitability
			if he.Verified && !be.Verified {
				delta.NewlyVerified = true
				d.NewlyVerified++
			}
			if !he.Verified && be.Verified {
				delta.NoLongerVerified = true
			}
		}
		d.Edges = append(d.Edges, delta)
	}
	for k, be := range baseEdges {
		if _, ok := headEdges[k]; ok {
			continue
		}
		d.FixedEdges++
		d.Edges = append(d.Edges, EdgeDelta{Key: k, From: be.From, To: be.To, Kind: be.Kind, Status: EdgeFixed})
	}
	d.NewlyFixed = d.FixedEdges

	// Node churn.
	baseNodes := map[string]bool{}
	for _, n := range base.Nodes {
		baseNodes[n.ID] = true
	}
	headNodes := map[string]bool{}
	for _, n := range head.Nodes {
		headNodes[n.ID] = true
	}
	for id := range headNodes {
		if !baseNodes[id] {
			d.NewNodes++
		}
	}
	for id := range baseNodes {
		if !headNodes[id] {
			d.RemovedNodes++
		}
	}

	// Objective-level movement.
	baseProven := objectivesWithProvenPath(base)
	headProven := objectivesWithProvenPath(head)
	for obj := range headProven {
		if !baseProven[obj] {
			d.NewlyProvenObjectives = append(d.NewlyProvenObjectives, obj)
		}
	}
	baseAny := objectivesWithAnyPath(base)
	headAny := objectivesWithAnyPath(head)
	for obj := range baseAny {
		if !headAny[obj] {
			d.NewlySafeObjectives = append(d.NewlySafeObjectives, obj)
		}
	}
	sort.Strings(d.NewlyProvenObjectives)
	sort.Strings(d.NewlySafeObjectives)

	// Order edges so a reviewer sees the regressions first.
	rank := func(e EdgeDelta) int {
		switch {
		case e.NewlyVerified:
			return 0
		case e.Status == EdgeNew:
			return 1
		case e.NoLongerVerified:
			return 2
		case e.Status == EdgePersisting:
			return 3
		default: // fixed
			return 4
		}
	}
	sort.SliceStable(d.Edges, func(i, j int) bool {
		ri, rj := rank(d.Edges[i]), rank(d.Edges[j])
		if ri != rj {
			return ri < rj
		}
		return d.Edges[i].Key < d.Edges[j].Key
	})

	d.Regressed = d.NewlyVerified > 0 || d.NewEdges > 0 || len(d.NewlyProvenObjectives) > 0
	d.Improved = d.FixedEdges > 0 || len(d.NewlySafeObjectives) > 0

	switch {
	case len(d.NewlyProvenObjectives) > 0 || d.NewlyVerified > 0:
		d.Priority = "critical" // a new proven attack appeared
	case d.NewEdges > 0:
		d.Priority = "high" // new modeled exposure
	case d.PersistingEdges > 0:
		d.Priority = "medium" // same exposure carried forward
	case d.Improved:
		d.Priority = "low" // only improvements
	default:
		d.Priority = "info"
	}
	return d
}

// RenderDiffMarkdown renders a snapshot diff as a compact reviewer report.
func RenderDiffMarkdown(d SnapshotDiff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Posture diff — %s → %s\n\n", shortOr(d.BaseID, "baseline"), shortOr(d.HeadID, "head"))

	verdict := "no net change"
	switch {
	case d.Regressed && d.Improved:
		verdict = "MIXED — new exposure and fixes"
	case d.Regressed:
		verdict = "REGRESSED — posture got worse"
	case d.Improved:
		verdict = "IMPROVED — exposure reduced"
	}
	fmt.Fprintf(&b, "_Verdict_ **%s**  ·  _Priority_ **%s**\n\n", verdict, strings.ToUpper(d.Priority))
	if !d.BaseTakenAt.IsZero() && !d.HeadTakenAt.IsZero() {
		fmt.Fprintf(&b, "_Baseline_ %s → _Head_ %s\n\n",
			d.BaseTakenAt.Format(time.RFC3339), d.HeadTakenAt.Format(time.RFC3339))
	}

	fmt.Fprintf(&b, "- 🔴 **%d** newly proven (modeled→verified)\n", d.NewlyVerified)
	fmt.Fprintf(&b, "- 🟠 **%d** new edges  ·  🟢 **%d** fixed  ·  ⚪ **%d** persisting\n", d.NewEdges, d.FixedEdges, d.PersistingEdges)
	fmt.Fprintf(&b, "- Nodes: **+%d** / **−%d**\n", d.NewNodes, d.RemovedNodes)
	if len(d.NewlyProvenObjectives) > 0 {
		fmt.Fprintf(&b, "- ⚠️ Newly reachable objectives (proven): %s\n", strings.Join(d.NewlyProvenObjectives, ", "))
	}
	if len(d.NewlySafeObjectives) > 0 {
		fmt.Fprintf(&b, "- ✅ Objectives no longer reachable: %s\n", strings.Join(d.NewlySafeObjectives, ", "))
	}
	b.WriteString("\n")

	// Only surface the edges that moved — persisting-unchanged edges are noise.
	var moved []EdgeDelta
	for _, e := range d.Edges {
		if e.Status == EdgePersisting && !e.NewlyVerified && !e.NoLongerVerified && e.ExploitabilityDelta == 0 {
			continue
		}
		moved = append(moved, e)
	}
	if len(moved) > 0 {
		b.WriteString("| Change | Transition | Kind | Note |\n|---|---|---|---|\n")
		for _, e := range moved {
			note := ""
			switch {
			case e.NewlyVerified:
				note = "now proven"
			case e.NoLongerVerified:
				note = "no longer proven"
			case e.ExploitabilityDelta > 0:
				note = fmt.Sprintf("exploitability +%.2f", e.ExploitabilityDelta)
			case e.ExploitabilityDelta < 0:
				note = fmt.Sprintf("exploitability %.2f", e.ExploitabilityDelta)
			}
			fmt.Fprintf(&b, "| %s | %s → %s | %s | %s |\n", e.Status, e.From, e.To, e.Kind, note)
		}
	}
	return b.String()
}

func shortOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
