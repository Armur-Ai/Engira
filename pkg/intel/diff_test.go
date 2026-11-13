package intel

import (
	"strings"
	"testing"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func snap(id string, edges []contracts.GraphEdge, paths []contracts.AttackPath, nodes ...contracts.GraphNode) contracts.AssessmentSnapshot {
	return contracts.AssessmentSnapshot{
		SnapshotID: id, Nodes: nodes, Edges: edges, Paths: paths, TakenAt: time.Unix(1700000000, 0),
	}
}

func TestDiff_ModeledToProvenIsCriticalRegression(t *testing.T) {
	e := contracts.GraphEdge{ID: "e1", From: "a", To: "b", Kind: "exploits", Exploitability: 0.5}
	base := snap("base", []contracts.GraphEdge{e}, nil)
	ev := e
	ev.Verified = true
	ev.Exploitability = 1.0
	head := snap("head", []contracts.GraphEdge{ev}, nil)

	d := DiffSnapshots(base, head)
	if d.NewlyVerified != 1 {
		t.Fatalf("NewlyVerified = %d, want 1", d.NewlyVerified)
	}
	if d.NewEdges != 0 || d.PersistingEdges != 1 {
		t.Errorf("edge churn wrong: new=%d persisting=%d", d.NewEdges, d.PersistingEdges)
	}
	if !d.Regressed || d.Priority != "critical" {
		t.Errorf("a modeled→proven edge must be a critical regression, got regressed=%v prio=%s", d.Regressed, d.Priority)
	}
	if len(d.Edges) == 0 || !d.Edges[0].NewlyVerified {
		t.Error("the newly-verified edge must sort first")
	}
	if delta := d.Edges[0].ExploitabilityDelta; delta != 0.5 {
		t.Errorf("exploitability delta = %v, want 0.5", delta)
	}
}

func TestDiff_NewAndFixedEdges(t *testing.T) {
	shared := contracts.GraphEdge{ID: "shared", From: "a", To: "b", Kind: "reaches"}
	gone := contracts.GraphEdge{ID: "gone", From: "b", To: "c", Kind: "leaks"}
	fresh := contracts.GraphEdge{ID: "fresh", From: "c", To: "d", Kind: "escalates_to"}

	base := snap("base", []contracts.GraphEdge{shared, gone}, nil)
	head := snap("head", []contracts.GraphEdge{shared, fresh}, nil)

	d := DiffSnapshots(base, head)
	if d.NewEdges != 1 || d.FixedEdges != 1 || d.PersistingEdges != 1 {
		t.Fatalf("got new=%d fixed=%d persisting=%d", d.NewEdges, d.FixedEdges, d.PersistingEdges)
	}
	if !d.Regressed || !d.Improved {
		t.Errorf("a new edge + a fix should be both regressed and improved, got r=%v i=%v", d.Regressed, d.Improved)
	}
	if d.Priority != "high" {
		t.Errorf("new modeled edge (no proof) should be high, got %s", d.Priority)
	}
}

func TestDiff_NewlyProvenObjective(t *testing.T) {
	step := contracts.PathStep{EdgeID: "e1", Verified: true}
	provenPath := contracts.AttackPath{Objective: "admin", Steps: []contracts.PathStep{step}, Complete: true}
	modeledStep := contracts.PathStep{EdgeID: "e1", Verified: false}
	modeledPath := contracts.AttackPath{Objective: "admin", Steps: []contracts.PathStep{modeledStep}, Complete: true}

	e := contracts.GraphEdge{ID: "e1", From: "a", To: "admin", Kind: "escalates_to"}
	base := snap("base", []contracts.GraphEdge{e}, []contracts.AttackPath{modeledPath})
	ev := e
	ev.Verified = true
	head := snap("head", []contracts.GraphEdge{ev}, []contracts.AttackPath{provenPath})

	d := DiffSnapshots(base, head)
	if len(d.NewlyProvenObjectives) != 1 || d.NewlyProvenObjectives[0] != "admin" {
		t.Fatalf("expected 'admin' newly proven, got %v", d.NewlyProvenObjectives)
	}
	if d.Priority != "critical" {
		t.Errorf("newly proven objective must be critical, got %s", d.Priority)
	}
}

func TestDiff_OnlyFixesImprove(t *testing.T) {
	gone := contracts.GraphEdge{ID: "gone", From: "a", To: "b", Kind: "exploits"}
	base := snap("base", []contracts.GraphEdge{gone}, nil)
	head := snap("head", nil, nil)

	d := DiffSnapshots(base, head)
	if d.Regressed {
		t.Error("removing the only edge must not count as a regression")
	}
	if !d.Improved || d.Priority != "low" {
		t.Errorf("pure improvement should be improved/low, got improved=%v prio=%s", d.Improved, d.Priority)
	}
}

func TestDiff_KeyFallbackWithoutID(t *testing.T) {
	// Edges with no ID key on From/To/Kind.
	e := contracts.GraphEdge{From: "x", To: "y", Kind: "reaches"}
	d := DiffSnapshots(snap("b", []contracts.GraphEdge{e}, nil), snap("h", []contracts.GraphEdge{e}, nil))
	if d.PersistingEdges != 1 {
		t.Errorf("same keyless edge should persist, got %+v", d)
	}
}

func TestRenderDiffMarkdown_Readable(t *testing.T) {
	e := contracts.GraphEdge{ID: "e1", From: "a", To: "b", Kind: "exploits"}
	ev := e
	ev.Verified = true
	d := DiffSnapshots(snap("base", []contracts.GraphEdge{e}, nil), snap("head", []contracts.GraphEdge{ev}, nil))
	md := RenderDiffMarkdown(d)
	if !strings.Contains(md, "REGRESSED") || !strings.Contains(md, "now proven") {
		t.Errorf("markdown missing expected regression signals:\n%s", md)
	}
}
