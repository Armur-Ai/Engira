package intel

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func inv(deps ...contracts.Dependency) contracts.DependencyInventory {
	return contracts.DependencyInventory{Parser: "test", Components: deps}
}

func TestMatcherApplicability(t *testing.T) {
	m := NewListMatcher("example-snap", ExampleAdvisories())
	refs, err := m.Match(context.Background(), inv(
		contracts.Dependency{Ecosystem: "npm", Name: "left-pad", Version: "1.2.0"}, // affected
		contracts.Dependency{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"}, // not affected (== fixed)
		contracts.Dependency{Ecosystem: "npm", Name: "safe-pkg", Version: "1.0.0"}, // no advisory
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("want 2 advisory refs, got %d: %+v", len(refs), refs)
	}
	got := map[string]string{}
	for _, r := range refs {
		got[r.Component] = r.Applicability
	}
	if got["left-pad@1.2.0"] != "affected" {
		t.Fatalf("1.2.0 should be affected: %v", got)
	}
	if got["left-pad@1.3.0"] != "not_affected" {
		t.Fatalf("1.3.0 should be not_affected: %v", got)
	}
}

func TestUnparseableVersionIsUnknown(t *testing.T) {
	m := NewListMatcher("s", ExampleAdvisories())
	refs, _ := m.Match(context.Background(), inv(
		contracts.Dependency{Ecosystem: "npm", Name: "left-pad", Version: "weird-build"},
	))
	if len(refs) != 1 || refs[0].Applicability != "unknown" {
		t.Fatalf("unparseable version should be unknown, got %+v", refs)
	}
}

func TestEngineEnrichWithListMatcher(t *testing.T) {
	e := New(NewListMatcher("snap-1", ExampleAdvisories()))
	res, err := e.Enrich(context.Background(), inv(
		contracts.Dependency{Ecosystem: "go", Name: "example.com/vuln", Version: "1.5.0"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if res.SnapshotRef != "snap-1" || len(res.Advisories) != 1 || res.Advisories[0].Applicability != "affected" {
		t.Fatalf("enrich via list matcher wrong: %+v", res)
	}
}

func TestMatch_FlagsKnownExploitedWhenAffected(t *testing.T) {
	m := NewListMatcher("snap-kev", []Advisory{
		{ID: "KEV-1", Ecosystem: "go", Package: "example.com/vuln", FixedIn: "2.0.0", KnownExploited: true},
	})
	inv := contracts.DependencyInventory{Components: []contracts.Dependency{
		{Name: "example.com/vuln", Version: "1.0.0", Ecosystem: "go"}, // affected
	}}
	refs, err := m.Match(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Applicability != "affected" {
		t.Fatalf("expected one affected ref, got %+v", refs)
	}
	if !IsKnownExploited(refs[0]) {
		t.Errorf("affected known-exploited advisory should be flagged KEV: %q", refs[0].Rationale)
	}
}

func TestMatch_NoKEVFlagWhenNotAffected(t *testing.T) {
	m := NewListMatcher("snap-kev", []Advisory{
		{ID: "KEV-1", Ecosystem: "go", Package: "example.com/vuln", FixedIn: "2.0.0", KnownExploited: true},
	})
	inv := contracts.DependencyInventory{Components: []contracts.Dependency{
		{Name: "example.com/vuln", Version: "2.1.0", Ecosystem: "go"}, // patched
	}}
	refs, _ := m.Match(context.Background(), inv)
	if len(refs) != 1 || refs[0].Applicability != "not_affected" {
		t.Fatalf("expected one not_affected ref, got %+v", refs)
	}
	if IsKnownExploited(refs[0]) {
		t.Error("a not-affected version must not be flagged as actively exploited")
	}
}
