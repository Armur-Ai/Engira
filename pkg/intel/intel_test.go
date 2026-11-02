package intel

import (
	"context"
	"testing"

	contracts "github.com/Armur-Ai/armur-contracts"
)

func TestEnrichWithStubIsHonestlyEmpty(t *testing.T) {
	e := New(OfflineStubMatcher{})
	res, err := e.Enrich(context.Background(), contracts.DependencyInventory{Parser: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if res.SnapshotRef != "stub-empty" {
		t.Fatalf("snapshot ref = %q", res.SnapshotRef)
	}
	if len(res.Advisories) != 0 {
		t.Fatalf("stub must match nothing, got %d", len(res.Advisories))
	}
	if res.ResultID == "" {
		t.Fatal("result id not set")
	}
}

func TestEnrichRequiresMatcher(t *testing.T) {
	e := New(nil)
	if _, err := e.Enrich(context.Background(), contracts.DependencyInventory{}); err == nil {
		t.Fatal("expected error with no matcher")
	}
}
