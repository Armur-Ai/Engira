// Package intel is Engira's vulnerability-intelligence engine: it is the suite's
// single authoritative advisory matcher. Given a dependency inventory and a
// pinned intelligence snapshot it produces a contracts.IntelligenceResult
// (advisory applicability + standards mapping + deterministic scoring). Other
// products (e.g. Trishul) delegate advisory interpretation here rather than
// reimplementing matching.
//
// Status: scaffold. The Matcher/Scorer seams are real and tested; the concrete
// advisory dataset + CVSS calculator are implemented in migration phase P3. A
// matched advisory is never an exploited finding — applicability + trust are
// explicit.
package intel

import (
	"context"
	"fmt"
	"time"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// Matcher resolves advisory applicability for a dependency inventory against a
// pinned snapshot. An empty result with notes is honest; silence is not safety.
type Matcher interface {
	SnapshotRef() string
	Match(ctx context.Context, inv contracts.DependencyInventory) ([]contracts.AdvisoryRef, error)
}

// Engine assembles an IntelligenceResult from a Matcher (and, later, a scorer).
type Engine struct {
	Matcher Matcher
}

// New builds an Engine from a Matcher.
func New(m Matcher) *Engine { return &Engine{Matcher: m} }

// Enrich matches advisories for the inventory and assembles the result.
func (e *Engine) Enrich(ctx context.Context, inv contracts.DependencyInventory) (contracts.IntelligenceResult, error) {
	res := contracts.IntelligenceResult{
		ResultID:    fmt.Sprintf("intel-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
	}
	if e.Matcher == nil {
		return res, fmt.Errorf("intel: no matcher configured")
	}
	res.SnapshotRef = e.Matcher.SnapshotRef()
	advs, err := e.Matcher.Match(ctx, inv)
	if err != nil {
		return res, err
	}
	res.Advisories = advs
	return res, nil
}

// OfflineStubMatcher is a placeholder that matches nothing and says so. It lets
// the standalone CLI run deterministically offline until the real pinned
// advisory dataset lands (P3).
type OfflineStubMatcher struct{}

func (OfflineStubMatcher) SnapshotRef() string { return "stub-empty" }
func (OfflineStubMatcher) Match(context.Context, contracts.DependencyInventory) ([]contracts.AdvisoryRef, error) {
	return nil, nil
}
