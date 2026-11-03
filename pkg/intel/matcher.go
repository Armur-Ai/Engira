package intel

import (
	"context"
	"strconv"
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// Advisory is one pinned advisory record: a package in an ecosystem is affected
// when its resolved version is below FixedIn. This is the deterministic matching
// unit; the matching logic here is real, the bundled data set is a small example
// (a continuously-updated, verified feed is the commercial tier).
type Advisory struct {
	ID        string // e.g. CVE / GHSA id
	Ecosystem string // e.g. "npm", "go", "pypi"
	Package   string
	FixedIn   string // first non-vulnerable version (semver); "" = all versions affected
	CVSS      string // optional vector
}

// ListMatcher matches a dependency inventory against a pinned advisory list.
type ListMatcher struct {
	snapshot   string
	advisories []Advisory
}

// NewListMatcher builds a matcher over a pinned advisory set with a snapshot ref
// (so results are reproducible and attributable to a dataset version).
func NewListMatcher(snapshotRef string, advs []Advisory) *ListMatcher {
	return &ListMatcher{snapshot: snapshotRef, advisories: advs}
}

func (m *ListMatcher) SnapshotRef() string { return m.snapshot }

// Match returns an AdvisoryRef per (component, advisory) pair for the components
// in the inventory, with explicit applicability.
func (m *ListMatcher) Match(_ context.Context, inv contracts.DependencyInventory) ([]contracts.AdvisoryRef, error) {
	var out []contracts.AdvisoryRef
	for _, dep := range inv.Components {
		for _, a := range m.advisories {
			if !strings.EqualFold(a.Ecosystem, dep.Ecosystem) || !strings.EqualFold(a.Package, dep.Name) {
				continue
			}
			out = append(out, contracts.AdvisoryRef{
				AdvisoryID:    a.ID,
				Component:     dep.Name + "@" + dep.Version,
				Applicability: applicability(dep.Version, a.FixedIn),
				Source:        m.snapshot,
				Trust:         contracts.TrustAsserted,
			})
		}
	}
	return out, nil
}

// applicability decides affected / not_affected / unknown. An unparseable
// version is "unknown" — never silently "not affected".
func applicability(version, fixedIn string) string {
	if fixedIn == "" {
		return "affected" // all versions affected
	}
	c, ok := compareSemver(version, fixedIn)
	if !ok {
		return "unknown"
	}
	if c < 0 {
		return "affected"
	}
	return "not_affected"
}

// compareSemver compares dotted numeric versions (major.minor.patch). It returns
// (-1|0|1, true) or (0,false) when either side isn't parseable. Pre-release/build
// suffixes are ignored for this conservative comparison.
func compareSemver(a, b string) (int, bool) {
	pa, oka := parseVer(a)
	pb, okb := parseVer(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func parseVer(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	var out [3]int
	if len(parts) == 0 || parts[0] == "" {
		return out, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// ExampleAdvisories is a tiny, clearly-illustrative pinned set for demos/tests.
// It is NOT a complete or current advisory feed.
func ExampleAdvisories() []Advisory {
	return []Advisory{
		{ID: "EXAMPLE-0001", Ecosystem: "npm", Package: "left-pad", FixedIn: "1.3.0", CVSS: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		{ID: "EXAMPLE-0002", Ecosystem: "go", Package: "example.com/vuln", FixedIn: "2.0.0"},
	}
}
