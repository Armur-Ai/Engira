package intel

import (
	"encoding/json"
	"fmt"
	"os"
)

// AdvisoryFile is a versioned, pinned advisory data set loaded from JSON. The
// snapshot + source fields preserve provenance so results are attributable to a
// dataset version.
type AdvisoryFile struct {
	Snapshot   string     `json:"snapshot"` // dataset version/ref
	Source     string     `json:"source"`   // where it came from (provenance)
	Advisories []Advisory `json:"advisories"`
}

// LoadAdvisories reads an advisory JSON file and returns the snapshot ref and
// the advisories. It errors on a missing snapshot (provenance is required).
func LoadAdvisories(path string) (snapshot string, advs []Advisory, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	var f AdvisoryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return "", nil, fmt.Errorf("intel: parse advisory file %s: %w", path, err)
	}
	if f.Snapshot == "" {
		return "", nil, fmt.Errorf("intel: advisory file %s has no snapshot (provenance required)", path)
	}
	return f.Snapshot, f.Advisories, nil
}
