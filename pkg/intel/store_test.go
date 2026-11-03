package intel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAdvisories(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "adv.json")
	body := `{"snapshot":"2026-11-03","source":"curated","advisories":[
	  {"id":"CVE-X","ecosystem":"npm","package":"foo","fixed_in":"2.0.0"}
	]}`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, advs, err := LoadAdvisories(p)
	if err != nil {
		t.Fatal(err)
	}
	if snap != "2026-11-03" || len(advs) != 1 || advs[0].ID != "CVE-X" || advs[0].FixedIn != "2.0.0" {
		t.Fatalf("loaded wrong: snap=%q advs=%+v", snap, advs)
	}
}

func TestLoadAdvisoriesRequiresSnapshot(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "adv.json")
	_ = os.WriteFile(p, []byte(`{"advisories":[]}`), 0o644)
	if _, _, err := LoadAdvisories(p); err == nil {
		t.Fatal("missing snapshot (provenance) must error")
	}
}
