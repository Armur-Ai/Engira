package intel

import (
	"fmt"
	"math"
	"strings"

	contracts "github.com/Armur-Ai/armur-contracts"
)

// CVSSv31BaseScore computes the CVSS v3.1 Base Score from a vector string such
// as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". Engira owns deterministic
// scoring; the calculation follows the CVSS v3.1 specification exactly,
// preserving the vector + version for reproducibility. Temporal/environmental
// metrics are out of scope for the base score.
func CVSSv31BaseScore(vector string) (contracts.Score, error) {
	m, err := parseVector(vector)
	if err != nil {
		return contracts.Score{}, err
	}

	av := pick(m, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20})
	ac := pick(m, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	ui := pick(m, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	scopeChanged := m["S"] == "C"
	// Privileges Required depends on Scope.
	var prTable map[string]float64
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	} else {
		prTable = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	}
	pr := pick(m, "PR", prTable)
	cia := map[string]float64{"N": 0.0, "L": 0.22, "H": 0.56}
	c := pick(m, "C", cia)
	i := pick(m, "I", cia)
	a := pick(m, "A", cia)
	if av < 0 || ac < 0 || ui < 0 || pr < 0 || c < 0 || i < 0 || a < 0 {
		return contracts.Score{}, fmt.Errorf("cvss: incomplete or invalid vector %q", vector)
	}

	iss := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	switch {
	case impact <= 0:
		base = 0
	case scopeChanged:
		base = roundUp(math.Min(1.08*(impact+exploitability), 10))
	default:
		base = roundUp(math.Min(impact+exploitability, 10))
	}

	return contracts.Score{System: "CVSS", Version: "3.1", Vector: vector, Value: base}, nil
}

// roundUp implements the CVSS v3.1 Roundup function (round up to the nearest 0.1
// with integer arithmetic to avoid float drift).
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

func parseVector(v string) (map[string]string, error) {
	parts := strings.Split(strings.TrimSpace(v), "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return nil, fmt.Errorf("cvss: vector must start with CVSS:3.x, got %q", v)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		m[kv[0]] = kv[1]
	}
	for _, req := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := m[req]; !ok {
			return nil, fmt.Errorf("cvss: missing base metric %s in %q", req, v)
		}
	}
	return m, nil
}

func pick(m map[string]string, key string, table map[string]float64) float64 {
	if val, ok := table[m[key]]; ok {
		return val
	}
	return -1
}
