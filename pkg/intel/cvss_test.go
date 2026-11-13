package intel

import "testing"

func TestCVSSv31KnownVectors(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// Canonical CVSS v3.1 examples with published base scores.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8}, // critical
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0}, // no impact
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1}, // scope changed
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8}, // local privesc
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9}, // high complexity, conf only
	}
	for _, tc := range cases {
		got, err := CVSSv31BaseScore(tc.vector)
		if err != nil {
			t.Fatalf("%s: %v", tc.vector, err)
		}
		if got.Value != tc.want {
			t.Fatalf("%s: base = %v, want %v", tc.vector, got.Value, tc.want)
		}
		if got.System != "CVSS" || got.Version != "3.1" {
			t.Fatalf("%s: system/version not preserved: %+v", tc.vector, got)
		}
	}
}

func TestCVSSv31RejectsBadVector(t *testing.T) {
	for _, bad := range []string{"", "nonsense", "CVSS:3.1/AV:N", "CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, err := CVSSv31BaseScore(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
}

func TestCVSSRating(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "None"},
		{0.1, "Low"},
		{3.9, "Low"},
		{4.0, "Medium"},
		{6.9, "Medium"},
		{7.0, "High"},
		{8.9, "High"},
		{9.0, "Critical"},
		{10.0, "Critical"},
	}
	for _, c := range cases {
		if got := CVSSRating(c.score); got != c.want {
			t.Errorf("CVSSRating(%.1f) = %q, want %q", c.score, got, c.want)
		}
	}
}
