package config

import "testing"

func TestEditionExposesPort(t *testing.T) {
	cases := []struct {
		edition string
		port    uint16
		want    bool
	}{
		{"", 139, true},
		{"workstation", 139, false},
		{"workstation", 135, false},
		{"workstation", 445, true},
		{"server", 139, true},
		{"server", 135, true},
		{"dc", 139, true},
		{"server", 445, true},
	}
	for _, tc := range cases {
		if got := EditionExposesPort(tc.edition, tc.port); got != tc.want {
			t.Fatalf("EditionExposesPort(%q, %d) = %v, want %v", tc.edition, tc.port, got, tc.want)
		}
	}
}