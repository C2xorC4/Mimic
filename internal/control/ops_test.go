package control

import "testing"

func TestNormalizeOp(t *testing.T) {
	cases := map[string]string{
		"service.restart":  "services.restart",
		"services.restart": "services.restart",
		"service.stop":     "services.stop",
		"services.list":    "services.list",
		"ping":             "ping",
	}
	for in, want := range cases {
		if got := NormalizeOp(in); got != want {
			t.Errorf("NormalizeOp(%q) = %q, want %q", in, got, want)
		}
	}
}