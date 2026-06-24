package platform

import (
	"fmt"
	"syscall"
	"testing"
)

func TestIsAddrInUse(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"eaddrinuse", fmt.Errorf("listen: %w", syscall.EADDRINUSE), true},
		{"windows msg", fmt.Errorf(`listen tcp :445: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.`), true},
		{"linux msg", fmt.Errorf("listen tcp :445: bind: address already in use"), true},
		{"other", fmt.Errorf("permission denied"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsAddrInUse(tc.err); got != tc.want {
				t.Fatalf("IsAddrInUse() = %v, want %v for %v", got, tc.want, tc.err)
			}
		})
	}
}