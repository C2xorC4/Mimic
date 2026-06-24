//go:build !windows

package netfilter

func newProbeResponder() ProbeResponder {
	return nil
}