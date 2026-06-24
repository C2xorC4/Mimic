//go:build !windows

package netfilter

func newICMPResponder() ICMPResponder {
	return nil
}