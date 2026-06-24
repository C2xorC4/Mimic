//go:build !windows

package netfilter

func newClosedPortResponder() ClosedPortResponder {
	return nil
}