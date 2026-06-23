//go:build linux

package stack

import "github.com/c2xorc4/mimic/internal/ebpf"

// linuxBackend adapts the eBPF FingerprintManager to the Backend interface. The
// only shim needed is InterfaceName (the manager exposes GetInterfaceName); the
// rest of the method set matches exactly, so this is behaviour-preserving.
type linuxBackend struct {
	*ebpf.FingerprintManager
}

func (b linuxBackend) InterfaceName() string { return b.GetInterfaceName() }

// Available reports whether a stack-fingerprint backend exists on this platform.
func Available() bool { return true }

// New returns the eBPF/TC stack backend for the given interface.
func New(ifaceName string) (Backend, error) {
	fm, err := ebpf.NewFingerprintManager(ifaceName)
	if err != nil {
		return nil, err
	}
	return linuxBackend{fm}, nil
}

// Teardown performs the stateless TC/clsact cleanup for the interface.
func Teardown(ifaceName string, purgeQdisc bool) (TeardownResult, error) {
	r, err := ebpf.TeardownInterface(ifaceName, purgeQdisc)
	return TeardownResult{
		FiltersRemoved: r.FiltersRemoved,
		QdiscRemoved:   r.QdiscRemoved,
		ForeignFilters: r.ForeignFilters,
	}, err
}
