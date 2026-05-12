package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -no-strip -cflags "-O2 -g -Wall -Werror" fingerprint fingerprint.c -- -I/usr/include/bpf -I/usr/include

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/c2xorc4/mimic/internal/config"
)

// FingerprintManager manages the eBPF fingerprint modification program
type FingerprintManager struct {
	iface         *net.Interface
	objs          *fingerprintObjects
	qdisc         *netlink.GenericQdisc
	filter        *netlink.BpfFilter
	ingressFilter *netlink.BpfFilter
	enabled       bool
}

// NewFingerprintManager creates a new fingerprint manager for the given interface
func NewFingerprintManager(ifaceName string) (*FingerprintManager, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}

	return &FingerprintManager{
		iface: iface,
	}, nil
}

// Load loads the eBPF program and attaches it to the interface
func (fm *FingerprintManager) Load() error {
	// Load the compiled eBPF objects
	objs := &fingerprintObjects{}
	if err := loadFingerprintObjects(objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	fm.objs = objs

	// Initialize IP ID state
	ipidState := IPIDState{
		Counter:    0,
		RandomSeed: uint32(time.Now().UnixNano()),
	}
	if err := fm.objs.IpIdMap.Put(uint32(0), &ipidState); err != nil {
		fm.objs.Close()
		return fmt.Errorf("initializing IP ID state: %w", err)
	}

	// Set enabled = 0 initially
	if err := fm.objs.EnabledMap.Put(uint32(0), uint32(0)); err != nil {
		fm.objs.Close()
		return fmt.Errorf("initializing enabled state: %w", err)
	}

	// Attach to TC egress
	if err := fm.attachTC(); err != nil {
		fm.objs.Close()
		return fmt.Errorf("attaching to TC: %w", err)
	}

	return nil
}

// attachTC attaches the eBPF program to the TC egress hook
func (fm *FingerprintManager) attachTC() error {
	// Verify interface exists in netlink
	if _, err := netlink.LinkByIndex(fm.iface.Index); err != nil {
		return fmt.Errorf("getting netlink link: %w", err)
	}

	// Create clsact qdisc if it doesn't exist
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: fm.iface.Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		// Ignore "file exists" error - qdisc may already exist
		if err.Error() != "file exists" {
			return fmt.Errorf("adding clsact qdisc: %w", err)
		}
	}
	fm.qdisc = qdisc

	// Attach BPF filter to egress
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: fm.iface.Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    1,
		Protocol:  0x0003, // ETH_P_ALL
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           fm.objs.FingerprintEgress.FD(),
		Name:         "deceiver_fingerprint",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		return fmt.Errorf("adding BPF filter: %w", err)
	}
	fm.filter = filter

	// Attach BPF filter to ingress (for seq_cache population — T4/T6 A=O fix)
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: fm.iface.Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    1,
		Protocol:  0x0003, // ETH_P_ALL
		Priority:  1,
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           fm.objs.FingerprintIngress.FD(),
		Name:         "deceiver_fingerprint_ingress",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return fmt.Errorf("adding BPF ingress filter: %w", err)
	}
	fm.ingressFilter = ingressFilter

	return nil
}

// SetProfile updates the BPF map with a new OS profile
func (fm *FingerprintManager) SetProfile(profile *config.OSProfile) error {
	if fm.objs == nil {
		return fmt.Errorf("eBPF not loaded")
	}

	bpfProfile := profileToBPF(profile)

	if err := fm.objs.ProfileMap.Put(uint32(0), bpfProfile); err != nil {
		return fmt.Errorf("updating profile map: %w", err)
	}

	return nil
}

// Enable enables fingerprint modification
func (fm *FingerprintManager) Enable() error {
	if fm.objs == nil {
		return fmt.Errorf("eBPF not loaded")
	}

	if err := fm.objs.EnabledMap.Put(uint32(0), uint32(1)); err != nil {
		return fmt.Errorf("enabling: %w", err)
	}
	fm.enabled = true
	return nil
}

// Disable disables fingerprint modification
func (fm *FingerprintManager) Disable() error {
	if fm.objs == nil {
		return fmt.Errorf("eBPF not loaded")
	}

	if err := fm.objs.EnabledMap.Put(uint32(0), uint32(0)); err != nil {
		return fmt.Errorf("disabling: %w", err)
	}
	fm.enabled = false
	return nil
}

// IsEnabled returns whether fingerprint modification is enabled
func (fm *FingerprintManager) IsEnabled() bool {
	return fm.enabled
}

// Close cleans up all resources
func (fm *FingerprintManager) Close() error {
	var errs []error

	// Remove filters
	if fm.filter != nil {
		if err := netlink.FilterDel(fm.filter); err != nil {
			errs = append(errs, fmt.Errorf("removing egress filter: %w", err))
		}
	}
	if fm.ingressFilter != nil {
		if err := netlink.FilterDel(fm.ingressFilter); err != nil {
			errs = append(errs, fmt.Errorf("removing ingress filter: %w", err))
		}
	}

	// Note: We don't remove the clsact qdisc as other programs may be using it

	// Close eBPF objects
	if fm.objs != nil {
		if err := fm.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing eBPF objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}
	return nil
}

// profileToBPF converts an OSProfile to the BPF map structure
func profileToBPF(profile *config.OSProfile) *OSProfileBPF {
	bpf := &OSProfileBPF{
		TTL:           profile.Stack.TTL,
		WindowSize:    profile.Stack.WindowSize,
		WindowScale:   profile.Stack.WindowScale,
		MSS:           profile.Stack.MSS,
		WindowInRST:   profile.Stack.WindowInRST,
		ICMPQuoteSize: profile.Stack.ICMPQuoteSize,
		ICMPTTLInQuote: profile.Stack.ICMPTTLInQuote,
	}

	// DF bit
	if profile.Stack.DFBit {
		bpf.DFBit = 1
	}

	// TCP timestamps
	if profile.Stack.TCPTimestamps {
		bpf.TCPTimestamps = 1
	}

	// SACK permitted
	if profile.Stack.SACKPermitted {
		bpf.SACKPermitted = 1
	}

	// ECN support
	if profile.Stack.ECNSupport {
		bpf.ECNSupport = 1
	}

	// ICMP DF in quote
	if profile.Stack.ICMPDFInQuote {
		bpf.ICMPDFInQuote = 1
	}

	// ICMP rate limit
	if profile.Stack.ICMPRateLimit {
		bpf.ICMPRateLimit = 1
	}

	// UDP closed port response
	if profile.Stack.UDPClosedPortResponse {
		bpf.UDPClosedPortResponse = 1
	}

	// IP ID behavior
	bpf.IPIDBehavior = IPIDBehaviorFromString(profile.Stack.IPIDBehavior)

	// ACK in RST behavior
	bpf.AckInRST = AckInRSTFromString(profile.Stack.AckInRST)

	// TCP options order
	for i, opt := range profile.Stack.TCPOptionsOrder {
		if i >= 10 {
			break
		}
		bpf.TCPOptionsOrder[i] = TCPOptionFromString(opt)
	}
	bpf.TCPOptionsCount = uint8(len(profile.Stack.TCPOptionsOrder))
	if bpf.TCPOptionsCount > 10 {
		bpf.TCPOptionsCount = 10
	}

	return bpf
}

// GetInterfaceName returns the attached interface name
func (fm *FingerprintManager) GetInterfaceName() string {
	if fm.iface != nil {
		return fm.iface.Name
	}
	return ""
}
