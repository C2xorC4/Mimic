package ebpf

import (
	"fmt"
	"strings"

	"github.com/vishvananda/netlink"
)

// mimicFilterPrefix is the TCA_BPF_NAME prefix Mimic gives its TC filters
// (see attachTC: "deceiver_fingerprint" / "deceiver_fingerprint_ingress").
// Teardown identifies *our* filters by this prefix so it never touches a
// co-tenant's program on a shared clsact qdisc.
const mimicFilterPrefix = "deceiver_fingerprint"

// TeardownResult reports what an interface teardown did.
type TeardownResult struct {
	FiltersRemoved int  // Mimic TC filters removed (egress + ingress)
	QdiscRemoved   bool // clsact qdisc removed (only when purge requested and no foreign filters remained)
	ForeignFilters int  // non-Mimic filters left on the clsact after we removed ours
}

// TeardownInterface removes Mimic's TC filters from ifaceName. It is STATELESS —
// it derives ownership by inspecting what's attached, so it works without a loaded
// FingerprintManager (e.g. a fresh `mimic stop` after a crash/SIGKILL) and is
// idempotent.
//
// If purgeQdisc is true it also removes the clsact qdisc, but ONLY if no foreign
// filters remain after ours are stripped — i.e. the qdisc was solely Mimic's.
// On a shared host (Cilium, eBPF EDR, QoS classifiers) the qdisc is left in place.
func TeardownInterface(ifaceName string, purgeQdisc bool) (TeardownResult, error) {
	var res TeardownResult

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return res, fmt.Errorf("link %s: %w", ifaceName, err)
	}

	hooks := []uint32{netlink.HANDLE_MIN_EGRESS, netlink.HANDLE_MIN_INGRESS}

	// Remove only our filters from both clsact hooks.
	for _, parent := range hooks {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			continue // hook may not exist; nothing to remove
		}
		for _, f := range filters {
			if isMimicFilter(f) {
				if err := netlink.FilterDel(f); err == nil {
					res.FiltersRemoved++
				}
			}
		}
	}

	if !purgeQdisc {
		return res, nil
	}

	// Content diff: only purge the qdisc if nothing else is attached to it.
	for _, parent := range hooks {
		if filters, err := netlink.FilterList(link, parent); err == nil {
			res.ForeignFilters += len(filters)
		}
	}
	if res.ForeignFilters == 0 {
		if removed, err := delClsact(link); err == nil {
			res.QdiscRemoved = removed
		}
	}
	return res, nil
}

// isMimicFilter reports whether a TC filter is one Mimic attached, by BPF name.
func isMimicFilter(f netlink.Filter) bool {
	bf, ok := f.(*netlink.BpfFilter)
	if !ok {
		return false
	}
	return strings.HasPrefix(bf.Name, mimicFilterPrefix)
}

// delClsact removes the clsact qdisc from link if present.
func delClsact(link netlink.Link) (bool, error) {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false, err
	}
	for _, q := range qdiscs {
		if q.Type() == "clsact" {
			if err := netlink.QdiscDel(q); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil // no clsact present
}
