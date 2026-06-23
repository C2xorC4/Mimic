//go:build tools

// Package tools pins build-time tools (not imported by the application) so they
// are recorded in go.mod and included by `go mod vendor`. bpf2go compiles the
// eBPF C and generates the Go bindings (see internal/ebpf //go:generate); vendoring
// it lets `go generate` run offline on the lab host (argus has no module-proxy
// access) with -mod=vendor.
package tools

import _ "github.com/cilium/ebpf/cmd/bpf2go"
