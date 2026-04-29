//go:build ignore

package main

import (
	"log"

	"github.com/cilium/ebpf/cmd/bpf2go"
)

func main() {
	// This file is used with go generate to compile the eBPF program
	// Run: go generate ./internal/ebpf/...
	log.Println("Use: go generate ./internal/ebpf/...")
}
