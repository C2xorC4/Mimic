.PHONY: all build generate clean install test test-unit matrix

# Build configuration
BINARY_NAME := mimic
BUILD_DIR := build
CMD_DIR := cmd/mimic

# eBPF configuration
EBPF_DIR := internal/ebpf
CLANG := clang
CLANG_FLAGS := -O2 -g -Wall -Werror -target bpf

# Go configuration
GO := go
GOFLAGS := -v
LDFLAGS := -s -w

all: generate build

# Generate eBPF Go bindings
generate:
	@echo "Generating eBPF Go bindings..."
	cd $(EBPF_DIR) && $(GO) generate ./...

# Build the binary
build: generate
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Build without generating (if eBPF is already generated)
build-only:
	@echo "Building $(BINARY_NAME) (skip generate)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)

# Install dependencies
deps:
	$(GO) mod download
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(EBPF_DIR)/fingerprint_bpfel.go
	rm -f $(EBPF_DIR)/fingerprint_bpfeb.go
	rm -f $(EBPF_DIR)/fingerprint_bpfel.o
	rm -f $(EBPF_DIR)/fingerprint_bpfeb.o

# Install to system
install: build
	@echo "Installing to /usr/local/bin..."
	install -m 755 $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installing profiles..."
	mkdir -p /etc/mimic/profiles
	cp -r profiles/* /etc/mimic/profiles/

# Uninstall from system
uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)
	rm -rf /etc/mimic

# Run tests
test:
	$(GO) test -v ./...

# Unit tests scoped to the real packages (skips any stray top-level scratch dirs)
test-unit:
	$(GO) test ./cmd/... ./internal/...

# Live fingerprint regression matrix: scan a running target and diff every
# golden against it. Requires nmap and a reachable target running Mimic.
#   make matrix MATRIX_TARGET=10.0.254.45 MATRIX_GOLDEN=windows-server-2025.yaml
#   make matrix MATRIX_TARGET=10.0.254.45 MATRIX_ALL=1   # all goldens (target must match each)
# This is the per-item "no fingerprint regression" gate; the OFFLINE half
# (parser/comparator/profile self-consistency) runs in `make test-unit`/CI.
MATRIX_TARGET ?=
MATRIX_GOLDEN ?=
MATRIX_ALL    ?=
matrix:
	@test -n "$(MATRIX_TARGET)" || { echo "set MATRIX_TARGET=<host>"; exit 2; }
	$(GO) run ./test/matrix -target $(MATRIX_TARGET) \
		$(if $(MATRIX_GOLDEN),-golden $(MATRIX_GOLDEN),) \
		$(if $(MATRIX_ALL),-all,)

# Format code
fmt:
	$(GO) fmt ./...

# Lint
lint:
	golangci-lint run ./...

# Check eBPF program syntax
check-ebpf:
	$(CLANG) $(CLANG_FLAGS) -c $(EBPF_DIR)/fingerprint.c -o /dev/null

# Development: run with example profile
run-example: build
	sudo $(BUILD_DIR)/$(BINARY_NAME) apply -i eth0 "Windows 10"

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Generate eBPF bindings and build binary"
	@echo "  generate  - Generate eBPF Go bindings using bpf2go"
	@echo "  build     - Build the binary (includes generate)"
	@echo "  build-only- Build without regenerating eBPF"
	@echo "  deps      - Download Go dependencies"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install binary and profiles to system"
	@echo "  uninstall - Remove from system"
	@echo "  test      - Run tests"
	@echo "  fmt       - Format Go code"
	@echo "  lint      - Run linter"
	@echo "  check-ebpf- Verify eBPF program compiles"
	@echo "  help      - Show this help"
