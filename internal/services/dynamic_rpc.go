package services

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/logging"
)

const dynamicRPCIdleTimeout = 30 * time.Second

// dynamicRPCPool holds TCP listeners for ncacn_ip_tcp ports advertised in the
// EPM ept_lookup response so port-scans see open bindings, not a tell.
type dynamicRPCPool struct {
	log       *logging.Logger
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	listeners []net.Listener
	ports     []uint16
}

func startDynamicRPCPool(parent context.Context, ports []uint16, baseDir string, log *logging.Logger) (*dynamicRPCPool, error) {
	if len(ports) == 0 {
		return nil, nil
	}
	bindAck, err := os.ReadFile(filepath.Join(baseDir, "responses", "bind_ack.bin"))
	if err != nil {
		return nil, fmt.Errorf("dynamic rpc bind_ack: %w", err)
	}
	bindNack, err := os.ReadFile(filepath.Join(baseDir, "responses", "bind_nack.bin"))
	if err != nil {
		return nil, fmt.Errorf("dynamic rpc bind_nack: %w", err)
	}

	ctx, cancel := context.WithCancel(parent)
	pool := &dynamicRPCPool{
		log:    log,
		cancel: cancel,
		ports:  append([]uint16(nil), ports...),
	}

	for _, port := range ports {
		addr := fmt.Sprintf(":%d", port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pool.stop()
			return nil, fmt.Errorf("dynamic rpc listen %d: %w", port, err)
		}
		pool.listeners = append(pool.listeners, ln)
		pool.wg.Add(1)
		go pool.servePort(ctx, ln, port, bindAck, bindNack)
	}

	if log != nil {
		log.Info("Dynamic RPC ports active", map[string]interface{}{
			"count": len(pool.listeners),
			"ports": pool.ports,
		})
	}
	return pool, nil
}

func (p *dynamicRPCPool) stop() {
	if p == nil {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	for _, ln := range p.listeners {
		ln.Close()
	}
	p.wg.Wait()
}

func (p *dynamicRPCPool) servePort(ctx context.Context, ln net.Listener, port uint16, bindAck, bindNack []byte) {
	defer p.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		p.wg.Add(1)
		go func(c net.Conn) {
			defer p.wg.Done()
			handleDynamicRPCConn(c, bindAck, bindNack)
		}(conn)
	}
}

func handleDynamicRPCConn(conn net.Conn, bindAck, bindNack []byte) {
	defer conn.Close()
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(dynamicRPCIdleTimeout))
	n, err := conn.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	var template []byte
	if buf[2] == 0x0b { // BIND
		template = bindAck
	} else {
		template = bindNack
	}
	resp := make([]byte, len(template))
	copy(resp, template)
	if n >= 16 && len(resp) >= 16 {
		copy(resp[12:16], buf[12:16]) // echo call_id
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(resp)
	// Drain any follow-up so the client sees a clean close.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = io.Copy(io.Discard, conn)
}

// epmLookupRewriteRules returns rewrite rules for the captured ept_lookup template.
func epmLookupRewriteRules(probes []config.ProbeConfig) []config.RewriteRule {
	for _, p := range probes {
		if p.Name == "dcerpc_ept_lookup" {
			return p.RewriteRules
		}
	}
	return nil
}

// eptLookupProbeBytes is a minimal CO RPC ept_lookup request for template rewriting.
func eptLookupProbeBytes() []byte {
	b := make([]byte, 64)
	b[0] = 0x05
	b[2] = 0x00
	b[3] = 0x03
	b[4] = 0x10
	binary.LittleEndian.PutUint16(b[8:], uint16(len(b)))
	binary.LittleEndian.PutUint16(b[22:], 2) // opnum 2
	return b
}