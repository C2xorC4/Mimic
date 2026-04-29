package logging

import (
	"encoding/hex"
)

// ProbeResult represents the outcome of a probe match attempt
type ProbeResult string

const (
	ProbeMatched   ProbeResult = "matched"
	ProbeUnmatched ProbeResult = "unmatched"
)

// ProbeEvent represents a probe attempt for logging
type ProbeEvent struct {
	Service    string      `json:"service"`
	Port       uint16      `json:"port"`
	Protocol   string      `json:"protocol"`
	SourceAddr string      `json:"source_addr"`
	Result     ProbeResult `json:"result"`
	ProbeName  string      `json:"probe_name,omitempty"`
	ProbeLen   int         `json:"probe_len"`
	ProbeHex   string      `json:"probe_hex"`
}

// LogProbe logs a probe attempt (matched or unmatched)
func LogProbe(event ProbeEvent) {
	logger := GetProbeLogger()
	if logger == nil {
		return
	}

	// Truncate probe hex for very large probes
	probeHex := event.ProbeHex
	if len(probeHex) > 512 {
		probeHex = probeHex[:512] + "..."
	}

	fields := map[string]interface{}{
		"service":     event.Service,
		"port":        event.Port,
		"protocol":    event.Protocol,
		"source_addr": event.SourceAddr,
		"result":      string(event.Result),
		"probe_len":   event.ProbeLen,
		"probe_hex":   probeHex,
	}

	if event.ProbeName != "" {
		fields["probe_name"] = event.ProbeName
	}

	var msg string
	if event.Result == ProbeMatched {
		msg = "Probe matched"
	} else {
		msg = "Probe unmatched"
	}

	logger.Info(msg, fields)
}

// LogProbeMatched logs a successfully matched probe
func LogProbeMatched(service string, port uint16, protocol, sourceAddr, probeName string, probeData []byte) {
	LogProbe(ProbeEvent{
		Service:    service,
		Port:       port,
		Protocol:   protocol,
		SourceAddr: sourceAddr,
		Result:     ProbeMatched,
		ProbeName:  probeName,
		ProbeLen:   len(probeData),
		ProbeHex:   hex.EncodeToString(probeData),
	})
}

// LogProbeUnmatched logs an unmatched probe
func LogProbeUnmatched(service string, port uint16, protocol, sourceAddr string, probeData []byte) {
	LogProbe(ProbeEvent{
		Service:    service,
		Port:       port,
		Protocol:   protocol,
		SourceAddr: sourceAddr,
		Result:     ProbeUnmatched,
		ProbeLen:   len(probeData),
		ProbeHex:   hex.EncodeToString(probeData),
	})
}
