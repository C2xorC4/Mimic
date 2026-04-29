package capture

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// FlowKey uniquely identifies a bidirectional network flow
type FlowKey struct {
	Protocol  string
	ClientIP  net.IP
	ClientPort uint16
	ServerIP  net.IP
	ServerPort uint16
}

func (f FlowKey) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d (%s)",
		f.ClientIP, f.ClientPort, f.ServerIP, f.ServerPort, f.Protocol)
}

// Reverse returns the reverse direction flow key
func (f FlowKey) Reverse() FlowKey {
	return FlowKey{
		Protocol:   f.Protocol,
		ClientIP:   f.ServerIP,
		ClientPort: f.ServerPort,
		ServerIP:   f.ClientIP,
		ServerPort: f.ClientPort,
	}
}

// Packet represents a captured packet with metadata
type Packet struct {
	Timestamp   time.Time
	Direction   Direction
	Data        []byte
	TCPFlags    uint8
	SeqNum      uint32
	AckNum      uint32
}

// Direction indicates packet direction relative to the service
type Direction int

const (
	DirectionInbound  Direction = iota // Client -> Server (probe)
	DirectionOutbound                  // Server -> Client (response)
)

func (d Direction) String() string {
	if d == DirectionInbound {
		return "inbound"
	}
	return "outbound"
}

// Exchange represents a single probe/response pair
type Exchange struct {
	Index      int
	Probe      []byte
	Response   []byte
	ProbeTime  time.Time
	ResponseTime time.Time
	ProbePackets   []Packet
	ResponsePackets []Packet
}

// Session represents a complete captured session (TCP connection or UDP exchange)
type Session struct {
	Key        FlowKey
	StartTime  time.Time
	EndTime    time.Time
	Packets    []Packet
	Exchanges  []Exchange
	Protocol   string // Application protocol (smb, rdp, http, etc.)
	mu         sync.Mutex
}

// NewSession creates a new session tracker
func NewSession(key FlowKey) *Session {
	return &Session{
		Key:       key,
		StartTime: time.Now(),
		Packets:   make([]Packet, 0),
		Exchanges: make([]Exchange, 0),
	}
}

// AddPacket adds a packet to the session
func (s *Session) AddPacket(pkt Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Packets = append(s.Packets, pkt)
	s.EndTime = pkt.Timestamp
}

// ExtractExchanges analyzes packets to identify probe/response pairs
// This is protocol-agnostic and uses timing/direction heuristics
func (s *Session) ExtractExchanges() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Packets) == 0 {
		return
	}

	var currentExchange *Exchange
	var exchangeIndex int

	for _, pkt := range s.Packets {
		// Skip empty packets (ACKs, etc.)
		if len(pkt.Data) == 0 {
			continue
		}

		if pkt.Direction == DirectionInbound {
			// New inbound packet - could be new probe or continuation
			if currentExchange == nil || len(currentExchange.Response) > 0 {
				// Start new exchange
				if currentExchange != nil {
					s.Exchanges = append(s.Exchanges, *currentExchange)
				}
				currentExchange = &Exchange{
					Index:     exchangeIndex,
					ProbeTime: pkt.Timestamp,
				}
				exchangeIndex++
			}
			currentExchange.Probe = append(currentExchange.Probe, pkt.Data...)
			currentExchange.ProbePackets = append(currentExchange.ProbePackets, pkt)

		} else {
			// Outbound packet - response
			if currentExchange == nil {
				// Response without probe (server-initiated) - skip or handle specially
				continue
			}
			if currentExchange.ResponseTime.IsZero() {
				currentExchange.ResponseTime = pkt.Timestamp
			}
			currentExchange.Response = append(currentExchange.Response, pkt.Data...)
			currentExchange.ResponsePackets = append(currentExchange.ResponsePackets, pkt)
		}
	}

	// Don't forget last exchange
	if currentExchange != nil && len(currentExchange.Probe) > 0 {
		s.Exchanges = append(s.Exchanges, *currentExchange)
	}
}

// SessionTracker manages multiple concurrent sessions
type SessionTracker struct {
	sessions map[string]*Session
	ports    map[uint16]bool // Ports we're interested in capturing
	mu       sync.RWMutex
	timeout  time.Duration
}

// NewSessionTracker creates a new session tracker
func NewSessionTracker(ports []uint16, timeout time.Duration) *SessionTracker {
	portMap := make(map[uint16]bool)
	for _, p := range ports {
		portMap[p] = true
	}

	return &SessionTracker{
		sessions: make(map[string]*Session),
		ports:    portMap,
		timeout:  timeout,
	}
}

// ShouldCapture returns true if this port should be captured
func (st *SessionTracker) ShouldCapture(port uint16) bool {
	if len(st.ports) == 0 {
		return true // Capture all if no filter
	}
	return st.ports[port]
}

// GetOrCreateSession gets existing session or creates new one
func (st *SessionTracker) GetOrCreateSession(key FlowKey) *Session {
	keyStr := key.String()

	st.mu.Lock()
	defer st.mu.Unlock()

	if session, exists := st.sessions[keyStr]; exists {
		return session
	}

	session := NewSession(key)
	st.sessions[keyStr] = session
	return session
}

// GetSession retrieves a session by key
func (st *SessionTracker) GetSession(key FlowKey) *Session {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.sessions[key.String()]
}

// GetAllSessions returns all tracked sessions
func (st *SessionTracker) GetAllSessions() []*Session {
	st.mu.RLock()
	defer st.mu.RUnlock()

	sessions := make([]*Session, 0, len(st.sessions))
	for _, s := range st.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// CleanupStale removes sessions older than timeout
func (st *SessionTracker) CleanupStale() int {
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := time.Now().Add(-st.timeout)
	removed := 0

	for key, session := range st.sessions {
		if session.EndTime.Before(cutoff) {
			delete(st.sessions, key)
			removed++
		}
	}

	return removed
}

// FinalizeSessions extracts exchanges from all sessions
func (st *SessionTracker) FinalizeSessions() {
	st.mu.RLock()
	defer st.mu.RUnlock()

	for _, session := range st.sessions {
		session.ExtractExchanges()
	}
}
