package capture

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// boolToFlag converts a bool to a flag bit at the specified position
func boolToFlag(b bool, pos uint8) uint8 {
	if b {
		return 1 << pos
	}
	return 0
}

// PCAPProcessor processes pcap files to extract sessions
type PCAPProcessor struct {
	tracker   *SessionTracker
	serverIPs map[string]bool // IPs that represent "our" server
	stats     ProcessingStats
}

// ProcessingStats tracks capture statistics
type ProcessingStats struct {
	TotalPackets    int
	TCPPackets      int
	UDPPackets      int
	CapturedPackets int
	Sessions        int
	Exchanges       int
}

// NewPCAPProcessor creates a new pcap processor
func NewPCAPProcessor(serverIPs []net.IP, ports []uint16) *PCAPProcessor {
	ipMap := make(map[string]bool)
	for _, ip := range serverIPs {
		ipMap[ip.String()] = true
	}

	return &PCAPProcessor{
		tracker:   NewSessionTracker(ports, 5*time.Minute),
		serverIPs: ipMap,
	}
}

// ProcessFile processes a pcap file and extracts sessions
func (p *PCAPProcessor) ProcessFile(filename string) error {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return fmt.Errorf("opening pcap: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		p.stats.TotalPackets++
		p.processPacket(packet)
	}

	// Finalize all sessions
	p.tracker.FinalizeSessions()

	// Update stats
	sessions := p.tracker.GetAllSessions()
	p.stats.Sessions = len(sessions)
	for _, s := range sessions {
		p.stats.Exchanges += len(s.Exchanges)
	}

	return nil
}

// processPacket handles a single packet
func (p *PCAPProcessor) processPacket(packet gopacket.Packet) {
	// Get network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP net.IP

	switch nl := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	case *layers.IPv6:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	default:
		return
	}

	// Get transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcPort, dstPort uint16
	var protocol string
	var tcpFlags uint8
	var seqNum, ackNum uint32

	switch tl := transportLayer.(type) {
	case *layers.TCP:
		p.stats.TCPPackets++
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		protocol = "tcp"
		tcpFlags = boolToFlag(tl.SYN, 1) | boolToFlag(tl.FIN, 0) | boolToFlag(tl.RST, 2) | boolToFlag(tl.ACK, 4)
		seqNum = tl.Seq
		ackNum = tl.Ack

	case *layers.UDP:
		p.stats.UDPPackets++
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		protocol = "udp"

	default:
		return
	}

	// Determine direction and check if we should capture
	var direction Direction
	var flowKey FlowKey

	srcIsServer := p.serverIPs[srcIP.String()]
	dstIsServer := p.serverIPs[dstIP.String()]

	if dstIsServer && p.tracker.ShouldCapture(dstPort) {
		// Inbound to server
		direction = DirectionInbound
		flowKey = FlowKey{
			Protocol:   protocol,
			ClientIP:   srcIP,
			ClientPort: srcPort,
			ServerIP:   dstIP,
			ServerPort: dstPort,
		}
	} else if srcIsServer && p.tracker.ShouldCapture(srcPort) {
		// Outbound from server
		direction = DirectionOutbound
		flowKey = FlowKey{
			Protocol:   protocol,
			ClientIP:   dstIP,
			ClientPort: dstPort,
			ServerIP:   srcIP,
			ServerPort: srcPort,
		}
	} else {
		// Not relevant to our capture
		return
	}

	// Get payload
	appLayer := packet.ApplicationLayer()
	var payload []byte
	if appLayer != nil {
		payload = appLayer.Payload()
	}

	// Create packet record
	pkt := Packet{
		Timestamp: packet.Metadata().Timestamp,
		Direction: direction,
		Data:      payload,
		TCPFlags:  tcpFlags,
		SeqNum:    seqNum,
		AckNum:    ackNum,
	}

	// Add to session
	session := p.tracker.GetOrCreateSession(flowKey)
	session.AddPacket(pkt)
	p.stats.CapturedPackets++
}

// GetSessions returns all extracted sessions
func (p *PCAPProcessor) GetSessions() []*Session {
	return p.tracker.GetAllSessions()
}

// GetStats returns processing statistics
func (p *PCAPProcessor) GetStats() ProcessingStats {
	return p.stats
}

// LiveCapture captures packets from a live interface
type LiveCapture struct {
	handle    *pcap.Handle
	tracker   *SessionTracker
	serverIPs map[string]bool
	stopChan  chan struct{}
	stats     ProcessingStats
}

// NewLiveCapture creates a new live capture instance
func NewLiveCapture(iface string, serverIPs []net.IP, ports []uint16) (*LiveCapture, error) {
	// Build BPF filter for specified ports
	filter := buildBPFFilter(ports)

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("opening interface: %w", err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("setting BPF filter: %w", err)
		}
	}

	ipMap := make(map[string]bool)
	for _, ip := range serverIPs {
		ipMap[ip.String()] = true
	}

	return &LiveCapture{
		handle:    handle,
		tracker:   NewSessionTracker(ports, 5*time.Minute),
		serverIPs: ipMap,
		stopChan:  make(chan struct{}),
	}, nil
}

// buildBPFFilter creates a BPF filter for the specified ports
func buildBPFFilter(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}

	filter := ""
	for i, port := range ports {
		if i > 0 {
			filter += " or "
		}
		filter += fmt.Sprintf("port %d", port)
	}
	return filter
}

// Start begins capturing packets
func (lc *LiveCapture) Start() {
	packetSource := gopacket.NewPacketSource(lc.handle, lc.handle.LinkType())

	go func() {
		for {
			select {
			case <-lc.stopChan:
				return
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				lc.processPacket(packet)
			}
		}
	}()
}

// Stop stops capturing
func (lc *LiveCapture) Stop() {
	close(lc.stopChan)
	lc.handle.Close()
	lc.tracker.FinalizeSessions()
}

// processPacket handles a single packet (same logic as PCAPProcessor)
func (lc *LiveCapture) processPacket(packet gopacket.Packet) {
	lc.stats.TotalPackets++

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	var srcIP, dstIP net.IP

	switch nl := networkLayer.(type) {
	case *layers.IPv4:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	case *layers.IPv6:
		srcIP = nl.SrcIP
		dstIP = nl.DstIP
	default:
		return
	}

	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	var srcPort, dstPort uint16
	var protocol string
	var tcpFlags uint8
	var seqNum, ackNum uint32

	switch tl := transportLayer.(type) {
	case *layers.TCP:
		lc.stats.TCPPackets++
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		protocol = "tcp"
		tcpFlags = boolToFlag(tl.SYN, 1) | boolToFlag(tl.FIN, 0) | boolToFlag(tl.RST, 2) | boolToFlag(tl.ACK, 4)
		seqNum = tl.Seq
		ackNum = tl.Ack

	case *layers.UDP:
		lc.stats.UDPPackets++
		srcPort = uint16(tl.SrcPort)
		dstPort = uint16(tl.DstPort)
		protocol = "udp"

	default:
		return
	}

	var direction Direction
	var flowKey FlowKey

	srcIsServer := lc.serverIPs[srcIP.String()]
	dstIsServer := lc.serverIPs[dstIP.String()]

	if dstIsServer && lc.tracker.ShouldCapture(dstPort) {
		direction = DirectionInbound
		flowKey = FlowKey{
			Protocol:   protocol,
			ClientIP:   srcIP,
			ClientPort: srcPort,
			ServerIP:   dstIP,
			ServerPort: dstPort,
		}
	} else if srcIsServer && lc.tracker.ShouldCapture(srcPort) {
		direction = DirectionOutbound
		flowKey = FlowKey{
			Protocol:   protocol,
			ClientIP:   dstIP,
			ClientPort: dstPort,
			ServerIP:   srcIP,
			ServerPort: srcPort,
		}
	} else {
		return
	}

	appLayer := packet.ApplicationLayer()
	var payload []byte
	if appLayer != nil {
		payload = appLayer.Payload()
	}

	pkt := Packet{
		Timestamp: packet.Metadata().Timestamp,
		Direction: direction,
		Data:      payload,
		TCPFlags:  tcpFlags,
		SeqNum:    seqNum,
		AckNum:    ackNum,
	}

	session := lc.tracker.GetOrCreateSession(flowKey)
	session.AddPacket(pkt)
	lc.stats.CapturedPackets++
}

// GetSessions returns all captured sessions
func (lc *LiveCapture) GetSessions() []*Session {
	return lc.tracker.GetAllSessions()
}

// GetStats returns capture statistics
func (lc *LiveCapture) GetStats() ProcessingStats {
	return lc.stats
}
