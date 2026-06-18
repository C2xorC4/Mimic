package rdp

// isX224ConnectionRequest reports whether payload is an X.224 Connection Request
// (CR TPDU, code 0xE0) optionally carrying an RDP negotiation request.
func isX224ConnectionRequest(payload []byte) bool {
	if len(payload) < 7 {
		return false
	}
	// X.224 CR: high nibble of TPDU code = 0xE (1110), immediately after LI.
	return payload[1]&0xf0 == 0xe0
}