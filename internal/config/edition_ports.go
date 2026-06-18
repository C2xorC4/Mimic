package config

// EditionExposesPort reports whether a Windows edition should listen on a
// well-known persona port. Workstation SKUs filter 135/139 (RPC/NetBIOS) by
// default; Server and DC SKUs expose them. Non-Windows profiles (edition "")
// expose all ports — the concept does not apply.
func EditionExposesPort(edition string, port uint16) bool {
	if edition == "" {
		return true
	}
	switch port {
	case 135, 139:
		return edition == "server" || edition == "dc"
	default:
		return true
	}
}