package smb

import (
	"net"
	"testing"
)

// newFreeListener opens a TCP listener on an OS-assigned port.
func newFreeListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// dialAddr dials a TCP address.
func dialAddr(addr string) (net.Conn, error) {
	return net.Dial("tcp", addr)
}

// extractPort parses the port number from a "host:port" address string.
func extractPort(addr string) int {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	if tcpAddr == nil {
		return 0
	}
	return tcpAddr.Port
}

func testAuthCredential() Credential {
	return Credential{Username: "svc_backup", Password: "V33m@Backup!23", Domain: "CORP"}
}

func testServerConfig() Config {
	return Config{
		ComputerName: "TESTBOX",
		DomainName:   "TESTDOM",
		Credentials:  []Credential{testAuthCredential()},
	}
}

func testPipeContext() PipeContext {
	cfg := testServerConfig()
	return PipeContext{
		Shares: defaultShares(),
		Env: PipeRPCEnv{
			ComputerName: cfg.ComputerName,
			DomainName:   cfg.DomainName,
		},
	}
}

// doAuth performs NEGOTIATE → SESSION_SETUP×2 → TREE_CONNECT on conn,
// returning (sessionID, treeID) on success or fatally logging on any error.
func doAuth(t *testing.T, conn net.Conn, uncPath string) (uint64, uint32) {
	t.Helper()
	var msgID uint64
	next := func() uint64 { msgID += 5; return msgID }
	cred := testAuthCredential()

	resp := sendRecv(t, conn, buildTestPacket(CmdNegotiate, 0, 0, next(), buildNegotiateBody()))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("doAuth negotiate: %#x", respStatus(resp))
	}

	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, 0, 0, next(), buildSessionSetup1Body()))
	if respStatus(resp) != StatusMoreProcessing {
		t.Fatalf("doAuth ss1: %#x", respStatus(resp))
	}
	sessionID := respSessionID(resp)
	challenge := extractChallengeFromSS1(resp)

	resp = sendRecv(t, conn, buildTestPacket(CmdSessionSetup, sessionID, 0, next(), buildSessionSetup2BodyCred(challenge, cred)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("doAuth ss2: %#x", respStatus(resp))
	}

	resp = sendRecv(t, conn, buildTestPacket(CmdTreeConnect, sessionID, 0, next(), buildTreeConnectBody(uncPath)))
	if respStatus(resp) != StatusSuccess {
		t.Fatalf("doAuth tree_connect: %#x", respStatus(resp))
	}
	return sessionID, respTreeID(resp)
}
