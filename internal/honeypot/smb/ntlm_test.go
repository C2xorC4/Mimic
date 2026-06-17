package smb

import (
	"encoding/binary"
	"testing"
)

// TestOSVersionTriple verifies the profile version string is parsed into the
// major/minor/build triple advertised in the NTLM CHALLENGE, with the historic
// 10.0.19041 fallback when the profile version is absent or malformed.
func TestOSVersionTriple(t *testing.T) {
	cases := []struct {
		osVersion    string
		major, minor uint8
		build        uint16
	}{
		{"10.0.22000", 10, 0, 22000}, // Windows 11 21H2
		{"10.0.26100", 10, 0, 26100}, // Windows 11 24H2 / Server 2025
		{"5.1.2600", 5, 1, 2600},     // Windows XP
		{"6.1.7601", 6, 1, 7601},     // Windows 7 SP1
		{"", 10, 0, 19041},           // unset → fallback
		{"garbage", 10, 0, 19041},    // unparseable → fallback
		{"10.0", 10, 0, 19041},       // missing build → build falls back
	}
	for _, c := range cases {
		srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM", OSVersion: c.osVersion})
		major, minor, build := srv.osVersionTriple()
		if major != c.major || minor != c.minor || build != c.build {
			t.Errorf("osVersionTriple(%q) = %d.%d.%d, want %d.%d.%d",
				c.osVersion, major, minor, build, c.major, c.minor, c.build)
		}
	}
}

// TestNTLMChallengeVersion verifies the Version field of the NTLMSSP CHALLENGE
// reflects the supplied major/minor/build instead of a hardcoded value.
func TestNTLMChallengeVersion(t *testing.T) {
	var challenge [8]byte
	msg := buildNTLMChallenge("TESTBOX", "TESTDOM", challenge, 10, 0, 22000)

	if len(msg) < 56 {
		t.Fatalf("challenge too short: %d bytes", len(msg))
	}
	if msg[48] != 10 {
		t.Errorf("MajorVersion = %d, want 10", msg[48])
	}
	if msg[49] != 0 {
		t.Errorf("MinorVersion = %d, want 0", msg[49])
	}
	if got := binary.LittleEndian.Uint16(msg[50:52]); got != 22000 {
		t.Errorf("ProductBuild = %d, want 22000", got)
	}
	if msg[55] != 15 {
		t.Errorf("NTLMRevisionCurrent = %d, want 15", msg[55])
	}
}
