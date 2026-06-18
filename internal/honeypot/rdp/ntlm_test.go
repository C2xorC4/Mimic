package rdp

import "testing"

func TestOSVersionTriple(t *testing.T) {
	cases := []struct {
		osVersion       string
		wantMajor       uint8
		wantMinor       uint8
		wantBuild       uint16
	}{
		{"", 10, 0, 19041},
		{"10.0.20348", 10, 0, 20348},
		{"10.0.26200", 10, 0, 26200},
	}
	for _, c := range cases {
		major, minor, build := osVersionTriple(c.osVersion)
		if major != c.wantMajor || minor != c.wantMinor || build != c.wantBuild {
			t.Errorf("osVersionTriple(%q) = %d.%d.%d, want %d.%d.%d",
				c.osVersion, major, minor, build, c.wantMajor, c.wantMinor, c.wantBuild)
		}
	}
}

func TestBuildNTLMChallengeVersion(t *testing.T) {
	var chal [8]byte
	msg := buildNTLMChallenge("SRV2022", "WORKGROUP", chal, 10, 0, 20348)
	if len(msg) < 56 {
		t.Fatalf("challenge too short: %d", len(msg))
	}
	if msg[48] != 10 || msg[49] != 0 {
		t.Errorf("version major/minor = %d.%d, want 10.0", msg[48], msg[49])
	}
	gotBuild := uint16(msg[50]) | uint16(msg[51])<<8
	if gotBuild != 20348 {
		t.Errorf("build = %d, want 20348", gotBuild)
	}
	if msg[55] != 15 {
		t.Errorf("NTLM revision = %d, want 15", msg[55])
	}
}