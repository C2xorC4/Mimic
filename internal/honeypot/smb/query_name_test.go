package smb

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

// TestQueryDirectoryFileName decodes the raw QUERY_DIRECTORY response and checks
// that entry FileName fields are actually populated (regression for blank names
// observed via impacket listPath during live validation). Exercises both the
// default FileBothDirectoryInformation (3) and FileIdBothDirectoryInformation (37).
func TestQueryDirectoryFileName(t *testing.T) {
	nameOffFor := map[byte]int{1: 64, 2: 68, 3: 94, 37: 104}
	for _, infoClass := range []byte{1, 2, 3, 37} {
		srv := New(Config{ComputerName: "TESTBOX", DomainName: "TESTDOM"})
		ln, err := newFreeListener()
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		srv.cfg.Port = uint16(extractPort(addr))
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		conn, err := dialAddr(addr)
		if err != nil {
			t.Fatal(err)
		}

		sessionID, treeID := doAuth(t, conn, `\\TESTBOX\C$`)
		var msgID uint64
		next := func() uint64 { msgID += 10; return msgID }

		// Open a directory known to have named children.
		resp := sendRecv(t, conn, buildTestPacket(CmdCreate, sessionID, treeID, next(),
			buildCreateBody(`Users\Administrator\Documents`)))
		if respStatus(resp) != StatusSuccess {
			t.Fatalf("class %d: create dir: %#x", infoClass, respStatus(resp))
		}
		dh := extractVolatileID(resp)

		resp = sendRecv(t, conn, buildTestPacket(CmdQueryDirectory, sessionID, treeID, next(),
			buildQueryDirBody(infoClass, dh)))
		if respStatus(resp) != StatusSuccess {
			t.Fatalf("class %d: query_dir: %#x", infoClass, respStatus(resp))
		}

		// Response body starts at frame[68]; entries at body[8:] (OutputBufferOffset=72).
		bufLen := int(binary.LittleEndian.Uint32(resp[72:76]))
		entries := resp[76 : 76+bufLen]

		nameOff := nameOffFor[infoClass]

		// Walk the NextEntryOffset chain and decode names.
		var names []string
		off := 0
		for {
			e := entries[off:]
			nameLen := int(binary.LittleEndian.Uint32(e[60:64]))
			if nameOff+nameLen > len(e) {
				t.Fatalf("class %d: name region overruns entry (nameOff=%d nameLen=%d entrylen left=%d)",
					infoClass, nameOff, nameLen, len(e))
			}
			name := decodeUTF16(e[nameOff : nameOff+nameLen])
			names = append(names, name)
			nextOff := int(binary.LittleEndian.Uint32(e[0:4]))
			if nextOff == 0 {
				break
			}
			off += nextOff
		}

		conn.Close()
		srv.Stop()

		t.Logf("class %d names: %q", infoClass, names)
		// Expect ".", "..", and the seeded bait files with real names.
		found := map[string]bool{}
		for _, n := range names {
			found[n] = true
		}
		for _, want := range []string{".", "..", "passwords.txt", "backup_credentials.txt"} {
			if !found[want] {
				t.Errorf("class %d: expected entry %q missing; got %q", infoClass, want, names)
			}
		}
	}
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
