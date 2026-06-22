package deception

import (
	"encoding/binary"
	"strings"
)

const registryHiveStubSize = 8192

// RegistryHiveStub returns a minimal plausible Windows registry hive image:
// REGF signature, header fields, and non-zero payload. Real hives are never
// empty; 0-byte SAM/SYSTEM files were an emulation tell in OSE-2026-001.
func RegistryHiveStub(name string) []byte {
	b := make([]byte, registryHiveStubSize)
	copy(b[0:4], []byte("regf"))
	binary.LittleEndian.PutUint32(b[4:8], 1)   // primary sequence
	binary.LittleEndian.PutUint32(b[8:12], 1)  // secondary sequence
	binary.LittleEndian.PutUint32(b[0x14:0x18], 1)
	binary.LittleEndian.PutUint32(b[0x18:0x1c], 6)
	binary.LittleEndian.PutUint32(b[0x1c:0x20], 0)
	binary.LittleEndian.PutUint32(b[0x20:0x24], 0x1000) // root cell offset
	binary.LittleEndian.PutUint32(b[0x24:0x28], registryHiveStubSize)
	binary.LittleEndian.PutUint32(b[0x28:0x2c], 1)
	binary.LittleEndian.PutUint32(b[0x2c:0x30], 1)
	// File name field (UTF-16LE, 64 bytes at 0x30) — hive label for listing realism.
	label := strings.ToUpper(name)
	if label == "" {
		label = "SYSTEM"
	}
	for i, r := range label {
		if i >= 31 {
			break
		}
		binary.LittleEndian.PutUint16(b[0x30+i*2:], uint16(r))
	}
	// Non-zero tail so size-on-disk looks populated.
	seed := pathSeed(label)
	for i := 0x200; i < len(b); i += 4 {
		seed = seed*6364136223846793005 + 1442695040888963407
		binary.LittleEndian.PutUint32(b[i:], uint32(seed>>32))
	}
	return b
}