package nmapprobe

import (
	"bytes"
	"testing"
)

// TestEncodingLossless verifies that bytes → Latin-1 string → bytes round-trips
// for all 256 byte values, individually and in sequences.
func TestEncodingLossless(t *testing.T) {
	// Every single byte value.
	for b := 0; b < 256; b++ {
		in := []byte{byte(b)}
		s := bytesToLatin1(in)
		out := []byte(latin1ToBytes(s))
		if !bytes.Equal(in, out) {
			t.Errorf("byte 0x%02X: round-trip failed: in=%v out=%v", b, in, out)
		}
	}

	// All 256 bytes in one buffer.
	all := make([]byte, 256)
	for i := 0; i < 256; i++ {
		all[i] = byte(i)
	}
	s := bytesToLatin1(all)
	out := []byte(latin1ToBytes(s))
	if !bytes.Equal(all, out) {
		t.Errorf("all bytes: round-trip failed")
	}

	// Real nping-echo response (the case that was failing before this fix).
	npingData := []byte{
		0x01, 0x01, 0x00, 0x18, 0x02, 0x1a, 0x20, 0x21,
		0x69, 0xe9, 0x6f, 0x8f, 0x00, 0x00, 0x00, 0x00,
		0xd0, 0x59, 0xeb, 0x8d, 0x65, 0x70, 0xec, 0x11,
		0x6a, 0x6a, 0x43, 0x96, 0x36, 0x4c, 0xf5, 0xdd,
		0x15, 0x9b, 0xdf, 0x87, 0xaa, 0x02, 0x0a, 0x63,
		0x7b, 0xcf, 0x68, 0x6a, 0xd0, 0x86, 0xf5, 0xe0,
	}
	s = bytesToLatin1(npingData)
	out = []byte(latin1ToBytes(s))
	if !bytes.Equal(npingData, out) {
		t.Errorf("nping data: round-trip failed")
	}
}

// TestRuneCountEqualsByteCount verifies the critical invariant: after encoding,
// the number of Unicode runes equals the original byte count. This is what
// makes regex quantifiers like `.{32}` count bytes, not multi-byte characters.
func TestRuneCountEqualsByteCount(t *testing.T) {
	// Use a sequence of high bytes — these are exactly the bytes that, in raw
	// UTF-8, would form multi-byte sequences and break naive byte counting.
	highBytes := []byte{0xC0, 0xE0, 0xF0, 0xFF, 0x80, 0x90, 0xA0, 0xB0}
	s := bytesToLatin1(highBytes)

	// Count runes in the encoded string.
	runeCount := 0
	for range s {
		runeCount++
	}

	if runeCount != len(highBytes) {
		t.Errorf("rune count %d != byte count %d (encoding is not 1:1)", runeCount, len(highBytes))
	}
}

// TestBinaryRegexAfterEncoding verifies that an nmap-style binary pattern
// matches binary data correctly after Latin-1 encoding.
func TestBinaryRegexAfterEncoding(t *testing.T) {
	// The nping-echo pattern from nmap-service-probes.
	pattern := `^\x01\x01\0\x18.{8}\0\0\0\0.{32}\0{16}.{32}$`

	// Build a 96-byte response that fits the pattern shape.
	data := make([]byte, 96)
	data[0] = 0x01
	data[1] = 0x01
	data[2] = 0x00
	data[3] = 0x18
	// data[4..12] = 8 arbitrary bytes (test with high bytes to stress encoding)
	for i := 4; i < 12; i++ {
		data[i] = byte(0xC0 | i)
	}
	// data[12..16] = 4 nulls
	// data[16..48] = 32 arbitrary bytes
	for i := 16; i < 48; i++ {
		data[i] = byte(i)
	}
	// data[48..64] = 16 nulls (already zero)
	// data[64..96] = 32 arbitrary bytes
	for i := 64; i < 96; i++ {
		data[i] = byte(0x80 | i)
	}

	m := Match{
		Service:    "nping-echo",
		PatternStr: pattern,
		Flags:      "s",
	}
	cm, err := compileMatch(m)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	result := cm.TryMatch(data, "NULL")
	if result == nil {
		t.Fatal("expected match, got nil — encoding may be losing data")
	}
	if result.Service != "nping-echo" {
		t.Errorf("service = %q", result.Service)
	}
}
