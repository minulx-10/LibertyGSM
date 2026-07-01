package mobile

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/minulx-10/LibertyGSM/core-go/tlsfrag"
)

// unframe parses the length-prefixed wire format produced by FragmentToWire.
func unframe(t *testing.T, wire []byte) [][]byte {
	t.Helper()
	var records [][]byte
	for len(wire) > 0 {
		if len(wire) < 4 {
			t.Fatalf("truncated length prefix (%d bytes left)", len(wire))
		}
		n := int(binary.BigEndian.Uint32(wire[:4]))
		wire = wire[4:]
		if len(wire) < n {
			t.Fatalf("frame claims %d bytes, only %d left", n, len(wire))
		}
		records = append(records, wire[:n])
		wire = wire[n:]
	}
	return records
}

func buildClientHello(sni string) []byte {
	name := []byte(sni)
	listLen := len(name) + 3
	extBody := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(name) >> 8), byte(len(name))}
	extBody = append(extBody, name...)
	ext := append([]byte{0x00, 0x00, byte(len(extBody) >> 8), byte(len(extBody))}, extBody...)

	inner := []byte{0x03, 0x03}
	inner = append(inner, make([]byte, 32)...)
	inner = append(inner, 0x20)
	inner = append(inner, make([]byte, 32)...)
	inner = append(inner, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02, 0x01, 0x00)
	inner = append(inner, byte(len(ext)>>8), byte(len(ext)))
	inner = append(inner, ext...)

	body := append([]byte{0x01, byte(len(inner) >> 16), byte(len(inner) >> 8), byte(len(inner))}, inner...)
	return append([]byte{0x16, 0x03, 0x03, byte(len(body) >> 8), byte(len(body))}, body...)
}

func TestFragmentToWireRoundTrip(t *testing.T) {
	hello := buildClientHello("www.youtube.com")
	wire := FragmentToWire(hello, "Standard")
	got := unframe(t, wire)

	want := tlsfrag.FragmentClientHello(hello, "Standard")
	if len(got) != len(want) {
		t.Fatalf("got %d framed records, FragmentClientHello gave %d", len(got), len(want))
	}

	var reassembled []byte
	for i, r := range got {
		if rl, ok := tlsfrag.TLSRecordLen(r); !ok || len(r) != 5+rl {
			t.Fatalf("record %d is not a valid TLS record", i)
		}
		if bytes.Contains(r[5:], []byte("www.youtube.com")) {
			t.Fatalf("record %d contains the whole SNI", i)
		}
		reassembled = append(reassembled, r[5:]...)
	}
	origBody := hello[5:]
	if !bytes.Equal(reassembled, origBody) {
		t.Fatal("reassembled records != original ClientHello body")
	}
}

func TestExcludeFacade(t *testing.T) {
	// Nothing is excluded by default (fragment everything on a DPI network).
	if DefaultExcludeHosts() != "" {
		t.Errorf("DefaultExcludeHosts should be empty, got %q", DefaultExcludeHosts())
	}
	if IsHostExcluded("login.nexon.com", DefaultExcludeHosts()) {
		t.Error("the default list must exclude nothing")
	}
	// An explicit newline-separated pattern still matches.
	if !IsHostExcluded("login.nexon.com", "*.nexon.com\nexample.org") {
		t.Error("explicit *.nexon.com should match login.nexon.com")
	}
}
