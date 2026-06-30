package tlsfrag

import (
	"bytes"
	"testing"
)

// buildClientHello crafts a minimal but well-formed TLS 1.x ClientHello record
// carrying the given SNI host name (mirrors the Python unit test's fixture).
func buildClientHello(sni string) []byte {
	name := []byte(sni)

	// server_name extension body: list_len(2) + name_type(1) + name_len(2) + name
	listLen := len(name) + 3
	extBody := []byte{byte(listLen >> 8), byte(listLen), 0x00, byte(len(name) >> 8), byte(len(name))}
	extBody = append(extBody, name...)
	// extension: type server_name(0x0000) + ext_len(2) + body
	ext := []byte{0x00, 0x00, byte(len(extBody) >> 8), byte(len(extBody))}
	ext = append(ext, extBody...)

	var inner bytes.Buffer
	inner.Write([]byte{0x03, 0x03})             // client_version
	inner.Write(make([]byte, 32))               // random
	inner.WriteByte(0x20)                       // session_id length
	inner.Write(make([]byte, 32))               // session_id
	inner.Write([]byte{0x00, 0x04})             // cipher_suites length
	inner.Write([]byte{0x13, 0x01, 0x13, 0x02}) // cipher_suites
	inner.Write([]byte{0x01, 0x00})             // compression_methods (len 1, null)
	inner.Write([]byte{byte(len(ext) >> 8), byte(len(ext))})
	inner.Write(ext)

	ib := inner.Bytes()
	var body bytes.Buffer
	body.WriteByte(0x01) // handshake type: client_hello
	body.Write([]byte{byte(len(ib) >> 16), byte(len(ib) >> 8), byte(len(ib))})
	body.Write(ib)

	bb := body.Bytes()
	rec := []byte{0x16, 0x03, 0x03, byte(len(bb) >> 8), byte(len(bb))}
	return append(rec, bb...)
}

func TestSNIName(t *testing.T) {
	hello := buildClientHello("www.youtube.com")
	if got := SNIName(hello); got != "www.youtube.com" {
		t.Fatalf("SNIName = %q, want www.youtube.com", got)
	}
	if got := SNIName([]byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x00}); got != "<no-sni>" {
		t.Fatalf("SNIName(no-sni) = %q", got)
	}
	if got := SNIName([]byte("garbage")); got != "<no-sni>" {
		t.Fatalf("SNIName(garbage) = %q (must not panic)", got)
	}
}

func TestFragmentClientHello(t *testing.T) {
	hello := buildClientHello("www.chess.com")
	name := []byte("www.chess.com")

	recordLen, ok := TLSRecordLen(hello)
	if !ok {
		t.Fatal("fixture is not a TLS record")
	}
	origBody := hello[5 : 5+recordLen]

	for _, mode := range []string{"Standard", "Advanced", "Extreme"} {
		recs := FragmentClientHello(hello, mode)
		if len(recs) < 2 {
			t.Fatalf("%s: expected >= 2 records, got %d", mode, len(recs))
		}
		var reassembled []byte
		for _, r := range recs {
			rl, ok := TLSRecordLen(r)
			if !ok || len(r) != 5+rl {
				t.Fatalf("%s: invalid record (len=%d, declared=%d, ok=%v)", mode, len(r), rl, ok)
			}
			if bytes.Contains(r[5:], name) {
				t.Fatalf("%s: a single record still contains the full SNI %q", mode, name)
			}
			reassembled = append(reassembled, r[5:]...)
		}
		if !bytes.Equal(reassembled, origBody) {
			t.Fatalf("%s: reassembled body != original", mode)
		}
	}
}

func TestFragmentNonTLSPassthrough(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\n")
	recs := FragmentClientHello(data, "Standard")
	if len(recs) != 1 || !bytes.Equal(recs[0], data) {
		t.Fatalf("non-TLS input must be returned unchanged, got %d records", len(recs))
	}
}

func TestIsHostExcluded(t *testing.T) {
	patterns := []string{"*.nexon.com", "example.org"}
	cases := []struct {
		host string
		want bool
	}{
		{"www.nexon.com", true},
		{"nexon.com", true},
		{"sub.www.nexon.com", true},
		{"nexonxcom", false},
		{"evil-nexon.com", false},
		{"example.org", true},
		{"a.example.org", true},
		{"notexample.org", false},
		{"<no-sni>", false},
		{"", false},
		{"google.com", false},
	}
	for _, c := range cases {
		if got := IsHostExcluded(c.host, patterns); got != c.want {
			t.Errorf("IsHostExcluded(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}
