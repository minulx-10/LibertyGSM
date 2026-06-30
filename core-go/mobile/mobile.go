// Package mobile is the gomobile-friendly facade over the LibertyGSM core.
//
// gomobile bind can only export a limited set of types -- string, []byte, the
// numeric/bool types, error, and bound struct pointers -- but NOT [][]byte,
// []string, or maps. This package adapts the richer core API into those
// mobile-safe signatures so the Android (.aar) and iOS/iPadOS (.xcframework)
// wrappers can call exactly the same logic the desktop engines use.
//
// Build the bindings with:
//
//	gomobile bind -target=android -o libgsm.aar   ./core-go/mobile
//	gomobile bind -target=ios     -o LibGSM.xcframework ./core-go/mobile
package mobile

import (
	"encoding/binary"
	"strings"

	"github.com/minulx-10/LibertyGSM/core-go/doh"
	"github.com/minulx-10/LibertyGSM/core-go/tlsfrag"
)

// FragmentToWire fragments a TLS ClientHello and returns the resulting records
// concatenated, each prefixed with a 4-byte big-endian length. The native side
// reads a length, then that many bytes, repeatedly, and writes each record to
// the upstream socket as a SEPARATE write. (gomobile can't return [][]byte, so
// this length-prefixed framing is the bridge.)
//
// `mode` is "Standard", "Advanced", or "Extreme". Non-TLS input comes back as a
// single framed record (i.e. unchanged), so the caller can always forward it.
func FragmentToWire(hello []byte, mode string) []byte {
	records := tlsfrag.FragmentClientHello(hello, mode)
	out := make([]byte, 0, len(hello)+4*len(records))
	var hdr [4]byte
	for _, r := range records {
		binary.BigEndian.PutUint32(hdr[:], uint32(len(r)))
		out = append(out, hdr[:]...)
		out = append(out, r...)
	}
	return out
}

// SNIName returns the SNI host name from a ClientHello, or "<no-sni>".
func SNIName(hello []byte) string { return tlsfrag.SNIName(hello) }

// IsHostExcluded reports whether host matches any of the newline-separated
// patterns (gomobile can't take []string). Patterns may use a "*." prefix.
func IsHostExcluded(host, patternsNewlineSep string) bool {
	return tlsfrag.IsHostExcluded(host, strings.Split(patternsNewlineSep, "\n"))
}

// DefaultExcludeHosts returns the built-in whitelist as a newline-separated string.
func DefaultExcludeHosts() string {
	return strings.Join(tlsfrag.DefaultExcludeHosts, "\n")
}

// Resolver wraps a DoH client for the mobile side. The VpnService/PacketTunnel
// hands captured UDP/53 query bytes to Resolve and writes the answer back.
type Resolver struct {
	c *doh.Client
}

// NewResolver creates a resolver over the default DoH endpoints.
func NewResolver() *Resolver { return &Resolver{c: doh.New(nil)} }

// Resolve resolves a raw DNS query (wire format) over DoH and returns the raw
// response. Returns an error (mapped to an exception on the native side) on
// failure so the caller can fail closed.
func (r *Resolver) Resolve(query []byte) ([]byte, error) { return r.c.Resolve(query) }

// Probe checks the DoH upstream is reachable.
func (r *Resolver) Probe() error { return r.c.Probe() }
