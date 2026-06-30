// Package tlsfrag is the portable LibertyGSM core: TLS ClientHello record-layer
// fragmentation (the actual SNI/DPI bypass) plus SNI parsing and exclude-host
// matching.
//
// This is a faithful port of the Python reference (tls_frag.py). It is the one
// piece of logic every platform engine shares: the platform-specific layer only
// has to capture an outbound ClientHello, hand it to FragmentClientHello, and
// write the returned records to the upstream socket as separate writes. Keeping
// it in Go lets the same core back the Windows/macOS/Linux desktop engines and,
// via gomobile, the Android (VpnService) and iOS/iPadOS (NEPacketTunnelProvider)
// apps -- one implementation to maintain instead of one per language.
//
// The key idea is TLS *record-layer* fragmentation, not TCP segmentation: the
// single ClientHello record is re-emitted as several valid TLS records, cut
// through the middle of the SNI host name. A DPI box that reads the SNI out of
// one record never sees the whole name, while the destination server reassembles
// the handshake across records and connects normally.
package tlsfrag

import (
	"math"
	"math/rand"
	"sort"
)

// recordTypeHandshake is the TLS record content type for handshake messages.
const recordTypeHandshake = 0x16

// tlsVersions are the legal record-layer versions for a ClientHello.
var tlsVersions = map[int]bool{0x0301: true, 0x0302: true, 0x0303: true, 0x0304: true}

// TLSRecordLen returns the record body length for a buffer that begins with a
// TLS record header, and whether the buffer is a TLS handshake record.
func TLSRecordLen(buf []byte) (int, bool) {
	if len(buf) < 5 || buf[0] != recordTypeHandshake {
		return 0, false
	}
	if !tlsVersions[int(buf[1])<<8|int(buf[2])] {
		return 0, false
	}
	return int(buf[3])<<8 | int(buf[4]), true
}

// makeRecord wraps handshake body bytes in a fresh TLS handshake record header.
// The result is an independent copy and never aliases body or version.
func makeRecord(version, body []byte) []byte {
	rec := make([]byte, 5+len(body))
	rec[0] = recordTypeHandshake
	rec[1] = version[0]
	rec[2] = version[1]
	rec[3] = byte(len(body) >> 8)
	rec[4] = byte(len(body))
	copy(rec[5:], body)
	return rec
}

// splitOffsets picks strictly-increasing body offsets that cut bodyLen into
// `chunks` records. The first cut stays early (well before the SNI).
func splitOffsets(bodyLen, chunks int, firstSmall bool) []int {
	if bodyLen <= 1 {
		return nil
	}
	if chunks < 2 {
		chunks = 2
	}
	if chunks > bodyLen {
		chunks = bodyLen
	}
	step := float64(bodyLen) / float64(chunks)
	var offsets []int
	for i := 1; i < chunks; i++ {
		v := int(math.Round(step * float64(i)))
		if v < 1 {
			v = 1
		}
		if v > bodyLen-1 {
			v = bodyLen - 1
		}
		offsets = append(offsets, v)
	}
	if firstSmall && len(offsets) > 0 {
		offsets[0] = 1
	}
	var out []int
	for _, o := range offsets {
		if len(out) == 0 || o > out[len(out)-1] {
			out = append(out, o)
		}
	}
	return out
}

// SNILocation returns the absolute (start, length) offsets of the SNI host name
// inside a ClientHello payload, and whether it was found. It is best-effort: any
// malformed input yields ok == false (a deferred recover mirrors the Python
// try/except so a truncated/garbage ClientHello can never panic the caller).
func SNILocation(payload []byte) (start, length int, ok bool) {
	defer func() {
		if recover() != nil {
			start, length, ok = 0, 0, false
		}
	}()

	if len(payload) < 6 || payload[0] != recordTypeHandshake || payload[5] != 0x01 {
		return 0, 0, false
	}
	pos := 5
	hsLen := int(payload[pos+1])<<16 | int(payload[pos+2])<<8 | int(payload[pos+3])
	end := pos + 4 + hsLen
	if end > len(payload) {
		end = len(payload)
	}
	pos += 4 + 2 + 32            // handshake header + client version + random
	pos += 1 + int(payload[pos]) // session_id
	clen := int(payload[pos])<<8 | int(payload[pos+1])
	pos += 2 + clen              // cipher_suites
	pos += 1 + int(payload[pos]) // compression_methods
	if pos+2 > end {
		return 0, 0, false
	}
	extLen := int(payload[pos])<<8 | int(payload[pos+1])
	extEnd := pos + 2 + extLen
	if extEnd > end {
		extEnd = end
	}
	pos += 2
	for pos+4 <= extEnd {
		etype := int(payload[pos])<<8 | int(payload[pos+1])
		elen := int(payload[pos+2])<<8 | int(payload[pos+3])
		body := pos + 4
		if etype == 0x0000 { // server_name
			p := body + 2
			if p < extEnd && payload[p] == 0x00 {
				nlen := int(payload[p+1])<<8 | int(payload[p+2])
				return p + 3, nlen, true
			}
			return 0, 0, false
		}
		pos = body + elen
	}
	return 0, 0, false
}

// SNIName returns a best-effort SNI host name from a ClientHello (for logging),
// or "<no-sni>"/"<empty>" when there isn't one.
func SNIName(payload []byte) string {
	start, length, ok := SNILocation(payload)
	if !ok {
		return "<no-sni>"
	}
	end := start + length
	if end > len(payload) {
		end = len(payload)
	}
	if name := string(payload[start:end]); name != "" {
		return name
	}
	return "<empty>"
}

func dedupeSorted(vals []int) []int {
	sort.Ints(vals)
	var out []int
	for _, v := range vals {
		if len(out) == 0 || v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func randRange(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + rand.Intn(hi-lo+1)
}

func clampi(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// FragmentClientHello re-emits a ClientHello as a list of valid TLS records to
// send in order. When the SNI host name can be located, the split lands in the
// MIDDLE of the host name so no single record contains the whole string.
//
//	"Standard" -> 2 records (split through the SNI)
//	"Advanced" -> 3 records (a tiny first record + a split through the SNI)
//	"Extreme"  -> ~8 records
//
// Anything that is not a well-formed ClientHello record is returned unchanged.
func FragmentClientHello(hello []byte, mode string) [][]byte {
	recordLen, ok := TLSRecordLen(hello)
	if !ok || recordLen < 2 || len(hello) < 5+recordLen {
		return [][]byte{hello}
	}
	version := hello[1:3]
	body := hello[5 : 5+recordLen]
	trailing := hello[5+recordLen:] // bytes after the record (normally empty)

	// Body-relative offset that lands in the middle of the SNI host name.
	sniSplit := -1
	if start, length, found := SNILocation(hello); found && length >= 2 {
		cut := (start - 5) + length/2
		if cut > 0 && cut < len(body) {
			sniSplit = cut
		}
	}

	var offsets []int
	switch mode {
	case "Extreme":
		offsets = splitOffsets(len(body), 8, false)
		if sniSplit > 0 {
			offsets = dedupeSorted(append(offsets, sniSplit))
		}
	case "Advanced":
		mid := sniSplit
		if mid < 0 {
			mid = randRange(2, clampi(len(body)-1, 2, 59))
		}
		var candidates []int
		for _, o := range []int{1, mid} {
			if o > 0 && o < len(body) {
				candidates = append(candidates, o)
			}
		}
		offsets = dedupeSorted(candidates)
	default: // Standard
		split := sniSplit
		if split < 0 {
			split = randRange(1, clampi(len(body)-1, 1, 59))
		}
		offsets = []int{split}
	}

	var records [][]byte
	prev := 0
	for _, off := range offsets {
		records = append(records, makeRecord(version, body[prev:off]))
		prev = off
	}
	records = append(records, makeRecord(version, body[prev:]))
	if len(trailing) > 0 {
		rec := make([]byte, len(trailing))
		copy(rec, trailing)
		records = append(records, rec)
	}
	return records
}
