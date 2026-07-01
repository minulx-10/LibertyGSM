// Package tunnel is the shared mobile packet engine: it drives a gVisor
// userspace TCP/IP stack from a TUN file descriptor and routes traffic through
// the LibertyGSM core. The Android VpnService and the iOS NEPacketTunnelProvider
// both establish a TUN, hand its fd to Connect, and get the full bypass:
//
//   - TCP (443/8080/...) -> dial a VPN-protected upstream socket, fragment the
//     first TLS ClientHello via the shared core (unless the SNI is whitelisted),
//     then pipe the rest. This is the same record-layer fragmentation the
//     Windows engine uses.
//   - UDP/53 -> resolve over DoH and write the answer back.
//   - UDP/443 (QUIC) -> dropped, forcing apps to fall back to the fragmented TCP.
//   - other UDP -> forwarded through a protected socket.
//
// This is gomobile-bound (gomobile bind ./core-go/tunnel) into the .aar / the
// .xcframework. The native side only implements Protector (VpnService.protect)
// so our upstream sockets escape the tunnel instead of looping back in.
//
// Modeled on Jigsaw's Intra, which shares one Go core across Android and iOS.
package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/minulx-10/LibertyGSM/core-go/doh"
	"github.com/minulx-10/LibertyGSM/core-go/tlsfrag"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	mtu   = 1500
	// dnsSinkIP is the fake DNS server the native side advertises
	// (VpnService.addDnsServer). We only answer UDP/53 (DoH) on it; anything
	// else -- notably a Private-DNS DoT probe to :853 -- has nothing to dial, so
	// we refuse it instantly instead of letting it hang for firstRTO. See
	// handleTCP. MUST match LibertyVpnService.kt's addDnsServer.
	dnsSinkIP = "10.111.0.2"
	firstRTO  = 8 * time.Second
	// fragGap is a short pause inserted between the fragmented pieces of the
	// first payload so the OS emits each piece as its OWN TCP segment instead of
	// coalescing them back together. The desktop (WinDivert) engine crafts
	// separate packets directly; here we ride a normal kernel socket, so without
	// this gap a DPI box can still reassemble the whole SNI/Host from one
	// segment. One-time per connection, so the latency cost is negligible.
	fragGap = 6 * time.Millisecond
)

// Protector is implemented by the native side (Android VpnService.protect / the
// equivalent on iOS). It must exclude the given socket fd from the VPN so our
// upstream connections reach the real network instead of looping back in.
type Protector interface {
	Protect(fd int) bool
}

// Session is a running tunnel. It is created by Connect and torn down by Stop.
type Session struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	tun    *os.File
	doh    *doh.Client
	prot   Protector
	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	mode  string
	hosts []string

	dnsCount  atomic.Int64
	tcpCount  atomic.Int64
	quicCount atomic.Int64

	dbgIn   atomic.Int64
	dbgOut  atomic.Int64
	dbgFrag atomic.Int64
	dbgDNS  atomic.Int64
}

// logf is a package alias for log.Printf, used where a local closure shadows the
// log package name (see sendFirstPayload).
var logf = log.Printf

// dbg logs the first `n` events of a category (rate-limited so per-packet loops
// don't flood logcat). Appears in Android logcat under the "GoLog" tag.
func dbg(counter *atomic.Int64, n int64, format string, args ...any) {
	if counter.Add(1) <= n {
		log.Printf("[libgsm] "+format, args...)
	}
}

// Connect starts a tunnel on the given TUN file descriptor. mode is "Standard",
// "Advanced", or "Extreme"; excludeHostsNewlineSep is the newline-separated
// whitelist of hosts to forward without fragmentation (pass "" for none).
func Connect(fd int, mode, excludeHostsNewlineSep string, prot Protector) (*Session, error) {
	if prot == nil {
		return nil, errors.New("tunnel: a Protector is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Session{
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		}),
		ep:     channel.New(512, mtu, ""),
		tun:    os.NewFile(uintptr(fd), "tun"),
		prot:   prot,
		ctx:    ctx,
		cancel: cancel,
		mode:   mode,
		hosts:  splitHosts(excludeHostsNewlineSep),
	}
	// The DoH resolver MUST dial through a VPN-protected socket; otherwise its
	// connection to the resolver (e.g. 1.0.0.1) loops back into this tunnel.
	s.doh = doh.New(nil, doh.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s.protectedDialer().DialContext(ctx, network, addr)
	}))

	if err := s.stack.CreateNIC(nicID, s.ep); err != nil {
		cancel()
		return nil, errors.New("tunnel: CreateNIC: " + err.String())
	}
	s.stack.SetSpoofing(nicID, true)
	s.stack.SetPromiscuousMode(nicID, true)
	s.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	s.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	tf := tcp.NewForwarder(s.stack, 0, 1024, s.handleTCP)
	s.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)
	uf := udp.NewForwarder(s.stack, s.handleUDP)
	s.stack.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)

	go s.inboundLoop()
	go s.outboundLoop()
	log.Printf("[libgsm] tunnel started (fd=%d, mode=%s, quic=allowed)", fd, mode)
	return s, nil
}

// Stop tears the tunnel down and restores normal traffic.
func (s *Session) Stop() {
	s.cancel()
	s.ep.Close()
	_ = s.tun.Close()
	s.stack.Close()
}

// UpdateMode changes the fragmentation intensity while running.
func (s *Session) UpdateMode(mode string) {
	s.mu.Lock()
	s.mode = mode
	s.mu.Unlock()
}

// SetExcludeHosts replaces the whitelist while running.
func (s *Session) SetExcludeHosts(newlineSep string) {
	s.mu.Lock()
	s.hosts = splitHosts(newlineSep)
	s.mu.Unlock()
}

// Counters for the native UI (names chosen so gomobile emits clean camelCase
// Java getters: dnsCount(), tcpCount(), quicDroppedCount()).
func (s *Session) DnsCount() int64         { return s.dnsCount.Load() }
func (s *Session) TcpCount() int64         { return s.tcpCount.Load() }
func (s *Session) QuicDroppedCount() int64 { return s.quicCount.Load() }

func (s *Session) snapshot() (string, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mode, s.hosts
}

// --- TUN <-> netstack pumps --------------------------------------------------

func (s *Session) inboundLoop() {
	defer guard("inboundLoop")
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			log.Printf("[libgsm] tun read error: %v (inbound loop exiting)", err)
			return
		}
		if n < 1 {
			continue
		}
		proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
		if buf[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		dbg(&s.dbgIn, 12, "inbound #%d %dB proto=%#x", s.dbgIn.Load(), n, proto)
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
		s.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (s *Session) outboundLoop() {
	defer guard("outboundLoop")
	for {
		pkt := s.ep.ReadContext(s.ctx)
		if pkt == nil {
			return // context cancelled
		}
		view := pkt.ToView()
		b := view.AsSlice()
		dbg(&s.dbgOut, 12, "outbound #%d %dB", s.dbgOut.Load(), len(b))
		_, _ = s.tun.Write(b)
		view.Release()
		pkt.DecRef()
	}
}

// --- dialing (VPN-protected) -------------------------------------------------

// protectedDialer builds a dialer whose sockets are excluded from the VPN (via
// the native Protector) so the tunnel's own upstream connections reach the real
// network instead of looping back into the tunnel.
func (s *Session) protectedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: firstRTO,
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { s.prot.Protect(int(fd)) })
		},
	}
}

func (s *Session) dial(network, dst string) (net.Conn, error) {
	return s.protectedDialer().DialContext(s.ctx, network, dst)
}

// guard keeps one bad connection/packet from crashing the whole VPN process
// (an unrecovered panic in any goroutine aborts the app).
func guard(tag string) {
	if r := recover(); r != nil {
		log.Printf("libertygsm tunnel: recovered in %s: %v", tag, r)
	}
}

// --- TCP: fragment the ClientHello, then pipe --------------------------------

func (s *Session) handleTCP(r *tcp.ForwarderRequest) {
	defer guard("handleTCP")
	id := r.ID()
	// Refuse TCP to our DNS sink immediately (RST) so a Private-DNS DoT probe
	// falls straight back to UDP/53 (DoH) instead of stalling for firstRTO.
	if addrString(id.LocalAddress) == dnsSinkIP {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	c := s.tcpCount.Add(1)
	local := gonet.NewTCPConn(&wq, ep)
	dst := net.JoinHostPort(addrString(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))
	if c <= 25 {
		log.Printf("[libgsm] TCP #%d -> %s", c, dst)
	}
	go s.pipeTCP(local, dst)
}

func (s *Session) pipeTCP(local net.Conn, dst string) {
	defer guard("pipeTCP")
	defer local.Close()
	up, err := s.dial("tcp", dst)
	if err != nil {
		log.Printf("[libgsm] dial tcp %s FAILED: %v", dst, err)
		return
	}
	defer up.Close()

	mode, hosts := s.snapshot()
	first, rerr := s.readFirstPayload(local)
	if len(first) == 0 {
		if rerr != nil {
			return
		}
	} else {
		if err := s.sendFirstPayload(up, first, dst, mode, hosts); err != nil {
			return
		}
	}

	go func() { _, _ = io.Copy(up, local) }()
	_, _ = io.Copy(local, up)
}

// readFirstPayload reads the client's opening bytes. For a TLS ClientHello it
// keeps reading until the ENTIRE handshake record is in hand: a large
// ClientHello (many extensions, ALPN, a session ticket -- e.g. chess.com) spans
// two TUN packets, and fragmenting only the first half would parse no SNI and
// leak the hostname in the clear.
func (s *Session) readFirstPayload(local net.Conn) ([]byte, error) {
	local.SetReadDeadline(time.Now().Add(firstRTO))
	defer local.SetReadDeadline(time.Time{})

	buf := make([]byte, 16384)
	n, err := local.Read(buf)
	if n <= 0 {
		return nil, err
	}
	first := append([]byte(nil), buf[:n]...)
	if first[0] == 0x16 { // TLS handshake -- make sure we have the whole record
		if recLen, ok := tlsfrag.TLSRecordLen(first); ok {
			for len(first) < 5+recLen {
				m, e := local.Read(buf)
				if m > 0 {
					first = append(first, buf[:m]...)
				}
				if e != nil {
					break
				}
			}
		}
	}
	return first, nil
}

// sendFirstPayload applies the DPI bypass to the opening bytes and writes them
// upstream. TLS ClientHellos are record-fragmented through the SNI; plaintext
// HTTP requests get their Host header split; each piece is flushed as its own
// TCP segment (see fragGap) so the DPI never sees a whole hostname in one place.
func (s *Session) sendFirstPayload(up net.Conn, first []byte, dst, mode string, hosts []string) error {
	log := func(format string, args ...any) {
		if s.dbgFrag.Add(1) <= 80 {
			logf("[libgsm] "+format, args...)
		}
	}

	if first[0] == 0x16 { // TLS ClientHello
		sni := tlsfrag.SNIName(first)
		if tlsfrag.IsHostExcluded(sni, hosts) {
			log("TLS %s sni=%q EXCLUDED (plain)", dst, sni)
			_, err := up.Write(first)
			return err
		}
		recs := tlsfrag.FragmentClientHello(first, mode)
		log("TLS %s sni=%q -> %d records (helloLen=%d)", dst, sni, len(recs), len(first))
		return writeSegments(up, recs)
	}

	if pieces, host := splitHTTPHost(first); pieces != nil { // plaintext HTTP
		log("HTTP %s host=%q -> split into %d segments", dst, host, len(pieces))
		return writeSegments(up, pieces)
	}

	_, err := up.Write(first)
	return err
}

// writeSegments writes each piece and pauses briefly between them so the kernel
// pushes each as a separate TCP segment (defeating segment-reassembling DPI).
func writeSegments(up net.Conn, pieces [][]byte) error {
	for i, p := range pieces {
		if i > 0 {
			time.Sleep(fragGap)
		}
		if _, err := up.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// splitHTTPHost splits a plaintext HTTP request in the MIDDLE of its Host header
// value, so no single TCP segment carries the whole hostname. Returns nil when
// the buffer is not an HTTP request with a usable Host header.
func splitHTTPHost(req []byte) (pieces [][]byte, host string) {
	if !looksLikeHTTP(req) {
		return nil, ""
	}
	i := bytes.Index(bytes.ToLower(req), []byte("host:"))
	if i < 0 {
		return nil, ""
	}
	p := i + len("host:")
	for p < len(req) && (req[p] == ' ' || req[p] == '\t') {
		p++
	}
	start, end := p, p
	for end < len(req) && req[end] != '\r' && req[end] != '\n' && req[end] != ':' {
		end++
	}
	if end-start < 2 {
		return nil, string(req[start:end])
	}
	cut := start + (end-start)/2
	return [][]byte{append([]byte(nil), req[:cut]...), append([]byte(nil), req[cut:]...)}, string(req[start:end])
}

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("TRACE "),
}

func looksLikeHTTP(req []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(req, m) {
			return true
		}
	}
	return false
}

// --- UDP: DoH for :53, drop :443 (QUIC), forward the rest --------------------

func (s *Session) handleUDP(r *udp.ForwarderRequest) bool {
	defer guard("handleUDP")
	id := r.ID()
	if id.LocalPort == 443 {
		s.quicCount.Add(1)
		return true // QUIC -> drop (forces TCP fallback, which we fragment)
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	dbg(&s.dbgDNS, 8, "UDP -> %s:%d", addrString(id.LocalAddress), id.LocalPort)
	if id.LocalPort == 53 {
		go s.handleDNS(conn)
	} else {
		go s.pipeUDP(conn, net.JoinHostPort(addrString(id.LocalAddress), strconv.Itoa(int(id.LocalPort))))
	}
	return true
}

func (s *Session) handleDNS(conn net.Conn) {
	defer guard("handleDNS")
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	q := make([]byte, 1500)
	n, err := conn.Read(q)
	if err != nil || n == 0 {
		log.Printf("[libgsm] DNS read err: %v (n=%d)", err, n)
		return
	}
	ans, err := s.doh.Resolve(q[:n])
	if err != nil {
		log.Printf("[libgsm] DoH resolve FAILED: %v", err)
		return // fail closed: drop rather than leak the plaintext query
	}
	s.dnsCount.Add(1)
	dbg(&s.dbgDNS, 8, "DoH ok: %dB query -> %dB answer", n, len(ans))
	_, _ = conn.Write(ans)
}

func (s *Session) pipeUDP(conn net.Conn, dst string) {
	defer guard("pipeUDP")
	defer conn.Close()
	up, err := s.dial("udp", dst)
	if err != nil {
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, conn) }()
	_, _ = io.Copy(conn, up)
}

// --- helpers -----------------------------------------------------------------

// addrString renders a gVisor address as a dotted/colon IP. Use As4 directly for
// IPv4 (As16 front-pads a 4-byte address, which is NOT v4-in-v6, so slicing it
// yields the wrong bytes).
func addrString(a tcpip.Address) string {
	if a.Len() == 4 {
		b := a.As4()
		return net.IP(b[:]).String()
	}
	b := a.As16()
	return net.IP(b[:]).String()
}

func splitHosts(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
