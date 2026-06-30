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
	"context"
	"errors"
	"io"
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
	nicID    = 1
	mtu      = 1500
	firstRTO = 8 * time.Second
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
		doh:    doh.New(nil),
		prot:   prot,
		ctx:    ctx,
		cancel: cancel,
		mode:   mode,
		hosts:  splitHosts(excludeHostsNewlineSep),
	}

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
	buf := make([]byte, 65535)
	for {
		n, err := s.tun.Read(buf)
		if err != nil {
			return
		}
		if n < 1 {
			continue
		}
		proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
		if buf[0]>>4 == 6 {
			proto = header.IPv6ProtocolNumber
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf[:n])})
		s.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

func (s *Session) outboundLoop() {
	for {
		pkt := s.ep.ReadContext(s.ctx)
		if pkt == nil {
			return // context cancelled
		}
		view := pkt.ToView()
		_, _ = s.tun.Write(view.AsSlice())
		view.Release()
		pkt.DecRef()
	}
}

// --- dialing (VPN-protected) -------------------------------------------------

func (s *Session) dial(network, dst string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: firstRTO,
		Control: func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { s.prot.Protect(int(fd)) })
		},
	}
	return d.DialContext(s.ctx, network, dst)
}

// --- TCP: fragment the ClientHello, then pipe --------------------------------

func (s *Session) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	s.tcpCount.Add(1)
	local := gonet.NewTCPConn(&wq, ep)
	dst := net.JoinHostPort(addrString(id.LocalAddress), strconv.Itoa(int(id.LocalPort)))
	go s.pipeTCP(local, dst)
}

func (s *Session) pipeTCP(local net.Conn, dst string) {
	defer local.Close()
	up, err := s.dial("tcp", dst)
	if err != nil {
		return
	}
	defer up.Close()

	mode, hosts := s.snapshot()
	local.SetReadDeadline(time.Now().Add(firstRTO))
	first := make([]byte, 65535)
	n, rerr := local.Read(first)
	local.SetReadDeadline(time.Time{})
	if n > 0 {
		hello := first[:n]
		if hello[0] == 0x16 && !tlsfrag.IsHostExcluded(tlsfrag.SNIName(hello), hosts) {
			for _, rec := range tlsfrag.FragmentClientHello(hello, mode) {
				if _, err := up.Write(rec); err != nil {
					return
				}
			}
		} else if _, err := up.Write(hello); err != nil {
			return
		}
	} else if rerr != nil {
		return
	}

	go func() { _, _ = io.Copy(up, local) }()
	_, _ = io.Copy(local, up)
}

// --- UDP: DoH for :53, drop :443 (QUIC), forward the rest --------------------

func (s *Session) handleUDP(r *udp.ForwarderRequest) bool {
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
	if id.LocalPort == 53 {
		go s.handleDNS(conn)
	} else {
		go s.pipeUDP(conn, net.JoinHostPort(addrString(id.LocalAddress), strconv.Itoa(int(id.LocalPort))))
	}
	return true
}

func (s *Session) handleDNS(conn net.Conn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	q := make([]byte, 1500)
	n, err := conn.Read(q)
	if err != nil || n == 0 {
		return
	}
	ans, err := s.doh.Resolve(q[:n])
	if err != nil {
		return // fail closed: drop rather than leak the plaintext query
	}
	s.dnsCount.Add(1)
	_, _ = conn.Write(ans)
}

func (s *Session) pipeUDP(conn net.Conn, dst string) {
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

func addrString(a tcpip.Address) string {
	b := a.As16()
	if a.Len() == 4 {
		return net.IP(b[12:]).String()
	}
	return net.IP(b[:]).String()
}

func splitHosts(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
