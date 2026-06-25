"""WinDivert transparent bypass engine for LibertyGSM.

This is the whole-system engine: instead of a userspace HTTP proxy that only
catches proxy-aware apps, it uses WinDivert to intercept traffic at the network
driver level, so EVERY app on the laptop is covered transparently -- no proxy
setting, no per-browser configuration.

Two things are intercepted:

  * Outbound UDP/53 (DNS) -> resolved over DNS-over-HTTPS and the reply injected
    back, so the school's DNS hijacking/censorship can't return fake IPs.
  * Outbound TCP/443 (HTTPS) -> redirected to a tiny local relay that re-emits
    the TLS ClientHello as several TLS records (record-layer fragmentation,
    cut through the SNI host name) before piping the rest through to the real
    server, so the SNI-based DPI filter can't see the blocked host name.

Architecture (the redirect trick) is a faithful adaptation of FreeGSM, which is
itself proven by mitmproxy's WinDivert transparent proxy. Requires Administrator
(WinDivert loads a kernel driver).
"""

from __future__ import annotations

import http.client
import socket
import socketserver
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pydivert
from pydivert.consts import Direction

from tls_frag import fragment_client_hello, sni_name, _TLS_HANDSHAKE

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
# DoH resolvers, addressed by literal IP so resolving the resolver never needs
# DNS. 1.0.0.1 / 8.8.4.4 are secondary anycast IPs; many school networks block
# 1.1.1.1 specifically but not its sibling. Their TLS certs include IP SANs, so
# verification still succeeds.
DOH_IPS = ["1.0.0.1", "1.1.1.1", "8.8.8.8", "8.8.4.4"]
DOH_PATH = "/dns-query"           # 8.8.8.8 also serves wire-format here
DOH_TIMEOUT = 5.0

# Outbound TCP ports whose TLS ClientHello we fragment. 443 covers normal HTTPS;
# add a site's game/WebSocket port here (e.g. KKuTu connects its game socket on a
# non-443 port) and it gets the same SNI-fragmentation treatment.
INTERCEPT_TCP_PORTS = [443]

RELAY_PORT = 47443                # local HTTPS-splitting relay
UPSTREAM_PORT_BASE = 30000        # relay -> server sockets bound here...
UPSTREAM_PORT_COUNT = 2048        # ...so the kernel filter can exclude them
_UPSTREAM_HI = UPSTREAM_PORT_BASE + UPSTREAM_PORT_COUNT - 1

HTTPS_CONNECT_TIMEOUT = 8.0
HTTPS_FIRST_READ_TIMEOUT = 8.0


def _build_filter():
    doh_excl = "".join(f" and ip.DstAddr != {ip}" for ip in DOH_IPS)
    ports = " or ".join(f"tcp.DstPort == {p}" for p in INTERCEPT_TCP_PORTS)
    return (
        "ip and ("
        "(outbound and udp.DstPort == 53)"
        " or (outbound and udp.DstPort == 443)"   # QUIC/HTTP3 -> dropped (force TCP)
        f" or (outbound and ({ports}){doh_excl}"
        f" and (tcp.SrcPort < {UPSTREAM_PORT_BASE} or tcp.SrcPort > {_UPSTREAM_HI}))"
        f" or (tcp.SrcPort == {RELAY_PORT})"
        ")"
    )


# --------------------------------------------------------------------------- #
# DoH client (stdlib, wire-format: the DNS query bytes ARE the request body)
# --------------------------------------------------------------------------- #
class DohClient:
    """Resolve raw DNS queries over DoH (RFC 8484 application/dns-message).

    Keeps one kept-alive HTTPS connection per resolver and fails over to the
    next resolver IP when one stops answering."""

    _HEADERS = {
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": "LibertyGSM",
    }

    def __init__(self, server_ips=None, path=DOH_PATH, timeout=DOH_TIMEOUT):
        self.server_ips = list(server_ips or DOH_IPS)
        self.path = path
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        self._conn = None
        self._active_ip = None
        self._lock = threading.Lock()

    def _open(self, ip):
        return http.client.HTTPSConnection(ip, 443, timeout=self.timeout, context=self._ctx)

    def resolve(self, query: bytes) -> bytes:
        with self._lock:
            # Try the active resolver first, then the rest, reconnecting once each.
            order = ([self._active_ip] if self._active_ip else []) + \
                    [ip for ip in self.server_ips if ip != self._active_ip]
            last_err = None
            for ip in order:
                for _ in range(2):  # one reconnect on a stale keep-alive
                    try:
                        if self._conn is None or self._active_ip != ip:
                            self._close()
                            self._conn = self._open(ip)
                            self._active_ip = ip
                        headers = dict(self._HEADERS, **{"Content-Length": str(len(query))})
                        self._conn.request("POST", self.path, body=query, headers=headers)
                        resp = self._conn.getresponse()
                        data = resp.read()
                        if resp.status != 200 or not data:
                            raise IOError(f"DoH HTTP {resp.status}")
                        return data
                    except Exception as exc:
                        last_err = exc
                        self._close()
                        self._active_ip = None
            raise RuntimeError(f"all DoH resolvers failed: {last_err}")

    def probe(self):
        # Minimal A query for example.com to confirm the upstream is reachable.
        q = (b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
        try:
            self.resolve(q)
            return True, self._active_ip or "ok"
        except Exception as exc:
            return False, str(exc)

    def _close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def close(self):
        with self._lock:
            self._close()
            self._active_ip = None


# --------------------------------------------------------------------------- #
# HTTPS splitting relay (terminates redirected :443, fragments the ClientHello)
# --------------------------------------------------------------------------- #
_port_lock = threading.Lock()
_next_port = UPSTREAM_PORT_BASE


def _connect_upstream(server_ip, server_port):
    """Open a socket to the real server, bound to a port in the reserved range
    (so the kernel filter never re-captures the relay's upstream leg)."""
    global _next_port
    last_err = None
    for _ in range(UPSTREAM_PORT_COUNT):
        with _port_lock:
            port = _next_port
            _next_port = port + 1 if port + 1 <= _UPSTREAM_HI else UPSTREAM_PORT_BASE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
        except OSError as exc:
            last_err = exc
            s.close()
            continue
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(HTTPS_CONNECT_TIMEOUT)
            s.connect((server_ip, server_port))
            s.settimeout(None)
            return s
        except OSError as exc:
            last_err = exc
            s.close()
            raise
    raise OSError(f"no free upstream port ({last_err})")


def _read_client_hello(sock):
    """Read the first client packet, growing until the full ClientHello record
    is present so it can be fragmented cleanly."""
    sock.settimeout(HTTPS_FIRST_READ_TIMEOUT)
    try:
        buf = sock.recv(16384)
    except (socket.timeout, OSError):
        return b""
    if len(buf) < 5 or buf[0] != _TLS_HANDSHAKE:
        return buf
    need = 5 + int.from_bytes(buf[3:5], "big")
    while len(buf) < need and len(buf) < 65535:
        try:
            chunk = sock.recv(16384)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _pump(src, dst, stats=None):
    """Copy src -> dst until EOF, then half-close dst's write side."""
    try:
        while True:
            data = src.recv(65535)
            if not data:
                break
            if stats is not None:
                stats["down"] += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        engine = self.server.engine
        client = self.request
        peer = self.client_address
        # Redirected connections always have peer IP == this host's interface IP.
        if peer[0] != client.getsockname()[0]:
            return
        orig = engine.conn_map.get((peer[0], peer[1]))
        if orig is None:
            return
        server_ip, server_port = orig

        try:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            upstream = _connect_upstream(server_ip, server_port)
        except OSError as exc:
            engine.log(f"upstream {server_ip}:{server_port} failed: {exc}", "WARNING")
            return
        try:
            self._relay(engine, client, upstream, server_ip)
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _relay(self, engine, client, upstream, server_ip):
        hello = _read_client_hello(client)
        if not hello:
            return
        stats = {"down": 0}
        try:
            if hello[0] == _TLS_HANDSHAKE:
                records = fragment_client_hello(hello, engine.mode)
                delay = engine.frag_delay()
                engine.log(f"{sni_name(hello)} -> {len(records)} TLS records ({engine.mode})")
                for i, rec in enumerate(records):
                    upstream.sendall(rec)
                    if delay and i < len(records) - 1:
                        time.sleep(delay)
            else:
                upstream.sendall(hello)
        except OSError:
            return

        reverse = threading.Thread(target=_pump, args=(upstream, client, stats), daemon=True)
        reverse.start()
        _pump(client, upstream)
        reverse.join(timeout=2.0)

        with engine._stats_lock:
            engine.stats["https_total"] += 1
            if stats["down"] == 0:
                engine.stats["https_reset"] += 1
                engine.log(f"{server_ip}: 0 bytes back after ClientHello -- DPI reset "
                           f"or IP block (browser retry may still succeed).", "WARNING")


class _RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# --------------------------------------------------------------------------- #
# Engine: WinDivert capture loop + dispatch
# --------------------------------------------------------------------------- #
class DivertEngine:
    def __init__(self, mode="Standard", log_callback=None):
        self.mode = mode
        self.log_callback = log_callback
        self.conn_map = {}                  # (src_addr,src_port)->(dst_addr,dst_port)
        self.doh = DohClient()
        self.stats = {"dns": 0, "https_total": 0, "https_reset": 0, "quic": 0}
        self._stats_lock = threading.Lock()
        self._w = None
        self._relay_server = None
        self._pool = None
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._capture_thread = None
        self.running = False

    # -- logging ----------------------------------------------------------- #
    def log(self, message, level="INFO"):
        if self.log_callback:
            self.log_callback(f"[{time.strftime('%H:%M:%S')}] [{level}] {message}")

    def frag_delay(self):
        return {"Extreme": 0.006, "Advanced": 0.003}.get(self.mode, 0.004)

    # -- lifecycle --------------------------------------------------------- #
    def start(self):
        """Probe DoH, start the relay, open WinDivert. Returns True on success."""
        self.log("Probing DoH upstream...")
        ok, detail = self.doh.probe()
        if not ok:
            self.log(f"DoH unreachable ({detail}). Not starting -- DNS would break.", "ERROR")
            return False
        self.log(f"DoH upstream reachable via {detail}.")

        self._relay_server = _RelayServer(("0.0.0.0", RELAY_PORT), _RelayHandler)
        self._relay_server.engine = self
        threading.Thread(target=self._relay_server.serve_forever,
                         name="relay", daemon=True).start()

        filter_str = _build_filter()
        try:
            self._w = pydivert.WinDivert(filter_str)
            self._w.open()
        except Exception as exc:
            self.log(f"Failed to open WinDivert: {exc}", "ERROR")
            self.log("Run as Administrator (WinDivert needs to load its driver).", "ERROR")
            self._relay_server.shutdown()
            self._relay_server.server_close()
            self._relay_server = None
            return False

        self._pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="doh")
        self._stop.clear()
        self.running = True
        self._capture_thread = threading.Thread(target=self._run_loop, name="capture", daemon=True)
        self._capture_thread.start()
        self.log("Engine running. ALL apps on this PC are now bypassed transparently.")
        return True

    def stop(self):
        self.running = False
        self._stop.set()
        if self._w is not None:
            try:
                self._w.close()
            except Exception:
                pass
        if self._pool is not None:
            self._pool.shutdown(wait=False)
            self._pool = None
        if self._relay_server is not None:
            try:
                self._relay_server.shutdown()
                self._relay_server.server_close()
            except Exception:
                pass
            self._relay_server = None
        self.doh.close()
        self.conn_map.clear()
        self.log("Engine stopped. Normal traffic restored.")

    # -- capture loop ------------------------------------------------------ #
    def _send(self, packet):
        with self._send_lock:
            try:
                self._w.send(packet)
            except Exception:
                pass

    def _run_loop(self):
        while not self._stop.is_set():
            try:
                packet = self._w.recv()
            except Exception:
                if self._stop.is_set():
                    break
                continue
            try:
                self._dispatch(packet)
            except Exception:
                self._send(packet)  # never drop a packet on a bug

    def _dispatch(self, packet):
        if packet.udp is not None:
            if packet.dst_port == 53 and packet.is_outbound:
                # DNS resolution can block (DoH round-trip) -> offload to the pool.
                self._pool.submit(self._handle_udp_dns, packet)
            elif packet.dst_port == 443 and packet.is_outbound:
                # Drop QUIC/HTTP3: its SNI lives in an encrypted Initial packet we
                # can't fragment, so we force the app to fall back to TCP/443
                # (which we DO fragment). Not re-injecting == dropping.
                with self._stats_lock:
                    self.stats["quic"] += 1
                return
            else:
                self._send(packet)
        elif packet.tcp is not None:
            # TCP rewriting runs INLINE on the capture thread, so conn_map needs
            # no lock.
            if packet.is_outbound and packet.dst_port in INTERCEPT_TCP_PORTS:
                self._redirect_443(packet)
            elif packet.src_port == RELAY_PORT:
                self._rewrite_relay_reply(packet)
            else:
                self._send(packet)
        else:
            self._send(packet)

    def _handle_udp_dns(self, packet):
        query = packet.payload
        if not query:
            return
        try:
            answer = self.doh.resolve(query)
        except Exception as exc:
            self.log(f"DNS over DoH failed: {exc}; dropped", "WARNING")
            return  # fail-closed: drop rather than leak the plaintext query
        with self._stats_lock:
            self.stats["dns"] += 1
        # Turn the captured query into its reply, in place.
        packet.src_addr, packet.dst_addr = packet.dst_addr, packet.src_addr
        packet.src_port, packet.dst_port = packet.dst_port, packet.src_port
        packet.payload = answer
        packet.direction = Direction.INBOUND
        self._send(packet)

    def _redirect_443(self, packet):
        key = (packet.src_addr, packet.src_port)
        self.conn_map[key] = (packet.dst_addr, packet.dst_port)
        if packet.tcp.rst:
            self.conn_map.pop(key, None)
        packet.dst_addr = packet.src_addr
        packet.dst_port = RELAY_PORT
        packet.direction = Direction.INBOUND
        self._send(packet)

    def _rewrite_relay_reply(self, packet):
        key = (packet.dst_addr, packet.dst_port)
        server = self.conn_map.get(key)
        if server is None:
            return  # stray/teardown packet -> drop
        packet.src_addr, packet.src_port = server
        packet.direction = Direction.INBOUND
        self._send(packet)
        if packet.tcp.rst or packet.tcp.fin:
            self.conn_map.pop(key, None)
