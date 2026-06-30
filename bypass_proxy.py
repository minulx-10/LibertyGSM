import socket
import threading
import time
import logging
import urllib.request
import json
import ssl
import struct
import random

from tls_frag import load_exclude_hosts, is_host_excluded


# Setup logger
logger = logging.getLogger("LibertyGSM.bypass_proxy")


# ---------------------------------------------------------------------------
# TLS ClientHello record-layer fragmentation (the actual SNI/DPI bypass)
#
# Splitting the ClientHello at the TCP layer -- just calling send() at different
# byte offsets -- does NOT defeat a DPI box that reassembles the TCP stream
# before reading the SNI: it still sees the whole host name and resets the
# connection. The technique that works (proven by Jigsaw's Intra and used by
# FreeGSM) is TLS *record-layer* fragmentation: re-emit the single ClientHello
# as TWO (or more) valid TLS records. A DPI that reads the SNI out of the first
# record finds a short record with no name in it, while the destination server
# reassembles the handshake across records and connects normally.
# ---------------------------------------------------------------------------
_TLS_HANDSHAKE = 0x16
_TLS_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}


def tls_record_len(buf):
    """Return (record_body_len, ok) for a buffer that begins with a TLS record
    header. ok is False when the buffer is not a TLS handshake record."""
    if len(buf) < 5 or buf[0] != _TLS_HANDSHAKE:
        return 0, False
    if int.from_bytes(buf[1:3], "big") not in _TLS_VERSIONS:
        return 0, False
    return int.from_bytes(buf[3:5], "big"), True


def _make_record(version_bytes, body):
    """Wrap handshake `body` bytes in a fresh TLS handshake record header."""
    return bytes([_TLS_HANDSHAKE]) + version_bytes + struct.pack("!H", len(body)) + body


def _split_offsets(body_len, chunks, first_small=False):
    """Pick strictly-increasing body offsets that cut `body_len` into `chunks`
    records. The first cut stays early (well before the SNI)."""
    if body_len <= 1:
        return []
    chunks = max(2, min(chunks, body_len))
    step = body_len / chunks
    offsets = []
    for i in range(1, chunks):
        offsets.append(max(1, min(body_len - 1, int(round(step * i)))))
    if first_small and offsets:
        offsets[0] = 1  # force a break right after the handshake type byte
    out = []
    for o in offsets:
        if not out or o > out[-1]:
            out.append(o)
    return out


def _sni_location(payload):
    """Return (host_start, host_len) -- absolute offsets of the SNI host name
    inside a ClientHello payload -- or None if it can't be found."""
    try:
        if len(payload) < 6 or payload[0] != _TLS_HANDSHAKE or payload[5] != 0x01:
            return None
        pos = 5
        hs_len = int.from_bytes(payload[pos + 1:pos + 4], "big")
        end = min(pos + 4 + hs_len, len(payload))
        pos += 4 + 2 + 32                                       # hdr + version + random
        pos += 1 + payload[pos]                                 # session_id
        pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")  # cipher_suites
        pos += 1 + payload[pos]                                 # compression
        if pos + 2 > end:
            return None
        ext_end = min(pos + 2 + int.from_bytes(payload[pos:pos + 2], "big"), end)
        pos += 2
        while pos + 4 <= ext_end:
            etype = int.from_bytes(payload[pos:pos + 2], "big")
            elen = int.from_bytes(payload[pos + 2:pos + 4], "big")
            body = pos + 4
            if etype == 0x0000:  # server_name
                p = body + 2
                if p < ext_end and payload[p] == 0x00:
                    nlen = int.from_bytes(payload[p + 1:p + 3], "big")
                    return (p + 3, nlen)
                return None
            pos = body + elen
        return None
    except Exception:
        return None


def fragment_client_hello(hello, mode):
    """Re-emit a ClientHello as a list of valid TLS records to send in order.

    When the SNI host name can be located, the split point is placed in the
    MIDDLE of the host name so the name is cut across the record boundary -- no
    single record contains the full string. (Falls back to an early split when
    the SNI can't be parsed.)

    Standard -> 2 records (split through the SNI).
    Advanced -> 3 records (tiny first record + a split through the SNI).
    Extreme  -> ~8 records.
    Anything that is not a well-formed ClientHello record is returned unchanged.
    """
    record_len, ok = tls_record_len(hello)
    if not ok or record_len < 2 or len(hello) < 5 + record_len:
        return [hello]

    version = hello[1:3]
    body = hello[5:5 + record_len]
    trailing = hello[5 + record_len:]  # bytes after the record (normally empty)

    # Body-relative offset that lands in the middle of the SNI host name.
    sni_split = None
    loc = _sni_location(hello)
    if loc:
        host_start, host_len = loc
        if host_len >= 2:
            cut = (host_start - 5) + host_len // 2  # to body coordinates
            if 0 < cut < len(body):
                sni_split = cut

    if mode == "Extreme":
        offsets = _split_offsets(len(body), chunks=8)
        if sni_split and sni_split not in offsets:
            offsets = sorted(set(offsets) | {sni_split})
    elif mode == "Advanced":
        early = 1
        mid = sni_split if sni_split else random.randint(2, min(59, max(2, len(body) - 1)))
        offsets = sorted({o for o in (early, mid) if 0 < o < len(body)})
    else:  # Standard
        split = sni_split if sni_split else random.randint(1, min(59, max(1, len(body) - 1)))
        offsets = [split]

    records = []
    prev = 0
    for off in offsets:
        records.append(_make_record(version, body[prev:off]))
        prev = off
    records.append(_make_record(version, body[prev:]))
    if trailing:
        records.append(trailing)
    return records


def sni_name(payload):
    """Best-effort SNI host name from a ClientHello, for logging only."""
    loc = _sni_location(payload)
    if not loc:
        return "<no-sni>"
    host_start, host_len = loc
    return payload[host_start:host_start + host_len].decode("ascii", "replace") or "<empty>"


# Openers that bypass the system proxy. Our DoH lookups MUST go out directly --
# never back through this proxy, because the system proxy points at us. An empty
# ProxyHandler disables proxy use for these specific requests.
_doh_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_doh_opener_unverified = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
)

class BypassProxyServer:
    def __init__(
        self,
        host="127.0.0.1",
        port=10809,
        bypass_mode="Standard",
        use_doh=True,
        log_callback=None,
        event_callback=None,
    ):
        self.host = host
        self.port = port
        self.bypass_mode = bypass_mode
        self.use_doh = use_doh
        self.log_callback = log_callback
        self.event_callback = event_callback
        self.server_socket = None
        self.running = False
        self.dns_cache = {}
        self.exclude_hosts = load_exclude_hosts()
        self.active_connections = 0
        self.stats = {"dns": 0, "https_total": 0, "https_reset": 0, "quic": 0}
        self._lock = threading.Lock()

    def log(self, message, level="INFO"):
        """Sends logs to the callback (for GUI) and to the standard logger."""
        formatted_message = f"[{time.strftime('%H:%M:%S')}] [{level}] {message}"
        if level == "INFO":
            logger.info(message)
        elif level == "WARNING":
            logger.warning(message)
        elif level == "ERROR":
            logger.error(message)

        if self.log_callback:
            self.log_callback(formatted_message)

    def start(self):
        """Starts the local proxy server."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(128)
            self.log(f"Proxy server started on {self.host}:{self.port}")
            self.log(f"Mode: {self.bypass_mode} | DNS-over-HTTPS: {'Enabled' if self.use_doh else 'Disabled'}")
        except Exception as e:
            self.log(f"Failed to bind to {self.host}:{self.port}: {e}", "ERROR")
            self.running = False
            return False

        # Start accept loop in a separate thread
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return True

    def stop(self):
        """Stops the local proxy server."""
        self.running = False
        if self.server_socket:
            try:
                # Connect to self to break the accept() block if it's waiting
                self.server_socket.close()
            except Exception:
                pass
        self.log("Proxy server stopped.")

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, client_addr), daemon=True).start()
            except Exception:
                # Socket closed or other accept error
                break

    def _resolve_host(self, host):
        """Resolves hostname using DNS-over-HTTPS or local fallback."""
        # If it's already an IP address, return it
        try:
            socket.inet_aton(host)
            return host
        except socket.error:
            pass

        # Check cache
        with self._lock:
            if host in self.dns_cache:
                return self.dns_cache[host]

        if self.use_doh:
            # Endpoints addressed by literal IP so resolving the resolver never
            # needs DNS itself. 1.0.0.1 / 8.8.4.4 are the secondary anycast IPs:
            # many school/ISP networks block 1.1.1.1 *specifically* but not its
            # sibling address for the very same service.
            doh_endpoints = [
                "https://1.1.1.1/dns-query?name={host}&type=A",
                "https://1.0.0.1/dns-query?name={host}&type=A",
                "https://8.8.8.8/resolve?name={host}&type=A",
                "https://8.8.4.4/resolve?name={host}&type=A",
            ]
            headers = {"Accept": "application/dns-json"}

            # Verified first (a trustworthy answer the network cannot forge),
            # then unverified as a last resort for networks that tamper with the
            # DoH TLS connection itself.
            for verify in (True, False):
                opener = _doh_opener if verify else _doh_opener_unverified
                for url_template in doh_endpoints:
                    url = url_template.format(host=host)
                    try:
                        req = urllib.request.Request(url, headers=headers)
                        with opener.open(req, timeout=2.5) as response:
                            res_data = json.loads(response.read().decode())
                    except Exception:
                        continue  # try next endpoint / verify mode

                    for answer in res_data.get("Answer", []):
                        if answer.get("type") == 1:  # A record (IPv4)
                            ip = answer["data"]
                            with self._lock:
                                self.dns_cache[host] = ip
                                self.stats["dns"] += 1
                            self.log(f"Resolved {host} -> {ip} via DoH ({url.split('?')[0]}, verify={verify})")
                            return ip

        # Fallback to local DNS resolution
        try:
            ip = socket.gethostbyname(host)
            with self._lock:
                self.dns_cache[host] = ip
                self.stats["dns"] += 1
            self.log(f"Resolved {host} -> {ip} via Local DNS (Fallback)")
            return ip
        except Exception as e:
            self.log(f"Failed to resolve {host}: {e}", "WARNING")
            raise

    def _handle_client(self, client_sock, client_addr):
        with self._lock:
            self.active_connections += 1
        
        try:
            client_sock.settimeout(10.0)
            # Read request line and headers
            request_data = b""
            while b"\r\n\r\n" not in request_data:
                chunk = client_sock.recv(4096)
                if not chunk:
                    break
                request_data += chunk

            if not request_data:
                return

            # Split request line and headers
            parts = request_data.split(b"\r\n\r\n", 1)
            header_lines = parts[0].split(b"\r\n")
            request_line = header_lines[0].decode("latin-1")
            
            # Parse request line (e.g. CONNECT example.com:443 HTTP/1.1)
            req_words = request_line.split()
            if len(req_words) < 2:
                return
            
            method, url = req_words[0], req_words[1]

            if method == "CONNECT":
                # HTTPS Tunneling
                if ":" in url:
                    host, port_str = url.split(":", 1)
                    port = int(port_str)
                else:
                    host = url
                    port = 443
                
                self.log(f"Tunneling HTTPS to {host}:{port}")
                self._handle_https_tunnel(client_sock, host, port)
            else:
                # HTTP Proxy
                # Parse host from header
                host = None
                port = 80
                for line in header_lines[1:]:
                    line_str = line.decode("latin-1")
                    if line_str.lower().startswith("host:"):
                        host_val = line_str.split(":", 1)[1].strip()
                        if ":" in host_val:
                            host, port_str = host_val.split(":", 1)
                            port = int(port_str)
                        else:
                            host = host_val
                        break
                
                if not host:
                    # Try to extract from absolute URL
                    if url.startswith("http://"):
                        url_parts = url[7:].split("/", 1)
                        host_val = url_parts[0]
                        if ":" in host_val:
                            host, port_str = host_val.split(":", 1)
                            port = int(port_str)
                        else:
                            host = host_val

                if host:
                    self.log(f"Proxying HTTP to {host}:{port}")
                    self._handle_http_request(client_sock, host, port, request_data)
                else:
                    client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")

        except (ConnectionError, socket.timeout, TimeoutError) as e:
            # Common browser behavior (speculative connection closures, navigate away, etc.)
            logger.debug(f"Connection closed by client {client_addr}: {e}")
        except Exception as e:
            self.log(f"Error handling connection {client_addr}: {e}", "WARNING")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            with self._lock:
                self.active_connections -= 1

    def _handle_https_tunnel(self, client_sock, host, port):
        try:
            ip = self._resolve_host(host)
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Connect to destination server
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        server_sock.settimeout(10.0)
        
        try:
            server_sock.connect((ip, port))
        except Exception as e:
            self.log(f"Failed to connect to target {host}:{port}: {e}", "WARNING")
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Notify client connection is established
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Now, read the full TLS ClientHello record from the client.
        hello_data = self._read_client_hello(client_sock)
        if not hello_data:
            server_sock.close()
            return

        # Fragment only a genuine TLS ClientHello; forward anything else as-is.
        if len(hello_data) >= 5 and hello_data[0] == _TLS_HANDSHAKE:
            sni = sni_name(hello_data)
            if is_host_excluded(sni, self.exclude_hosts):
                self.log(f"Intercepted ClientHello (SNI={sni}, {len(hello_data)}B). Fragmentation bypassed (whitelisted).", "INFO")
                server_sock.sendall(hello_data)
            else:
                self.log(f"Intercepted ClientHello (SNI={sni}, {len(hello_data)}B). Applying {self.bypass_mode} record-layer fragmentation.", "INFO")
                self._send_fragmented_tls(server_sock, hello_data)
        else:
            # Not TLS or unknown, send normally
            server_sock.sendall(hello_data)

        # Remove timeouts for active relaying
        client_sock.settimeout(None)
        server_sock.settimeout(None)

        # Start bidirectional pipe and inspect the outcome.
        stats = self._pipe(client_sock, server_sock)

        # If the server sent back nothing after our (fragmented) ClientHello, the
        # connection was killed before any ServerHello -- the classic signature
        # of an SNI/DPI reset or an IP-level block, NOT a code bug.
        if stats["down"] == 0:
            reason = "RST from network" if stats["reset"] else "connection dropped, no reply"
            with self._lock:
                self.stats["https_total"] += 1
                self.stats["https_reset"] += 1
            self.log(
                f"{host}: server returned 0 bytes after ClientHello ({reason}). "
                f"DPI likely blocked this SNI -- record fragmentation was not enough here.",
                "WARNING",
            )
            if self.event_callback:
                self.event_callback("bypass_fail", host)
        else:
            with self._lock:
                self.stats["https_total"] += 1
            self.log(f"{host}: OK (relayed up={stats['up']}B down={stats['down']}B)")
            if self.event_callback:
                self.event_callback("bypass_success", host)

    def _handle_http_request(self, client_sock, host, port, original_data):
        try:
            ip = self._resolve_host(host)
        except Exception:
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.settimeout(10.0)
        
        try:
            server_sock.connect((ip, port))
        except Exception as e:
            self.log(f"Failed to connect to HTTP target {host}:{port}: {e}", "WARNING")
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return

        # Bypass DPI by changing 'Host: ...' header case to 'hOsT: ...' (standard, but bypasses simple regex checkers)
        # Or split the HTTP request into small packets
        modified_data = original_data
        
        # Simple string replacement for Host header (case insensitive search, replace with hOsT)
        try:
            lines = original_data.split(b"\r\n")
            for i, line in enumerate(lines):
                if line.lower().startswith(b"host:"):
                    # Change 'Host:' to 'hOsT:'
                    lines[i] = b"hOsT:" + line[5:]
                    break
            modified_data = b"\r\n".join(lines)
            self.log(f"Intercepted HTTP request. Obfuscating host header to bypass DPI.", "INFO")
        except Exception:
            pass

        # Send request in small fragments (DPI Bypass)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        chunk_size = 10
        for i in range(0, len(modified_data), chunk_size):
            server_sock.sendall(modified_data[i:i+chunk_size])
            time.sleep(0.002)

        client_sock.settimeout(None)
        server_sock.settimeout(None)

        # Start bidirectional pipe
        self._pipe(client_sock, server_sock)

    def _read_client_hello(self, sock):
        """Reads the first client packet, growing the buffer until the full TLS
        ClientHello record is present (so we can fragment it cleanly)."""
        sock.settimeout(5.0)
        try:
            buf = sock.recv(16384)
        except socket.timeout:
            return b""
        if len(buf) < 5 or buf[0] != _TLS_HANDSHAKE:
            return buf  # not TLS -- hand back whatever arrived

        need = 5 + int.from_bytes(buf[3:5], "big")
        while len(buf) < need and len(buf) < 65535:
            try:
                chunk = sock.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def _send_fragmented_tls(self, server_sock, data):
        """Re-emits the ClientHello as multiple TLS records (record-layer
        fragmentation) so a DPI box cannot read the SNI from the first record."""
        try:
            records = fragment_client_hello(data, self.bypass_mode)

            if self.bypass_mode == "Extreme":
                delay = 0.006
            elif self.bypass_mode == "Advanced":
                delay = 0.003
            else:  # Standard -- small delay so the two records leave as separate
                # TCP segments (a single coalesced packet defeats the purpose).
                delay = 0.004

            self.log(f"Fragmented ClientHello into {len(records)} TLS record(s).")
            for i, record in enumerate(records):
                server_sock.sendall(record)
                if delay and i < len(records) - 1:
                    time.sleep(delay)
        except (ConnectionError, socket.timeout) as e:
            logger.debug(f"Connection closed during fragmentation: {e}")
        except Exception as e:
            self.log(f"Fragmentation send error: {e}", "WARNING")
            try:
                server_sock.sendall(data)  # try sending it all as fallback
            except Exception:
                pass

    def _pipe(self, client_sock, server_sock):
        """Relays traffic bidirectionally and BLOCKS until the connection ends.

        This must block: the caller (_handle_client) closes client_sock in its
        finally clause as soon as this returns, so if we spawned the relay
        threads and returned immediately, the sockets would be closed out from
        under the still-running relays and every connection would reset.
        """
        # stats["up"] = client->server bytes, stats["down"] = server->client
        # bytes (i.e. the server's reply), stats["reset"] = an RST was seen.
        stats = {"up": 0, "down": 0, "reset": False}
        t1 = threading.Thread(target=self._relay, args=(client_sock, server_sock, stats, "up"), daemon=True)
        t2 = threading.Thread(target=self._relay, args=(server_sock, client_sock, stats, "down"), daemon=True)
        t1.start()
        t2.start()
        # Wait for both directions to finish before unwinding (and closing socks).
        t1.join()
        t2.join()
        return stats

    def _relay(self, src, dst, stats, key):
        try:
            while self.running:
                data = src.recv(16384)
                if not data:
                    break
                stats[key] += len(data)
                dst.sendall(data)
        except ConnectionResetError:
            stats["reset"] = True
        except Exception:
            pass
        finally:
            try:
                src.close()
            except Exception:
                pass
            try:
                dst.close()
            except Exception:
                pass
