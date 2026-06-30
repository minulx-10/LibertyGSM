"""TLS ClientHello record-layer fragmentation -- the core SNI/DPI bypass.

Splitting a ClientHello at the TCP layer (sending at different byte offsets) does
NOT defeat a DPI box that reassembles the TCP stream before reading the SNI. The
technique that works (proven by Jigsaw's Intra and used by FreeGSM) is TLS
*record-layer* fragmentation: re-emit the single ClientHello as several valid TLS
records, cut through the middle of the SNI host name. A DPI that reads the SNI
out of one record never sees the whole name, while the destination server
reassembles the handshake across records and connects normally.

Shared by both engines (the legacy userspace proxy and the WinDivert engine).
"""

from __future__ import annotations

import os
import random
import struct
import sys

# Record-layer content type 0x16 == handshake; legal versions for a ClientHello.
_TLS_HANDSHAKE = 0x16
_TLS_VERSIONS = {0x0301, 0x0302, 0x0303, 0x0304}


def get_exclude_hosts_path() -> str:
    if getattr(sys, "frozen", False):
        base_dir = os.path.dirname(sys.executable)
    else:
        try:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        except Exception:
            base_dir = os.getcwd()
    return os.path.join(base_dir, "exclude_hosts.txt")


def load_exclude_hosts() -> set[str]:
    path = get_exclude_hosts_path()
    default_hosts = [
        "*.nexon.com",
        "*.nexon.co.kr",
        "*.nx.com",
        "*.nexon.io",
        "*.nexon.net"
    ]
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("# LibertyGSM - Exclude Hosts\n")
                f.write("# Domains listed here will bypass TLS record-layer fragmentation.\n")
                f.write("# Use this for sites that fail to connect or throw handshake/TLS reset errors.\n")
                f.write("# Lines starting with # are ignored. Wildcards are supported (e.g., *.nexon.com).\n\n")
                for host in default_hosts:
                    f.write(f"{host}\n")
        except Exception:
            pass
        return set(default_hosts)

    hosts = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.add(line.lower())
    except Exception:
        return set(default_hosts)
    return hosts


def is_host_excluded(host: str, exclude_hosts: set[str]) -> bool:
    if not host or host in ("<no-sni>", "<empty>"):
        return False
    host = host.lower().strip()
    for pattern in exclude_hosts:
        pattern = pattern.strip().lower()
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if host == suffix or host.endswith("." + suffix):
                return True
        else:
            if host == pattern or host.endswith("." + pattern):
                return True
    return False



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


def sni_location(payload):
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


def sni_name(payload):
    """Best-effort SNI host name from a ClientHello, for logging only."""
    loc = sni_location(payload)
    if not loc:
        return "<no-sni>"
    host_start, host_len = loc
    return payload[host_start:host_start + host_len].decode("ascii", "replace") or "<empty>"


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
    loc = sni_location(hello)
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
