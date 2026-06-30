from __future__ import annotations

import unittest

from tls_frag import fragment_client_hello, is_host_excluded, sni_name


def make_client_hello(host: str) -> bytes:
    host_bytes = host.encode("ascii")
    server_name = b"\x00" + len(host_bytes).to_bytes(2, "big") + host_bytes
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    sni_extension = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    extensions = len(sni_extension).to_bytes(2, "big") + sni_extension

    handshake_body = (
        b"\x03\x03"
        + (b"\x00" * 32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + len(handshake_body).to_bytes(3, "big") + handshake_body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


class TlsFragmentationTests(unittest.TestCase):
    def test_sni_name_is_parsed_from_client_hello(self):
        hello = make_client_hello("blocked.example")

        self.assertEqual(sni_name(hello), "blocked.example")

    def test_standard_fragmentation_splits_host_across_records(self):
        host = "blocked.example"
        hello = make_client_hello(host)

        records = fragment_client_hello(hello, "Standard")

        self.assertGreaterEqual(len(records), 2)
        self.assertEqual(b"".join(record[5:] for record in records), hello[5:])
        self.assertFalse(any(host.encode("ascii") in record for record in records))

    def test_wildcard_exclude_hosts_match_subdomains_and_apex(self):
        excludes = {"*.example.com"}

        self.assertTrue(is_host_excluded("example.com", excludes))
        self.assertTrue(is_host_excluded("www.example.com", excludes))
        self.assertFalse(is_host_excluded("example.net", excludes))


if __name__ == "__main__":
    unittest.main()
