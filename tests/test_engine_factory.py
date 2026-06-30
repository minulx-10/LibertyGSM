from __future__ import annotations

import unittest
from unittest import mock

from engines import factory


class EngineFactoryTests(unittest.TestCase):
    def test_macos_uses_portable_proxy_until_native_engine_exists(self):
        with mock.patch.object(factory.sys, "platform", "darwin"):
            info = factory.get_engine_info()

        self.assertTrue(info.supported)
        self.assertFalse(info.transparent)
        self.assertEqual(info.key, "portable_proxy")
        self.assertIn("Network Extension", info.reason)
        self.assertIn("127.0.0.1:10809", info.reason)

    def test_linux_uses_portable_proxy_until_native_engine_exists(self):
        with mock.patch.object(factory.sys, "platform", "linux"):
            info = factory.get_engine_info()

        self.assertTrue(info.supported)
        self.assertFalse(info.transparent)
        self.assertEqual(info.key, "portable_proxy")
        self.assertIn("TUN", info.reason)

    def test_android_is_gated_until_native_engine_exists(self):
        with mock.patch.object(factory.sys, "platform", "android"):
            info = factory.get_engine_info()

        self.assertFalse(info.supported)
        self.assertIn("VpnService", info.reason)

    def test_ios_is_gated_until_native_engine_exists(self):
        with mock.patch.object(factory.sys, "platform", "ios"):
            info = factory.get_engine_info()

        self.assertFalse(info.supported)
        self.assertIn("NEPacketTunnelProvider", info.reason)


if __name__ == "__main__":
    unittest.main()
