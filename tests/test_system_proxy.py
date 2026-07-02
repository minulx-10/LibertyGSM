from __future__ import annotations

import unittest
from unittest import mock

import system_proxy
from system_proxy import SystemProxy, parse_networksetup_proxy


class ParseNetworksetupTests(unittest.TestCase):
    def test_parses_enabled_proxy(self):
        out = "Enabled: Yes\nServer: 10.0.0.1\nPort: 8080\nAuthenticated Proxy Enabled: 0\n"
        info = parse_networksetup_proxy(out)
        self.assertTrue(info["enabled"])
        self.assertEqual(info["server"], "10.0.0.1")
        self.assertEqual(info["port"], "8080")

    def test_parses_disabled_proxy(self):
        info = parse_networksetup_proxy("Enabled: No\nServer:\nPort: 0\n")
        self.assertFalse(info["enabled"])
        self.assertEqual(info["server"], "")


class _FakeRun:
    """Records commands and returns canned stdout keyed by a matching substring."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, cmd):
        self.calls.append(cmd)
        stdout = ""
        for key, value in self.responses.items():
            if key in cmd:
                stdout = value
                break
        return mock.Mock(stdout=stdout, returncode=0)


class MacOSApplyRevertTests(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(system_proxy.sys, "platform", "darwin")
        self.p.start()
        self.addCleanup(self.p.stop)

    def test_apply_sets_both_proxies_on_enabled_services(self):
        fake = _FakeRun({
            "-listallnetworkservices": "An asterisk denotes a disabled service\nWi-Fi\n*Bridge\n",
            "-getwebproxy": "Enabled: No\nServer:\nPort: 0\n",
            "-getsecurewebproxy": "Enabled: No\nServer:\nPort: 0\n",
        })
        with mock.patch.object(system_proxy, "_run", fake):
            sp = SystemProxy("127.0.0.1", 10809)
            self.assertTrue(sp.apply())

        joined = [" ".join(c) for c in fake.calls]
        # Disabled service (*Bridge) is skipped; Wi-Fi gets web + secure web proxy.
        self.assertTrue(any("-setwebproxy Wi-Fi 127.0.0.1 10809" in j for j in joined))
        self.assertTrue(any("-setsecurewebproxy Wi-Fi 127.0.0.1 10809" in j for j in joined))
        self.assertFalse(any("Bridge" in j and "-setwebproxy" in j for j in joined))

    def test_revert_restores_prior_proxy_when_one_existed(self):
        fake = _FakeRun({
            "-listallnetworkservices": "Header\nWi-Fi\n",
            "-getwebproxy": "Enabled: Yes\nServer: 10.0.0.1\nPort: 3128\n",
            "-getsecurewebproxy": "Enabled: No\nServer:\nPort: 0\n",
        })
        with mock.patch.object(system_proxy, "_run", fake):
            sp = SystemProxy("127.0.0.1", 10809)
            sp.apply()
            fake.calls.clear()
            sp.revert()

        joined = [" ".join(c) for c in fake.calls]
        # Prior web proxy restored to 10.0.0.1:3128; secure (was off) turned off.
        self.assertTrue(any("-setwebproxy Wi-Fi 10.0.0.1 3128" in j for j in joined))
        self.assertTrue(any("-setsecurewebproxystate Wi-Fi off" in j for j in joined))


class LinuxApplyRevertTests(unittest.TestCase):
    def setUp(self):
        self.p = mock.patch.object(system_proxy.sys, "platform", "linux")
        self.p.start()
        self.addCleanup(self.p.stop)

    def test_apply_sets_gnome_manual_mode(self):
        fake = _FakeRun({"get": "'none'\n"})
        with mock.patch.object(system_proxy, "_run", fake), \
             mock.patch.object(system_proxy.shutil, "which", return_value="/usr/bin/gsettings"):
            sp = SystemProxy("127.0.0.1", 10809)
            self.assertTrue(sp.apply())
            fake.calls.clear()
            sp.revert()

        joined = [" ".join(c) for c in fake.calls]
        # Reverts to the prior mode captured on apply ('none').
        self.assertTrue(any("set org.gnome.system.proxy mode none" in j for j in joined))

    def test_apply_without_gsettings_is_graceful(self):
        with mock.patch.object(system_proxy.shutil, "which", return_value=None):
            sp = SystemProxy("127.0.0.1", 10809)
            self.assertFalse(sp.apply())  # no crash, just reports False


if __name__ == "__main__":
    unittest.main()
