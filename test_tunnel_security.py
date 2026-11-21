#!/usr/bin/env python3
"""Unit tests specifically covering is_tunneled_request security logic."""

import unittest
from scoreboard import is_tunneled_request

class DummyHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)

class DummyRequest:
    def __init__(self, headers=None):
        self.headers = DummyHeaders(headers or {})

class TestTunnelSecurity(unittest.TestCase):
    def test_legitimate_localhost_requests(self):
        # Localhost variants without proxy headers
        valid_hosts = [
            "localhost",
            "localhost:8080",
            "127.0.0.1",
            "127.0.0.1:5000",
            "[::1]",
            "[::1]:8080",
        ]
        for host in valid_hosts:
            req = DummyRequest({"Host": host})
            self.assertFalse(is_tunneled_request(req), f"Failed for valid host: {host}")

    def test_proxy_headers(self):
        # Presence of X-Forwarded-For or Forwarded should flag as tunneled even if host is localhost
        req_xff = DummyRequest({"Host": "localhost", "X-Forwarded-For": "192.168.1.50"})
        self.assertTrue(is_tunneled_request(req_xff))

        req_fwd = DummyRequest({"Host": "127.0.0.1", "Forwarded": "for=192.168.1.50"})
        self.assertTrue(is_tunneled_request(req_fwd))

    def test_crafted_host_headers(self):
        # External or malicious host headers
        malicious_hosts = [
            "evil.com",
            "localhost.evil.com",
            "127.0.0.1.evil.com",
            "evil.com:8080",
        ]
        for host in malicious_hosts:
            req = DummyRequest({"Host": host})
            self.assertTrue(is_tunneled_request(req), f"Failed to catch malicious host: {host}")

    def test_malformed_host_strings(self):
        # Missing host, empty, malformed IPv6, etc.
        malformed = [
            "",
            "   ",
            "[::2]",
            "[invalid-ipv6]",
        ]
        for host in malformed:
            req = DummyRequest({"Host": host})
            self.assertTrue(is_tunneled_request(req), f"Failed to catch malformed host: {repr(host)}")

        # Missing Host header entirely
        req_no_host = DummyRequest({})
        self.assertTrue(is_tunneled_request(req_no_host))

if __name__ == "__main__":
    unittest.main()
