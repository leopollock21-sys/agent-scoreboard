#!/usr/bin/env python3
"""Automated test suite for Agent Scoreboard (core ledger, tamper detection, HTTP API, MCP server)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import mcp_server
from scoreboard import DEFAULT_CATEGORIES, ScoreboardStore, make_handler


class TestScoreboardCore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ScoreboardStore(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_defaults_and_pin_flow(self) -> None:
        board = self.store.build_leaderboard()
        self.assertFalse(board["has_pin"])
        self.assertEqual(board["categories"], DEFAULT_CATEGORIES)
        self.assertTrue(board["integrity"]["ok"])

        with self.assertRaises(PermissionError):
            self.store.record_score(
                agent="Claude", category="Trust", delta=1, reason="Honest", pin="1234"
            )

        self.store.set_pin("9876")
        self.assertTrue(self.store.load_scoreboard()["pin_hash"] is not None)

        with self.assertRaises(PermissionError):
            self.store.record_score(
                agent="Claude", category="Trust", delta=1, reason="Honest", pin="0000"
            )

        self.store.record_score(
            agent="Claude", category="Trust", delta=1, reason="Showed real test logs", pin="9876"
        )
        self.store.record_score(
            agent="Codex", category="Faith", delta=-1, reason="Skipped git commit rule", pin="9876"
        )

        key = self.store.verify_pin("9876")
        board = self.store.build_leaderboard(pin_key=key)
        self.assertTrue(board["integrity"]["ok"])
        self.assertTrue(board["integrity"]["verified_signatures"])
        self.assertEqual(board["leaderboard"][0]["agent"], "Claude")
        self.assertEqual(board["leaderboard"][0]["total"], 1)

        codex = next(r for r in board["leaderboard"] if r["agent"] == "Codex")
        self.assertEqual(codex["status"], "WARNING")
        self.assertTrue(any("Faith (-1)" in w for w in codex["warnings"]))

        brief = self.store.brief_path.read_text(encoding="utf-8")
        self.assertIn("Showed real test logs", brief)
        self.assertIn("Skipped git commit rule", brief)

    def test_pending_propose_and_approve_reject(self) -> None:
        self.store.set_pin("4321")
        # Ensure Antigravity is in the leaderboard
        self.store.add_agent("Antigravity", "AI coding assistant", "4321")

        p1 = self.store.propose_score(
            agent="Antigravity",
            category="Wisdom",
            delta=1,
            reason="Found simple root cause cleanly",
            proposed_by="Antigravity",
        )
        p2 = self.store.propose_score(
            agent="Antigravity",
            category="Affection",
            delta=1,
            reason="Fake self-praise",
            proposed_by="Antigravity",
        )

        # Proposals must NOT alter official scores before approval
        board = self.store.build_leaderboard()
        ag = next(r for r in board["leaderboard"] if r["agent"] == "Antigravity")
        self.assertEqual(ag["total"], 0)
        self.assertEqual(len(board["pending"]), 2)

        # Reject fake one, approve real one
        self.store.resolve_pending(p2["id"], "reject", "4321")
        self.store.resolve_pending(p1["id"], "approve", "4321")

        board = self.store.build_leaderboard()
        ag = next(r for r in board["leaderboard"] if r["agent"] == "Antigravity")
        self.assertEqual(ag["total"], 1)
        self.assertEqual(ag["scores"]["Wisdom"], 1)
        self.assertEqual(len(board["pending"]), 0)
        self.assertEqual(ag["recent_reasons"][0]["reason"], "Found simple root cause cleanly")

        # Add Antigravity to leaderboard if not present
        if not any(r["agent"] == "Antigravity" for r in board["leaderboard"]):
            self.store.add_agent("Antigravity", "AI coding assistant", "4321")

    def test_tamper_detection_blocks_cheating(self) -> None:
        self.store.set_pin("2468")
        self.store.record_score(
            agent="ChatGPT", category="Trust", delta=-1, reason="Guessed without checking", pin="2468"
        )

        # Simulate a rogue agent editing scoreboard.json directly to erase its punishment
        raw = json.loads(self.store.scoreboard_path.read_text(encoding="utf-8"))
        raw["ledger"][0]["delta"] = 1
        raw["ledger"][0]["reason"] = "Actually I was great"
        self.store.scoreboard_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")

        integrity = self.store.check_integrity(self.store.verify_pin("2468"))
        self.assertFalse(integrity["ok"])
        self.assertGreaterEqual(len(integrity["issues"]), 1)

        with self.assertRaises(RuntimeError):
            self.store.record_score(
                agent="ChatGPT", category="Execution", delta=1, reason="Another task", pin="2468"
            )


class TestHttpAndMcp(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ScoreboardStore(self.tmp.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _req(self, path: str, method: str = "GET", body: dict | None = None, pin: str = "", headers: dict | None = None) -> tuple[int, str]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req_headers = {"Content-Type": "application/json"} if data is not None else {}
        if headers:
            req_headers.update(headers)
        if pin:
            req_headers["X-Scoreboard-Pin"] = pin
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, headers=req_headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8")

    def test_http_ui_and_pending_approval_flow(self) -> None:
        status, html = self._req("/")
        self.assertEqual(status, 200)
        self.assertIn("Agent Scoreboard", html)

        status, _ = self._req("/api/pin/setup", "POST", {"pin": "5555"})
        self.assertEqual(status, 200)

        status, prop_text = self._req(
            "/api/propose",
            "POST",
            {
                "agent": "Claude",
                "category": "Affection",
                "delta": 1,
                "reason": "Clear, polite, plain language",
                "proposed_by": "Claude",
            },
        )
        self.assertEqual(status, 200)
        prop_id = json.loads(prop_text)["proposal"]["id"]

        # Without PIN, approval must be rejected
        status, _ = self._req(f"/api/pending/{prop_id}/approve", "POST", {})
        self.assertEqual(status, 401)

        # With PIN, approval succeeds
        status, _ = self._req(f"/api/pending/{prop_id}/approve", "POST", {}, pin="5555")
        self.assertEqual(status, 200)

        status, warn_text = self._req("/api/warnings?agent=Claude")
        self.assertEqual(status, 200)
        warn_data = json.loads(warn_text)
        self.assertEqual(warn_data["agents"][0]["total"], 1)
        self.assertEqual(
            warn_data["agents"][0]["recent_reasons"][0]["reason"],
            "Clear, polite, plain language",
        )

    def test_mcp_server_only_exposes_safe_tools(self) -> None:
        init_resp = mcp_server.handle_request(self.store, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init_resp["result"]["serverInfo"]["name"], "agent-scoreboard")

        tools_resp = mcp_server.handle_request(self.store, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = [t["name"] for t in tools_resp["result"]["tools"]]
        self.assertEqual(set(tool_names), {"get_leaderboard", "get_agent_warnings", "propose_score"})

        prop_resp = mcp_server.handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "propose_score",
                    "arguments": {
                        "agent": "Codex",
                        "category": "Execution",
                        "delta": 1,
                        "reason": "Clean diff and green tests",
                        "proposed_by": "Antigravity",
                    },
                },
            },
        )
        self.assertFalse(prop_resp["result"]["isError"])
        payload = json.loads(prop_resp["result"]["content"][0]["text"])
        self.assertEqual(payload["status"], "pending_human_approval")

    def test_tunnel_security(self) -> None:
        status, _ = self._req("/", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 403)

        status, _ = self._req("/api/warnings", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 200)

        status, _ = self._req("/api/warnings?agent=Claude", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 200)

        status, _ = self._req(
            "/api/score",
            "POST",
            {"agent": "A", "category": "Trust", "delta": 1, "reason": "R"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        self.assertEqual(status, 403)

        status, _ = self._req(
            "/api/propose",
            "POST",
            {"agent": "Claude", "category": "Trust", "delta": 1, "reason": "R"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        self.assertEqual(status, 200)

        # Host header spoofing (localhost.evil.com) must also be blocked
        status, _ = self._req("/", headers={"Host": "localhost.evil.com"})
        self.assertEqual(status, 403)

    def test_pin_cooldown(self) -> None:
        self.store.set_pin("1234")
        for _ in range(5):
            with self.assertRaises(PermissionError) as cm:
                self.store.verify_pin("wrong")
            self.assertEqual(str(cm.exception), "Invalid PIN.")

        with self.assertRaises(PermissionError) as cm:
            self.store.verify_pin("wrong")
        self.assertEqual(str(cm.exception), "Too many wrong PIN attempts. Wait a few seconds.")

    def test_file_locking(self) -> None:
        from pathlib import Path
        from scoreboard import FileLock

        target = Path(self.tmp.name) / "test.json"
        lock_file = target.with_suffix(target.suffix + ".lock")
        with FileLock(target):
            self.assertTrue(lock_file.exists())
        self.assertFalse(lock_file.exists())


if __name__ == "__main__":
    unittest.main()
