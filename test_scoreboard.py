#!/usr/bin/env python3
"""Automated test suite for Agent Scoreboard (core ledger, tamper detection, HTTP API, MCP server)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import mcp_server
from scoreboard import DEFAULT_CATEGORIES, MAX_PENDING_PROPOSALS, REMOTE_PROPOSALS_PER_MINUTE, ScoreboardStore, is_tunneled_request, make_handler


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

    def test_api_tokens_are_pin_gated_and_only_hashes_are_stored(self) -> None:
        self.store.set_pin("8642")
        with self.assertRaises(PermissionError):
            self.store.rotate_api_token("0000")

        first = self.store.rotate_api_token("8642")
        self.assertTrue(self.store.verify_api_token(first))
        settings = json.loads(self.store.settings_path.read_text(encoding="utf-8"))
        self.assertNotIn(first, json.dumps(settings))
        self.assertEqual(len(settings["api_token_sha256"]), 64)

        second = self.store.rotate_api_token("8642")
        self.assertFalse(self.store.verify_api_token(first))
        self.assertTrue(self.store.verify_api_token(second))
        self.store.reset_pin_and_archive()
        self.assertFalse(self.store.verify_api_token(second))

    def test_proposals_have_field_and_queue_limits(self) -> None:
        with self.assertRaises(ValueError):
            self.store.propose_score(
                agent="Claude", category="Trust", delta=1,
                reason="x" * 2001, proposed_by="Codex",
            )

        pending = [{"id": f"pen_{index}"} for index in range(MAX_PENDING_PROPOSALS)]
        self.store._write_json(self.store.pending_path, {"pending": pending})
        with self.assertRaisesRegex(ValueError, "Pending queue is full"):
            self.store.propose_score(
                agent="Claude", category="Trust", delta=1,
                reason="Valid bounded reason", proposed_by="Codex",
            )

    def test_remote_proposal_rate_limit(self) -> None:
        for _ in range(REMOTE_PROPOSALS_PER_MINUTE):
            self.assertTrue(self.store.allow_remote_proposal())
        self.assertFalse(self.store.allow_remote_proposal())

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
        status, _, payload = self._req_bytes(path, method, body, pin, headers)
        return status, payload.decode("utf-8", errors="replace")

    def _req_bytes(self, path: str, method: str = "GET", body: dict | None = None, pin: str = "", headers: dict | None = None) -> tuple[int, dict[str, str], bytes]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req_headers = {"Content-Type": "application/json"} if data is not None else {}
        if method == "POST":
            req_headers.setdefault("Origin", f"http://127.0.0.1:{self.port}")
        if headers:
            req_headers.update(headers)
        if pin:
            req_headers["X-Scoreboard-Pin"] = pin
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, headers=req_headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def test_http_brand_assets(self) -> None:
        for path in ("/assets/app_icon.png", "/assets/chinlung_logo.png"):
            with self.subTest(path=path):
                status, headers, payload = self._req_bytes(path)
                self.assertEqual(status, 200)
                self.assertEqual(headers.get("Content-Type"), "image/png")
                self.assertTrue(payload)

    def test_http_backup_listing(self) -> None:
        created = self.store.reset_pin_and_archive()
        status, body = self._req("/api/backups")
        self.assertEqual(status, 200)
        parsed = json.loads(body)
        self.assertIn("backup_dir", parsed)
        names = [item["name"] for item in parsed["backups"]]
        self.assertIn(created.name, names)
        self.assertTrue(any(n.startswith("scoreboard.auto.") for n in names))

    def test_custom_backup_folder_and_manual_backup(self) -> None:
        with tempfile.TemporaryDirectory() as custom_dir:
            status, body = self._req("/api/backup/folder", "POST", {"folder": custom_dir})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["backup_dir"], custom_dir)
            status, body2 = self._req("/api/backup/now", "POST", {})
            self.assertEqual(status, 200)
            fname = json.loads(body2)["file"]
            self.assertTrue((Path(custom_dir) / fname).is_file())

            # Reject deleting scoreboard.json
            status, _ = self._req("/api/backup/delete", "POST", {"file": "scoreboard.json"})
            self.assertEqual(status, 400)

            # Delete valid backup file from UI endpoint
            status, _ = self._req("/api/backup/delete", "POST", {"file": fname})
            self.assertEqual(status, 200)
            self.assertFalse((Path(custom_dir) / fname).is_file())

    def test_http_backup_download_and_path_traversal_rejection(self) -> None:
        created = self.store.reset_pin_and_archive()
        status, headers, payload = self._req_bytes(
            "/api/backup/download?file=" + urllib.parse.quote(created.name)
        )
        self.assertEqual(status, 200)
        self.assertIn(f'filename="{created.name}"', headers.get("Content-Disposition", ""))
        self.assertEqual(payload, created.read_bytes())

        status, headers, payload = self._req_bytes(
            "/api/backup/download?file=..%2F..%2Fscoreboard.json"
        )
        self.assertEqual(status, 200)
        self.assertIn('filename="scoreboard.json"', headers.get("Content-Disposition", ""))
        self.assertEqual(payload, self.store.scoreboard_path.read_bytes())

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

    def test_http_api_token_generation_and_local_csrf_guards(self) -> None:
        status, _ = self._req("/api/pin/setup", "POST", {"pin": "5555"})
        self.assertEqual(status, 200)

        status, _ = self._req("/api/api-token", "POST", {}, headers={"Origin": "https://attacker.example"})
        self.assertEqual(status, 403)
        status, _ = self._req("/api/api-token", "POST", {})
        self.assertEqual(status, 401)

        status, token_text = self._req("/api/api-token", "POST", {}, pin="5555")
        self.assertEqual(status, 200)
        token = json.loads(token_text)["token"]
        self.assertTrue(self.store.verify_api_token(token))

        status, _ = self._req(
            "/api/pin/reset", "POST", {}, headers={"Origin": "https://attacker.example"}
        )
        self.assertEqual(status, 403)
        self.assertTrue(json.loads(self._req("/api/state")[1])["has_pin"])

        status, _ = self._req(
            "/api/pin/reset", "POST", {}, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)

        status, html = self._req("/")
        self.assertEqual(status, 200)
        self.assertIn("Remote Access", html)
        self.assertIn("Generate / Replace API Token", html)

    def test_http_rejects_oversized_request_body(self) -> None:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/propose",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "65537",
                "Origin": f"http://127.0.0.1:{self.port}",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("Expected an oversized request to be rejected.")
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, 413)
        self.assertEqual(self.store.load_pending(), [])

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
        self.assertTrue(is_tunneled_request(SimpleNamespace(
            headers={"Host": "localhost"}, client_address=("192.0.2.10", 8000)
        )))
        self.assertFalse(is_tunneled_request(SimpleNamespace(
            headers={"Host": "localhost"}, client_address=("127.0.0.1", 8000)
        )))

        status, _ = self._req("/", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 403)

        status, _ = self._req("/api/warnings", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 401)

        status, _ = self._req("/api/warnings?agent=Claude", headers={"X-Forwarded-For": "1.2.3.4"})
        self.assertEqual(status, 401)

        self.store.set_pin("5555")
        token = self.store.rotate_api_token("5555")
        bearer = {"X-Forwarded-For": "1.2.3.4", "Authorization": f"Bearer {token}"}
        status, _ = self._req("/api/warnings", headers=bearer)
        self.assertEqual(status, 200)
        status, _ = self._req("/api/warnings?agent=Claude", headers=bearer)
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
            headers=bearer,
        )
        self.assertEqual(status, 200)

        status, _ = self._req(
            "/api/propose",
            "POST",
            {"agent": "Claude", "category": "Trust", "delta": 1, "reason": "R"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        )
        self.assertEqual(status, 401)

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

    def test_remove_agent_preserves_integrity(self) -> None:
        self.store.set_pin("7777")
        self.store.add_agent("Research Subagent", "Read-only explorer", "7777")
        self.store.record_score(
            agent="Research Subagent",
            category="Execution",
            delta=1,
            reason="Found exact root cause",
            pin="7777",
        )
        self.store.remove_agent("Research Subagent", "7777")
        key = self.store.verify_pin("7777")
        board = self.store.build_leaderboard(pin_key=key)
        self.assertTrue(board["integrity"]["ok"])
        self.assertTrue(board["integrity"]["verified_signatures"])
        names = [r["agent"] for r in board["leaderboard"]]
        self.assertNotIn("Research Subagent", names)
        self.assertNotIn("Research Subagent", self.store.brief_path.read_text(encoding="utf-8"))

    def test_reset_pin_archives_and_keeps_agents(self) -> None:
        self.store.set_pin("1111")
        self.store.add_agent("MyAgent", "Custom", "1111")
        self.store.record_score(agent="MyAgent", category="Trust", delta=1, reason="Honest", pin="1111")
        backup = self.store.reset_pin_and_archive()
        self.assertTrue(backup.exists())
        board = self.store.build_leaderboard()
        self.assertFalse(board["has_pin"])
        self.assertTrue(board["integrity"]["ok"])
        self.assertIn("MyAgent", [r["agent"] for r in board["leaderboard"]])

    def test_http_reset_pin_button_endpoint(self) -> None:
        status, _ = self._req("/api/pin/setup", "POST", {"pin": "2222"})
        self.assertEqual(status, 200)
        status, _ = self._req("/api/pin/reset", "POST", {})
        self.assertEqual(status, 200)
        status, state_text = self._req("/api/state")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(state_text)["has_pin"])


if __name__ == "__main__":
    unittest.main()
