#!/usr/bin/env python3
"""Automated tests for Agent Scoreboard Auto-Judge, HTTP endpoints, and hook installer."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import auto_judge
import install
from scoreboard import ScoreboardStore, make_handler


class _FakeHttpResponse:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


class TestAutoJudgeCore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.store = ScoreboardStore(self.data_dir)
        self.store.set_pin("1234")
        self.store.add_agent("Antigravity", "Antigravity AI assistant", "1234")
        self.store.add_agent("Codex", "OpenAI Codex CLI assistant", "1234")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hook_fast_exit_when_disabled_or_idle_or_greeting(self) -> None:
        with mock.patch("auto_judge._spawn_detached_evaluator") as spawn_mock:
            # Disabled by default
            resp = auto_judge.handle_stop_hook(
                json.dumps({"lastUserInput": "Fix bug and run tests", "terminationReason": "NO_TOOL_CALL"}),
                data_dir_override=str(self.data_dir),
            )
            self.assertEqual(resp, {"decision": "allow"})
            spawn_mock.assert_not_called()

            # Enable Auto-Judge
            auto_judge.save_config(self.data_dir, {"enabled": True})

            # Non-NO_TOOL_CALL termination reason
            resp = auto_judge.handle_stop_hook(
                json.dumps({"lastUserInput": "Fix bug", "terminationReason": "USER_CANCELED"}),
                data_dir_override=str(self.data_dir),
            )
            self.assertEqual(resp, {"decision": "allow"})
            spawn_mock.assert_not_called()

            # fullyIdle False
            resp = auto_judge.handle_stop_hook(
                json.dumps({"lastUserInput": "Fix bug", "terminationReason": "NO_TOOL_CALL", "fullyIdle": False}),
                data_dir_override=str(self.data_dir),
            )
            self.assertEqual(resp, {"decision": "allow"})
            spawn_mock.assert_not_called()

            # Trivial greeting with no tool work
            resp = auto_judge.handle_stop_hook(
                json.dumps({"lastUserInput": "Thanks!", "terminationReason": "NO_TOOL_CALL", "fullyIdle": True}),
                data_dir_override=str(self.data_dir),
            )
            self.assertEqual(resp, {"decision": "allow"})
            spawn_mock.assert_not_called()

    def test_hook_spawns_detached_evaluator_on_substantive_turn(self) -> None:
        auto_judge.save_config(self.data_dir, {"enabled": True})
        payload = {
            "conversationId": "conv-123",
            "lastUserInput": "Fix login bug and run unit tests",
            "terminationReason": "NO_TOOL_CALL",
            "fullyIdle": True,
        }
        with mock.patch("auto_judge._spawn_detached_evaluator") as spawn_mock:
            resp = auto_judge.handle_stop_hook(
                json.dumps(payload),
                data_dir_override=str(self.data_dir),
            )
            self.assertEqual(resp, {"decision": "allow"})
            self.assertEqual(spawn_mock.call_count, 1)
            queued_path, queued_data_dir = spawn_mock.call_args[0]
            self.assertEqual(queued_data_dir, self.data_dir)
            self.assertTrue(queued_path.is_file())
            self.assertEqual(json.loads(queued_path.read_text(encoding="utf-8"))["conversationId"], "conv-123")

    def test_secret_masking_before_external_api(self) -> None:
        fake_openai = "sk-test" + ("A" * 24)
        fake_google = "AIza" + ("B" * 30)
        fake_gh = "ghp_" + ("C" * 24)
        raw = f"OPENAI_API_KEY={fake_openai} key={fake_google} token={fake_gh} password=mysecretpass"
        masked = auto_judge.mask_secrets(raw)
        self.assertNotIn(fake_openai, masked)
        self.assertNotIn(fake_google, masked)
        self.assertNotIn(fake_gh, masked)
        self.assertNotIn("mysecretpass", masked)
        self.assertIn("[REDACTED", masked)

    def test_providers_propose_into_pending_and_deduplicate(self) -> None:
        transcript_file = self.data_dir / "transcript.jsonl"
        fake_token = "ghp_" + ("Z" * 24)
        transcript_file.write_text(
            "\n".join([
                json.dumps({"type": "USER_INPUT", "content": "Run tests and fix bug"}),
                json.dumps({
                    "type": "PLANNER_RESPONSE",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": f"TOKEN={fake_token} python -m unittest"}}],
                    "content": "Ran all 20 tests and all passed.",
                }),
            ]) + "\n",
            encoding="utf-8",
        )

        # 1. Gemini proposal + deduplication
        auto_judge.save_config(
            self.data_dir,
            {"enabled": True, "provider": "gemini", "api_key": "test-gemini-key-9999"},
        )
        captured_bodies: list[dict] = []

        def fake_gemini_urlopen(req, timeout=30):
            captured_bodies.append(json.loads(req.data.decode("utf-8")))
            self.assertEqual(req.get_header("X-goog-api-key"), "test-gemini-key-9999")
            return _FakeHttpResponse({
                "candidates": [{
                    "content": {
                        "parts": [{
                            "text": json.dumps({
                                "should_propose": True,
                                "agent": "Antigravity",
                                "category": "Trust",
                                "delta": 1,
                                "reason": "Verified all 20 tests passing before finishing.",
                            })
                        }]
                    }
                }]
            })

        payload = {
            "conversationId": "conv-gem-1",
            "transcriptPath": str(transcript_file),
            "lastUserInput": "Run tests and fix bug",
            "cwd": str(self.data_dir),
        }
        with mock.patch("urllib.request.urlopen", side_effect=fake_gemini_urlopen):
            res1 = auto_judge.evaluate_hook_payload(payload, store=self.store)
            res2 = auto_judge.evaluate_hook_payload(payload, store=self.store)

        self.assertTrue(res1["ok"])
        self.assertEqual(res1["status"], "proposed")
        self.assertEqual(res2["status"], "duplicate")
        self.assertEqual(len(captured_bodies), 1)
        self.assertNotIn(fake_token, json.dumps(captured_bodies[0]))

        pending = self.store.load_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["proposed_by"], "AutoJudge")
        self.assertEqual(pending[0]["category"], "Trust")
        self.assertEqual(pending[0]["delta"], 1)
        # Official leaderboard untouched before PIN approval
        board = self.store.build_leaderboard()
        ag = next(r for r in board["leaderboard"] if r["agent"] == "Antigravity")
        self.assertEqual(ag["total"], 0)

        # 2. OpenAI notable_only skip
        auto_judge.save_config(
            self.data_dir,
            {"enabled": True, "provider": "openai", "api_key": "test-openai-key-1111", "mode": "notable_only"},
        )

        def fake_openai_skip(req, timeout=30):
            return _FakeHttpResponse({
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "should_propose": False,
                            "reason": "Routine file check; nothing notable.",
                        })
                    }
                }]
            })

        payload2 = dict(payload, conversationId="conv-oai-2")
        with mock.patch("urllib.request.urlopen", side_effect=fake_openai_skip):
            res_skip = auto_judge.evaluate_hook_payload(payload2, store=self.store)
        self.assertEqual(res_skip["status"], "skipped")
        self.assertEqual(len(self.store.load_pending()), 1)

        # 2b. OpenRouter provider
        auto_judge.save_config(
            self.data_dir,
            {"enabled": True, "provider": "openrouter", "api_key": "test-or-key-2222"},
        )

        def fake_openrouter_urlopen(req, timeout=30):
            self.assertIn("openrouter.ai/api/v1/chat/completions", req.full_url)
            return _FakeHttpResponse({
                "choices": [{
                    "message": {
                        "content": json.dumps({
                            "should_propose": True,
                            "agent": "Antigravity",
                            "category": "Wisdom",
                            "delta": 1,
                            "reason": "Fixed root cause cleanly.",
                        })
                    }
                }]
            })

        with mock.patch("urllib.request.urlopen", side_effect=fake_openrouter_urlopen):
            res_or = auto_judge.evaluate_hook_payload(dict(payload, conversationId="conv-or-3"), store=self.store)
        self.assertEqual(res_or["status"], "proposed")
        self.assertEqual(len(self.store.load_pending()), 2)

        # 3. Ollama manual evaluation without API key
        auto_judge.save_config(
            self.data_dir,
            {"enabled": True, "provider": "ollama", "clear_api_key": True, "model": "llama3.2"},
        )

        def fake_ollama_urlopen(req, timeout=30):
            self.assertIn("127.0.0.1:11434/api/chat", req.full_url)
            return _FakeHttpResponse({
                "message": {
                    "content": json.dumps({
                        "should_propose": True,
                        "agent": "Codex",
                        "category": "Execution",
                        "delta": 1,
                        "reason": "Fixed bug cleanly with passing tests.",
                    })
                }
            })

        with mock.patch("urllib.request.urlopen", side_effect=fake_ollama_urlopen):
            res_manual = auto_judge.evaluate_manual(
                store=self.store,
                agent="Codex",
                summary="Fixed bug and all tests passed.",
            )
        self.assertEqual(res_manual["status"], "proposed")
        self.assertEqual(len(self.store.load_pending()), 3)
        self.assertEqual(self.store.load_pending()[2]["agent"], "Codex")

    def test_cli_hook_and_evaluate_payload_deletes_temp_file(self) -> None:
        auto_judge.save_config(self.data_dir, {"enabled": False})
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "auto_judge.py"), "--hook", "--data-dir", str(self.data_dir)],
            input=json.dumps({"lastUserInput": "Hello", "terminationReason": "NO_TOOL_CALL"}),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        self.assertEqual(json.loads(proc.stdout.strip()), {"decision": "allow"})

        # --evaluate-payload deletes temp payload file
        qfile = self.data_dir / "queued.json"
        qfile.write_text(json.dumps({"conversationId": "c1", "lastUserInput": "Test"}), encoding="utf-8")
        proc2 = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parent / "auto_judge.py"),
                "--evaluate-payload",
                str(qfile),
                "--data-dir",
                str(self.data_dir),
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
        self.assertEqual(proc2.returncode, 0)
        self.assertFalse(qfile.exists())


class TestAutoJudgeHttpAndInstall(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ScoreboardStore(self.tmp.name)
        self.store.set_pin("5555")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.store))
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _req(self, path: str, method: str = "GET", body: dict | None = None, pin: str = "", headers: dict | None = None) -> tuple[int, dict]:
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
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read().decode("utf-8"))

    def test_auto_judge_http_endpoints_and_security(self) -> None:
        # UI includes Auto-Judge tab
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/", timeout=5) as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("Auto-Judge", html)
        self.assertIn("Judge Last Work", html)

        # Unauthenticated / wrong PIN POSTs rejected
        status, _ = self._req("/api/auto-judge/config", "POST", {"enabled": True})
        self.assertEqual(status, 401)
        status, _ = self._req("/api/auto-judge/test", "POST", {})
        self.assertEqual(status, 401)
        status, _ = self._req("/api/auto-judge/run", "POST", {"summary": "test"})
        self.assertEqual(status, 401)

        # Cross-origin rejected
        status, _ = self._req(
            "/api/auto-judge/config",
            "POST",
            {"enabled": True},
            pin="5555",
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(status, 403)

        # Save config with PIN -> GET returns masked key only
        secret_key = "test-secret-key-9876"
        status, saved = self._req(
            "/api/auto-judge/config",
            "POST",
            {"enabled": True, "provider": "gemini", "api_key": secret_key, "mode": "notable_only"},
            pin="5555",
        )
        self.assertEqual(status, 200)
        self.assertTrue(saved["ok"])

        status, cfg = self._req("/api/auto-judge/config")
        self.assertEqual(status, 200)
        self.assertNotIn("api_key", cfg)
        self.assertNotIn(secret_key, json.dumps(cfg))
        self.assertTrue(cfg["has_api_key"])
        self.assertEqual(cfg["api_key_masked"], "••••9876")

        # Blank api_key preserves saved key; clear_api_key clears it
        status, _ = self._req(
            "/api/auto-judge/config",
            "POST",
            {"enabled": True, "provider": "gemini", "api_key": ""},
            pin="5555",
        )
        self.assertEqual(status, 200)
        _, cfg2 = self._req("/api/auto-judge/config")
        self.assertEqual(cfg2["api_key_masked"], "••••9876")

        # Test Judge endpoint (mocked)
        with mock.patch("auto_judge.test_connection", return_value={"ok": True, "message": "Connected!"}):
            status, test_res = self._req("/api/auto-judge/test", "POST", {}, pin="5555")
        self.assertEqual(status, 200)
        self.assertTrue(test_res["ok"])

        # Manual Judge endpoint (mocked provider)
        with mock.patch(
            "auto_judge.call_provider",
            return_value=json.dumps({
                "should_propose": True,
                "agent": "Codex",
                "category": "Trust",
                "delta": 1,
                "reason": "Showed real passing tests.",
            }),
        ):
            status, run_res = self._req(
                "/api/auto-judge/run",
                "POST",
                {"agent": "Codex", "summary": "Fixed test suite and verified output."},
                pin="5555",
            )
        self.assertEqual(status, 200)
        self.assertEqual(run_res["status"], "proposed")
        self.assertEqual(len(self.store.load_pending()), 1)

        # Tunneled requests MUST be blocked with 403 even with a valid bearer token
        token = self.store.rotate_api_token("5555")
        bearer = {"X-Forwarded-For": "1.2.3.4", "Authorization": f"Bearer {token}"}
        for path, method, body in (
            ("/api/auto-judge/config", "GET", None),
            ("/api/auto-judge/config", "POST", {"enabled": False}),
            ("/api/auto-judge/test", "POST", {}),
            ("/api/auto-judge/run", "POST", {"summary": "hi"}),
        ):
            status, _ = self._req(path, method, body, pin="5555", headers=bearer)
            self.assertEqual(status, 403)

    def test_install_generates_hooks_json_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as plugin_dir:
            dest = Path(plugin_dir) / "agent-scoreboard"
            install.install_antigravity_plugin(dest)
            install.install_antigravity_plugin(dest)  # idempotent second run
            hooks_file = dest / "hooks.json"
            self.assertTrue(hooks_file.is_file())
            hooks_data = json.loads(hooks_file.read_text(encoding="utf-8"))
            stop_list = hooks_data["agent-scoreboard-auto-judge"]["Stop"]
            self.assertEqual(len(stop_list), 1)
            self.assertEqual(stop_list[0]["type"], "command")
            self.assertEqual(stop_list[0]["timeout"], 10)
            self.assertIn("auto_judge.py", stop_list[0]["command"])
            self.assertIn("--hook", stop_list[0]["command"])


if __name__ == "__main__":
    unittest.main()
