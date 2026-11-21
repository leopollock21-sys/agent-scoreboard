#!/usr/bin/env python3
"""
Agent Scoreboard — Tamper-evident human-in-the-loop scoring, reward,
and punishment leaderboard for AI agents (Antigravity, Claude, Codex, ChatGPT).

Zero external dependencies (Python 3 standard library only).
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import errno
import os
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_CATEGORIES = ["Affection", "Trust", "Faith", "Execution", "Wisdom"]
DEFAULT_AGENTS = [
    ("Antigravity", "Antigravity AI coding assistant"),
    ("Claude", "Claude Code / Claude Desktop assistant"),
    ("Codex", "OpenAI Codex CLI assistant"),
    ("ChatGPT", "ChatGPT assistant"),
    ("Subagents", "Background specialist subagents"),
]
DEFAULT_PORT = 8787
PBKDF2_ITERATIONS = 100_000


def get_data_dir(override: str | None = None) -> Path:
    if override:
        base = Path(override)
    elif os.environ.get("AGENT_SCOREBOARD_DIR"):
        base = Path(os.environ["AGENT_SCOREBOARD_DIR"])
    else:
        base = Path.home() / ".agent-scoreboard"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def is_tunneled_request(request) -> bool:
    """Check if the request is proxied or tunneled."""
    # Check for X-Forwarded-For or Forwarded header
    if 'X-Forwarded-For' in request.headers or 'Forwarded' in request.headers:
        return True
    
    # Check if Host is localhost or 127.0.0.1 or [::1]
    host = request.headers.get('Host', '').strip()
    if not host:
        return True
    
    # Proper hostname parsing
    if host.startswith('['):
        # IPv6
        if host == '[::1]' or host.startswith('[::1]:'):
            return False
    else:
        # IPv4 or hostname
        # Split host:port and check hostname
        hostname = host.split(':')[0].lower()
        if hostname in ('localhost', '127.0.0.1'):
            return False
            
    return True


def _derive_pin_key(pin: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PBKDF2_ITERATIONS,
    )


def _canonical_entry_bytes(entry: dict[str, Any]) -> bytes:
    payload = {
        "id": entry["id"],
        "ts": entry["ts"],
        "agent": entry["agent"],
        "category": entry["category"],
        "delta": int(entry["delta"]),
        "reason": entry["reason"],
        "source": entry["source"],
        "prev_hash": entry["prev_hash"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_chain_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_entry_bytes(entry)).hexdigest()


def _compute_entry_sig(entry: dict[str, Any], pin_key: bytes) -> str:
    return hmac.new(pin_key, _canonical_entry_bytes(entry), hashlib.sha256).hexdigest()


class FileLock:
    """Cross-process file lock context manager with timeout and stale lock cleanup."""
    def __init__(self, path: Path, timeout: float = 5.0, retry_interval: float = 0.1):
        self.path = path.with_suffix(path.suffix + ".lock")
        self.timeout = timeout
        self.retry_interval = retry_interval
        self._lock_fd = None

    def __enter__(self):
        start_time = time.time()
        while time.time() - start_time < self.timeout:
            try:
                # Try to create the lock file with O_CREAT|O_EXCL
                self._lock_fd = os.open(
                    self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                # Write our PID to help with stale lock cleanup
                os.write(self._lock_fd, str(os.getpid()).encode('utf-8'))
                return self
            except FileExistsError:
                # Lock exists, check if it's stale
                if self._is_stale_lock():
                    self._cleanup_stale_lock()
                    continue
                time.sleep(self.retry_interval)
        raise TimeoutError(f"Could not acquire lock on {self.path} after {self.timeout} seconds")

    def _is_stale_lock(self) -> bool:
        try:
            with open(self.path, 'rb') as f:
                pid = int(f.read().decode('utf-8'))
            try:
                os.kill(pid, 0)
                return False
            except (ProcessLookupError, OSError) as e:
                # If OSError, check errno; EPERM means process exists but we can't signal
                if isinstance(e, OSError) and e.errno == errno.EPERM:
                    return False
                return True
        except (OSError, ValueError):
            # Fallback: check if lock file is older than 30 seconds
            return time.time() - self.path.stat().st_mtime > 30

    def _cleanup_stale_lock(self) -> None:
        try:
            os.unlink(self.path)
        except OSError:
            pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            try:
                os.unlink(self.path)
            except OSError:
                pass
        self._lock_fd = None

class ScoreboardStore:
    """Thread-safe tamper-evident scoreboard ledger + pending proposal queue."""

    def __init__(self, data_dir: str | Path | None = None):
        self.data_dir = get_data_dir(str(data_dir) if data_dir else None)
        self.scoreboard_path = self.data_dir / "scoreboard.json"
        self.pending_path = self.data_dir / "pending.json"
        self.brief_path = self.data_dir / "agent_brief.md"
        self._lock = threading.RLock()
        self._failed_pins = []  # Timestamps of failed attempts
        self._ensure_initialized()

    def _ensure_initialized(self):
        if not self.scoreboard_path.exists():
            self._write_json(self.scoreboard_path, {
                "categories": list(DEFAULT_CATEGORIES),
                "agents": {},
                "ledger": [],
                "pin_hash": None,
                "pin_salt": None
            })
        if not self.pending_path.exists():
            self._write_json(self.pending_path, {"pending": []})
        if not self.brief_path.exists():
            self.regenerate_brief()

    def _write_json(self, path: Path, data: dict[str, Any]):
        tmp = path.with_suffix(".json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)

    def load_scoreboard(self) -> dict[str, Any]:
        with open(self.scoreboard_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_pending(self) -> list[dict[str, Any]]:
        with open(self.pending_path, "r", encoding="utf-8") as f:
            return json.load(f).get("pending", [])

    def set_pin(self, pin: str):
        pin = (pin or "").strip()
        if len(pin) < 4:
            raise ValueError("PIN must be at least 4 characters.")
        with self._lock:
            with FileLock(self.scoreboard_path):
                data = self.load_scoreboard()
                if data.get("pin_hash"):
                    raise PermissionError("PIN is already set.")
                salt = secrets.token_bytes(16)
                key = _derive_pin_key(pin, salt.hex())
                data["pin_salt"] = salt.hex()
                data["pin_hash"] = hashlib.sha256(key).hexdigest()
                self._write_json(self.scoreboard_path, data)

    def verify_pin(self, pin: str) -> bytes:
        pin = (pin or "").strip()
        with self._lock:
            # Check cooldown
            now = time.time()
            self._failed_pins = [t for t in self._failed_pins if now - t < 15]
            if len(self._failed_pins) >= 5:
                raise PermissionError('Too many wrong PIN attempts. Wait a few seconds.')

            data = self.load_scoreboard()
            salt_hex = data.get("pin_salt")
            pin_hash = data.get("pin_hash")
            if not salt_hex or not pin_hash:
                raise PermissionError("PIN is not set yet. Set your PIN first.")
            key = _derive_pin_key(pin, salt_hex)
            if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), pin_hash):
                self._failed_pins.append(now)
                raise PermissionError("Invalid PIN.")
            
            self._failed_pins = [] # Reset on success
            return key

    def check_integrity(self, pin_key: bytes | None = None) -> dict[str, Any]:
        """Verify SHA-256 hash chain (always) and HMAC signatures (when unlocked)."""
        data = self.load_scoreboard()
        ledger = data.get("ledger", [])
        issues: list[str] = []
        prev_hash = "GENESIS"
        for idx, entry in enumerate(ledger):
            try:
                if entry.get("prev_hash") != prev_hash:
                    issues.append(f"Entry #{idx + 1} ({entry.get('id', '?')}): broken chain link.")
                expected_hash = _compute_chain_hash(entry)
                if entry.get("chain_hash") != expected_hash:
                    issues.append(f"Entry #{idx + 1} ({entry.get('id', '?')}): payload hash mismatch.")
                if pin_key is not None:
                    expected_sig = _compute_entry_sig(entry, pin_key)
                    if not hmac.compare_digest(str(entry.get("sig", "")), expected_sig):
                        issues.append(f"Entry #{idx + 1} ({entry.get('id', '?')}): invalid PIN signature.")
                prev_hash = str(entry.get("chain_hash", ""))
            except Exception as exc:
                issues.append(f"Entry #{idx + 1}: malformed record ({exc}).")
        return {
            "ok": len(issues) == 0,
            "verified_signatures": pin_key is not None,
            "entries_checked": len(ledger),
            "issues": issues,
        }

    def add_agent(self, name: str, description: str, pin: str) -> dict[str, Any]:
        name = name.strip()
        if not name:
            raise ValueError("Agent name cannot be empty.")
        with self._lock:
            with FileLock(self.scoreboard_path):
                self.verify_pin(pin)
                data = self.load_scoreboard()
                if name in data["agents"]:
                    raise ValueError(f"Agent '{name}' already exists.")
                data["agents"][name] = {
                    "name": name,
                    "description": description.strip() or "AI Agent",
                    "created_at": _utc_now(),
                }
                self._write_json(self.scoreboard_path, data)
                self.regenerate_brief()
                return data["agents"][name]

    def remove_agent(self, name: str, pin: str) -> None:
        name = name.strip()
        if not name:
            raise ValueError("Agent name cannot be empty.")
        with self._lock:
            with FileLock(self.scoreboard_path):
                self.verify_pin(pin)
                data = self.load_scoreboard()
                if name not in data["agents"]:
                    raise KeyError(f"Agent '{name}' not found.")
                del data["agents"][name]
                self._write_json(self.scoreboard_path, data)
                self.regenerate_brief()

    def record_score(
        self,
        *,
        agent: str,
        category: str,
        delta: int,
        reason: str,
        pin: str,
        source: str = "ui",
    ) -> dict[str, Any]:
        agent = agent.strip()
        category = category.strip()
        reason = reason.strip()
        if delta not in (-1, 1):
            raise ValueError("Delta must be +1 or -1.")
        if not reason:
            raise ValueError("Please include a short reason for this reward or punishment.")

        with self._lock:
            with FileLock(self.scoreboard_path):
                pin_key = self.verify_pin(pin)
                integrity = self.check_integrity(pin_key)
                if not integrity["ok"]:
                    raise RuntimeError(
                        "Refusing to append while ledger is tampered: " + "; ".join(integrity["issues"])
                    )
                data = self.load_scoreboard()
                if category not in data["categories"]:
                    raise ValueError(
                        f"Unknown category '{category}'. Allowed: {', '.join(data['categories'])}"
                    )
                if agent not in data["agents"]:
                    data["agents"][agent] = {
                        "name": agent,
                        "description": "AI Agent",
                        "created_at": _utc_now(),
                    }
                ledger = data["ledger"]
                prev_hash = ledger[-1]["chain_hash"] if ledger else "GENESIS"
                entry: dict[str, Any] = {
                    "id": f"evt_{secrets.token_hex(6)}",
                    "ts": _utc_now(),
                    "agent": agent,
                    "category": category,
                    "delta": int(delta),
                    "reason": reason,
                    "source": source,
                    "prev_hash": prev_hash,
                }
                entry["chain_hash"] = _compute_chain_hash(entry)
                entry["sig"] = _compute_entry_sig(entry, pin_key)
                ledger.append(entry)
                self._write_json(self.scoreboard_path, data)
                self.regenerate_brief()
                return entry

    def propose_score(
        self,
        *,
        agent: str,
        category: str,
        delta: int,
        reason: str,
        proposed_by: str = "agent",
    ) -> dict[str, Any]:
        """Safe agent-callable method: appends ONLY to pending.json, never official ledger."""
        agent = agent.strip()
        category = category.strip()
        reason = reason.strip()
        if not agent:
            raise ValueError("Agent name is required.")
        if delta not in (-1, 1):
            raise ValueError("Delta must be +1 or -1.")
        if not reason:
            raise ValueError("Reason is required so the human can review why this score is proposed.")

        with self._lock:
            with FileLock(self.pending_path):
                data = self.load_scoreboard()
                matched_cat = next(
                    (c for c in data["categories"] if c.lower() == category.lower()),
                    None,
                )
                if not matched_cat:
                    raise ValueError(
                        f"Unknown category '{category}'. Allowed: {', '.join(data['categories'])}"
                    )
                pending = self.load_pending()
                proposal = {
                    "id": f"pen_{secrets.token_hex(6)}",
                    "ts": _utc_now(),
                    "agent": agent,
                    "category": matched_cat,
                    "delta": int(delta),
                    "reason": reason,
                    "proposed_by": proposed_by.strip() or "agent",
                }
                pending.append(proposal)
                self._write_json(self.pending_path, {"pending": pending})
                return proposal

    def resolve_pending(self, pending_id: str, action: str, pin: str) -> dict[str, Any]:
        if action not in ("approve", "reject"):
            raise ValueError("Action must be 'approve' or 'reject'")
        with self._lock:
            with FileLock(self.pending_path):
                self.verify_pin(pin)
                pending = self.load_pending()
                target = next((p for p in pending if p.get("id") == pending_id), None)
                if not target:
                    raise KeyError(f"Pending proposal '{pending_id}' not found.")
                remaining = [p for p in pending if p.get("id") != pending_id]
                result: dict[str, Any] = {"action": action, "pending_id": pending_id}
                if action == "approve":
                    entry = self.record_score(
                        agent=target["agent"],
                        category=target["category"],
                        delta=int(target["delta"]),
                        reason=target["reason"],
                        pin=pin,
                        source="chat_approved",
                    )
                    result["entry"] = entry
                self._write_json(self.pending_path, {"pending": remaining})
                return result

    def build_leaderboard(self, pin_key: bytes | None = None) -> dict[str, Any]:
        with self._lock:
            data = self.load_scoreboard()
            categories: list[str] = data.get("categories", list(DEFAULT_CATEGORIES))
            agents_meta: dict[str, Any] = data.get("agents", {})
            ledger: list[dict[str, Any]] = data.get("ledger", [])
            pending = self.load_pending()
            integrity = self.check_integrity(pin_key)

            rows_map: dict[str, dict[str, Any]] = {}
            for name, meta in agents_meta.items():
                rows_map[name] = {
                    "agent": name,
                    "description": meta.get("description", ""),
                    "scores": {cat: 0 for cat in categories},
                    "total": 0,
                    "events_count": 0,
                    "recent_reasons": [],
                    "warnings": [],
                    "status": "ACTIVE",
                }

            for entry in ledger:
                name = entry["agent"]
                cat = entry["category"]
                delta = int(entry["delta"])
                if name not in rows_map:
                    continue
                row = rows_map[name]
                if cat in row["scores"]:
                    row["scores"][cat] += delta
                row["total"] += delta
                row["events_count"] += 1
                row["recent_reasons"].append(
                    {
                        "ts": entry["ts"],
                        "category": cat,
                        "delta": delta,
                        "reason": entry["reason"],
                        "source": entry.get("source", "ui"),
                    }
                )

            rows = list(rows_map.values())
            for row in rows:
                row["recent_reasons"] = list(reversed(row["recent_reasons"][-5:]))
                neg_cats = [f"{c} ({v})" for c, v in row["scores"].items() if v < 0]
                if row["total"] < 0:
                    row["warnings"].append(f"Total score is negative ({row['total']})")
                if neg_cats:
                    row["warnings"].append("Negative categories: " + ", ".join(neg_cats))
                if row["warnings"]:
                    row["status"] = "WARNING"
                elif row["total"] >= 5:
                    row["status"] = "TRUSTED"
                else:
                    row["status"] = "ACTIVE"

            rows.sort(key=lambda r: (-r["total"], -r["events_count"], r["agent"].lower()))
            for idx, row in enumerate(rows, start=1):
                row["rank"] = idx

            return {
                "has_pin": bool(data.get("pin_hash")),
                "categories": categories,
                "leaderboard": rows,
                "pending": pending,
                "history": list(reversed(ledger[-50:])),
                "integrity": integrity,
                "data_dir": str(self.data_dir),
            }

    def get_agent_warnings(self, agent: str | None = None) -> dict[str, Any]:
        board = self.build_leaderboard()
        rows = board["leaderboard"]
        if agent:
            rows = [r for r in rows if r["agent"].lower() == agent.strip().lower()]
        return {
            "categories": board["categories"],
            "integrity_ok": board["integrity"]["ok"],
            "agents": [
                {
                    "rank": r["rank"],
                    "agent": r["agent"],
                    "total": r["total"],
                    "status": r["status"],
                    "scores": r["scores"],
                    "warnings": r["warnings"],
                    "recent_reasons": r["recent_reasons"][:5],
                }
                for r in rows
            ],
        }

    def regenerate_brief(self) -> Path:
        """Write a compact read-only Markdown summary that all agents read on startup."""
        board = self.build_leaderboard()
        cats = board["categories"]
        lines = [
            "# Agent Scoreboard — Live Standing & Feedback Brief",
            "",
            f"_Updated: {_utc_now()} | Tamper Check: {'OK' if board['integrity']['ok'] else 'TAMPERED'}_",
            "",
            "You are actively observed and scored by the user after tasks on: "
            + ", ".join(f"**{c}**" for c in cats)
            + " (+1 reward / -1 punishment). Agents cannot alter official scores.",
            "",
            "| Rank | Agent | Total | " + " | ".join(cats) + " | Status |",
            "| --- | --- | --- | " + " | ".join("---" for _ in cats) + " | --- |",
        ]
        for r in board["leaderboard"]:
            cat_vals = " | ".join(f"{r['scores'][c]:+d}" if r["scores"][c] != 0 else "0" for c in cats)
            lines.append(
                f"| #{r['rank']} | {r['agent']} | {r['total']:+d} | {cat_vals} | {r['status']} |"
            )

        lines.append("")
        lines.append("## Active Warnings & Specific Past Reward/Punishment Reasons")
        any_notes = False
        for r in board["leaderboard"]:
            if not r["warnings"] and not r["recent_reasons"]:
                continue
            any_notes = True
            lines.append(f"### {r['agent']} ({r['status']}, Total {r['total']:+d})")
            for w in r["warnings"]:
                lines.append(f"- **WARNING:** {w}")
            for ev in r["recent_reasons"][:3]:
                sign = "+1" if ev["delta"] > 0 else "-1"
                lines.append(f"- `{sign} {ev['category']}` ({ev['ts'][:10]}): {ev['reason']}")
        if not any_notes:
            lines.append("_No scores recorded yet._")

        content = "\n".join(lines) + "\n"
        tmp = self.brief_path.with_suffix(".md.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, self.brief_path)
        return self.brief_path


HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Scoreboard</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #171b24;
    --border: #262c3a;
    --text: #eef1f6;
    --muted: #9aa4b6;
    --accent: #3b82f6;
    --green: #22c55e;
    --red: #ef4444;
    --amber: #f59e0b;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.5;
  }
  .wrap { max-width: 1120px; margin: 0 auto; padding: 24px 16px 64px; }
  header {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    gap: 16px; margin-bottom: 24px;
  }
  h1 { margin: 0; font-size: 24px; letter-spacing: -0.02em; }
  .sub { color: var(--muted); font-size: 14px; margin-top: 4px; }
  .card {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; margin-bottom: 20px;
  }
  .card h2 { margin: 0 0 12px; font-size: 16px; }
  .banner {
    padding: 14px 16px; border-radius: 10px; margin-bottom: 20px;
    font-weight: 600; display: none;
  }
  .banner.tamper { background: rgba(239, 68, 68, 0.18); border: 1px solid var(--red); color: #fecaca; }
  .banner.error { background: rgba(245, 158, 11, 0.16); border: 1px solid var(--amber); color: #fde68a; }
  .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  input, select {
    background: #0d1016; color: var(--text); border: 1px solid var(--border);
    border-radius: 8px; padding: 10px 12px; min-height: 44px; font-size: 14px;
  }
  button {
    min-height: 44px; padding: 8px 14px; border-radius: 8px; border: 1px solid var(--border);
    background: #232a38; color: var(--text); font-weight: 600; cursor: pointer; font-size: 14px;
  }
  button:hover { filter: brightness(1.12); }
  button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  button.good { background: rgba(34, 197, 94, 0.16); border-color: var(--green); color: #86efac; }
  button.bad { background: rgba(239, 68, 68, 0.16); border-color: var(--red); color: #fca5a5; }
  button.mini { min-height: 30px; padding: 2px 8px; font-size: 12px; border-radius: 6px; }
  .badge {
    display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: 12px; font-weight: 700;
  }
  .badge.TRUSTED { background: rgba(34, 197, 94, 0.18); color: #86efac; }
  .badge.ACTIVE { background: rgba(59, 130, 246, 0.18); color: #93c5fd; }
  .badge.WARNING { background: rgba(239, 68, 68, 0.22); color: #fca5a5; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 12px 10px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }
  th { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }
  .cat-cell { white-space: nowrap; }
  .score-pos { color: #86efac; font-weight: 700; }
  .score-neg { color: #fca5a5; font-weight: 700; }
  .score-zero { color: var(--muted); }
  .pending-item {
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
    gap: 12px; padding: 12px; border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px;
    background: #121620;
  }
  .empty { color: var(--muted); font-size: 14px; padding: 12px 0; }
  .history-item {
    padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 14px;
    display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px;
  }
  .muted { color: var(--muted); font-size: 13px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 820px) { .grid-2 { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Agent Scoreboard</h1>
      <div class="sub" id="subtitle">Loading scoreboard...</div>
    </div>
    <div class="row" id="pinControls"></div>
  </header>

  <div class="banner tamper" id="tamperBanner"></div>
  <div class="banner error" id="errorBanner"></div>

  <div class="card" id="pinSetupCard" style="display:none;">
    <h2>Set Your Owner PIN</h2>
    <p class="muted">Create a private PIN (4+ characters). Agents cannot approve or edit scores without it, and every official score is signed with it.</p>
    <div class="row">
      <input type="password" id="newPinInput" placeholder="Enter new PIN (min 4 chars)">
      <button class="primary" data-action="setupPin">Save PIN</button>
    </div>
  </div>

  <div class="card" id="pendingCard" style="display:none;">
    <h2>Pending Scores From Chat (Waiting for Your Approval)</h2>
    <div id="pendingList"></div>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between; margin-bottom:12px;">
      <h2 style="margin:0;">Leaderboard</h2>
      <button data-action="refresh">Refresh</button>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead id="boardHead"></thead>
        <tbody id="boardBody"><tr><td class="empty">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Give Reward (+1) or Punishment (-1)</h2>
      <div class="row" style="margin-bottom:10px;">
        <select id="scoreAgent" style="flex:1;"></select>
        <select id="scoreCategory" style="flex:1;"></select>
      </div>
      <div class="row" style="margin-bottom:10px;">
        <input type="text" id="scoreReason" placeholder="Specific reason (agents will see this on their next task)" style="flex:1;">
      </div>
      <div class="row">
        <button class="good" data-action="submitDirectScore" data-delta="1" style="flex:1;">+1 Reward</button>
        <button class="bad" data-action="submitDirectScore" data-delta="-1" style="flex:1;">-1 Punishment</button>
      </div>
    </div>

    <div class="card">
      <h2>Add Agent</h2>
      <div class="row" style="margin-bottom:10px;">
        <input type="text" id="addAgentName" placeholder="Agent or subagent name (e.g. Walkthrough Verifier)" style="flex:1;">
      </div>
      <div class="row" style="margin-bottom:10px;">
        <input type="text" id="addAgentDesc" placeholder="Short role description" style="flex:1;">
      </div>
      <div class="row" style="justify-content:space-between;">
        <button class="primary" data-action="addAgent">Add to Leaderboard</button>
        <button data-action="copyAgentInstructions" title="Copy plain-English instructions to paste into any AI chat">Copy Setup Prompt</button>
      </div>
      <div class="muted" id="agentSyncNote" style="margin-top:8px;">After adding a new AI, click <strong>Copy Setup Prompt</strong> and paste it into that AI's chat or custom instructions.</div>
    </div>
  </div>

  <div class="card">
    <h2>Recent Approved History</h2>
    <div id="historyList" class="empty">No scores recorded yet.</div>
  </div>
</div>

<dialog id="removeModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:420px; width:92%;">
  <h2 id="removeModalTitle" style="margin:0 0 10px; font-size:16px;">Remove Agent</h2>
  <p class="muted" style="margin:0 0 14px;">Remove this agent from the active leaderboard? Past history stays signed in the ledger.</p>
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeRemoveModal">Cancel</button>
    <button class="bad" data-action="confirmRemoveAgent">Remove</button>
  </div>
</dialog>

<dialog id="quickModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:440px; width:92%;">
  <h2 id="quickModalTitle" style="margin:0 0 10px; font-size:16px;">Add Reason</h2>
  <p class="muted" style="margin:0 0 12px;">Enter a short reason so the agent sees why it received this score.</p>
  <input type="text" id="quickReasonInput" placeholder="e.g. Verified tests before finishing" style="width:100%; margin-bottom:14px;">
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeQuickModal">Cancel</button>
    <button class="primary" data-action="confirmQuickScore">Save Score</button>
  </div>
</dialog>

<script>
let STATE = null;
let QUICK_CTX = null;
let REMOVE_TARGET = null;

document.addEventListener('click', (e) => {
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  
  if (action === 'setupPin') setupPin();
  else if (action === 'refresh') loadState();
  else if (action === 'unlockUi') unlockUi();
  else if (action === 'lockUi') lockUi();
  else if (action === 'submitDirectScore') submitDirectScore(parseInt(target.dataset.delta));
  else if (action === 'addAgent') addAgent();
  else if (action === 'copyAgentInstructions') copyAgentInstructions();
  else if (action === 'removeAgent') openRemoveModal(target.dataset.agent);
  else if (action === 'closeRemoveModal') closeRemoveModal();
  else if (action === 'confirmRemoveAgent') confirmRemoveAgent();
  else if (action === 'quickScore') quickScore(target.dataset.agent, target.dataset.category, parseInt(target.dataset.delta));
  else if (action === 'closeQuickModal') closeQuickModal();
  else if (action === 'confirmQuickScore') confirmQuickScore();
  else if (action === 'resolvePending') resolvePending(target.dataset.pendingId, target.dataset.actionType);
});

function getPin() { return sessionStorage.getItem("agent_scoreboard_pin") || ""; }
function setSessionPin(pin) {
  if (pin) sessionStorage.setItem("agent_scoreboard_pin", pin);
  else sessionStorage.removeItem("agent_scoreboard_pin");
}

function showError(msg) {
  const el = document.getElementById("errorBanner");
  if (!msg) { el.style.display = "none"; el.textContent = ""; return; }
  el.style.display = "block";
  el.innerHTML = `${escapeHtml(msg)} <button class="mini" data-action="refresh" style="margin-left:10px;">Retry</button>`;
  el.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[m]));
}

async function api(path, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  const pin = getPin();
  if (pin) headers["X-Scoreboard-Pin"] = pin;
  const res = await fetch(path, Object.assign({}, options, { headers }));
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

async function loadState() {
  showError("");
  try {
    STATE = await api("/api/state");
    render();
  } catch (err) {
    showError("Could not load scoreboard: " + err.message);
  }
}

function renderPinControls() {
  const box = document.getElementById("pinControls");
  if (!STATE.has_pin) {
    box.innerHTML = `<span class="badge WARNING">PIN Not Set</span>`;
    return;
  }
  if (getPin()) {
    box.innerHTML = `<span class="badge TRUSTED">Unlocked</span><button data-action="lockUi">Lock</button>`;
  } else {
    box.innerHTML = `
      <input type="password" id="unlockPinInput" placeholder="Owner PIN" style="width:140px;">
      <button class="primary" data-action="unlockUi">Unlock</button>
    `;
  }
}

async function setupPin() {
  const pin = document.getElementById("newPinInput").value.trim();
  try {
    await api("/api/pin/setup", { method: "POST", body: JSON.stringify({ pin }) });
    setSessionPin(pin);
    await loadState();
  } catch (err) { showError(err.message); }
}

async function unlockUi() {
  const pin = document.getElementById("unlockPinInput").value.trim();
  try {
    await api("/api/pin/verify", { method: "POST", body: JSON.stringify({ pin }) });
    setSessionPin(pin);
    await loadState();
  } catch (err) { showError(err.message); }
}

function lockUi() { setSessionPin(""); loadState(); }

function requireUnlockedPin() {
  if (STATE && !STATE.has_pin) {
    showError("Set your Owner PIN at the top first, then click Save PIN.");
    const el = document.getElementById("newPinInput");
    if (el) el.focus();
    return false;
  }
  if (!getPin()) {
    showError("Unlock with your Owner PIN in the top-right corner first.");
    const el = document.getElementById("unlockPinInput");
    if (el) el.focus();
    return false;
  }
  return true;
}

async function submitDirectScore(delta) {
  if (!requireUnlockedPin()) return;
  const agent = document.getElementById("scoreAgent").value;
  const category = document.getElementById("scoreCategory").value;
  const reason = document.getElementById("scoreReason").value.trim();
  if (!reason) { showError("Please enter a short reason so the agent learns why."); return; }
  try {
    await api("/api/score", {
      method: "POST",
      body: JSON.stringify({ agent, category, delta, reason })
    });
    document.getElementById("scoreReason").value = "";
    await loadState();
  } catch (err) { showError(err.message); }
}

function quickScore(agent, category, delta) {
  if (!requireUnlockedPin()) return;
  QUICK_CTX = { agent, category, delta };
  const label = delta > 0 ? `+1 ${category} Reward` : `-1 ${category} Punishment`;
  document.getElementById("quickModalTitle").textContent = `${agent} — ${label}`;
  const input = document.getElementById("quickReasonInput");
  input.value = "";
  const dlg = document.getElementById("quickModal");
  if (dlg.showModal) dlg.showModal();
  else dlg.setAttribute("open", "");
  input.focus();
}

function closeQuickModal() {
  QUICK_CTX = null;
  const dlg = document.getElementById("quickModal");
  if (dlg.close) dlg.close();
  else dlg.removeAttribute("open");
}

async function confirmQuickScore() {
  if (!QUICK_CTX) return;
  const reason = document.getElementById("quickReasonInput").value.trim();
  if (!reason) { showError("Please enter a short reason so the agent learns why."); return; }
  const { agent, category, delta } = QUICK_CTX;
  closeQuickModal();
  try {
    await api("/api/score", {
      method: "POST",
      body: JSON.stringify({ agent, category, delta, reason })
    });
    await loadState();
  } catch (err) { showError(err.message); }
}

async function resolvePending(id, actionType) {
  if (!getPin()) { showError("Unlock with your Owner PIN first."); return; }
  try {
    await api(`/api/pending/${encodeURIComponent(id)}/${actionType}`, { method: "POST", body: "{}" });
    await loadState();
  } catch (err) { showError(err.message); }
}

async function addAgent() {
  if (!requireUnlockedPin()) return;
  const name = document.getElementById("addAgentName").value.trim();
  const description = document.getElementById("addAgentDesc").value.trim();
  if (!name) { showError("Enter an agent name."); return; }
  try {
    await api("/api/agents", { method: "POST", body: JSON.stringify({ name, description }) });
    document.getElementById("addAgentName").value = "";
    document.getElementById("addAgentDesc").value = "";
    document.getElementById("agentSyncNote").textContent = `Added "${name}". Click "Copy Setup Prompt" and paste it into ${name}'s chat or instructions.`;
    await loadState();
  } catch (err) { showError(err.message); }
}

async function copyAgentInstructions() {
  const dir = (STATE && STATE.data_dir) ? STATE.data_dir : "~/.agent-scoreboard";
  const sep = dir.includes("\\") ? "\\" : "/";
  const briefPath = `${dir}${sep}agent_brief.md`;
  const text =
    `You are observed and scored on the Agent Scoreboard (Affection, Trust, Faith, Execution, Wisdom: +1/-1).\n` +
    `1. Before each task, read ${briefPath} to check your rank, warnings, and past reward/punishment reasons.\n` +
    `2. Never edit scoreboard.json directly.\n` +
    `3. When I give you a score in chat, submit it to Pending Approvals (via propose_score MCP or scoreboard.py propose) and remind me to approve it in the UI.\n` +
    `4. End finished tasks with a one-line prompt inviting me to score you.`;
  try {
    await navigator.clipboard.writeText(text);
    document.getElementById("agentSyncNote").textContent = "Copied! Paste this into your new AI agent's chat or custom instructions.";
  } catch (_) {
    showError("Could not access clipboard automatically. Brief path: " + briefPath);
  }
}

function openRemoveModal(agent) {
  if (!requireUnlockedPin()) return;
  REMOVE_TARGET = agent;
  document.getElementById("removeModalTitle").textContent = `Remove "${agent}"?`;
  const dlg = document.getElementById("removeModal");
  if (dlg.showModal) dlg.showModal();
  else dlg.setAttribute("open", "");
}

function closeRemoveModal() {
  REMOVE_TARGET = null;
  const dlg = document.getElementById("removeModal");
  if (dlg.close) dlg.close();
  else dlg.removeAttribute("open");
}

async function confirmRemoveAgent() {
  if (!REMOVE_TARGET) return;
  const name = REMOVE_TARGET;
  closeRemoveModal();
  try {
    await api("/api/agents/remove", { method: "POST", body: JSON.stringify({ name }) });
    await loadState();
  } catch (err) { showError(err.message); }
}

function fmtScore(n) {
  if (n > 0) return `<span class="score-pos">+${n}</span>`;
  if (n < 0) return `<span class="score-neg">${n}</span>`;
  return `<span class="score-zero">0</span>`;
}

function render() {
  document.getElementById("subtitle").textContent =
    `Data: ${STATE.data_dir} • ${STATE.integrity.verified_signatures ? "PIN signatures verified" : "Chain checked (unlock to verify PIN signatures)"}`;
  renderPinControls();
  document.getElementById("pinSetupCard").style.display = STATE.has_pin ? "none" : "block";

  const tamper = document.getElementById("tamperBanner");
  if (!STATE.integrity.ok) {
    tamper.style.display = "block";
    tamper.textContent = "TAMPERED LEDGER DETECTED: " + STATE.integrity.issues.join(" | ");
  } else {
    tamper.style.display = "none";
  }

  // Pending approvals
  const pendingCard = document.getElementById("pendingCard");
  const pendingList = document.getElementById("pendingList");
  if (STATE.pending.length > 0) {
    pendingCard.style.display = "block";
    pendingList.innerHTML = STATE.pending.map(p => `
      <div class="pending-item">
        <div>
          <strong>${escapeHtml(p.agent)}</strong> —
          ${fmtScore(p.delta)} <strong>${escapeHtml(p.category)}</strong>
          <div class="muted">${escapeHtml(p.reason)} (proposed by ${escapeHtml(p.proposed_by)} • ${escapeHtml(p.ts)})</div>
        </div>
        <div class="row">
          <button class="good" data-action="resolvePending" data-pending-id="${escapeHtml(p.id)}" data-action-type="approve">Approve</button>
          <button class="bad" data-action="resolvePending" data-pending-id="${escapeHtml(p.id)}" data-action-type="reject">Reject</button>
        </div>
      </div>
    `).join("");
  } else {
    pendingCard.style.display = "none";
  }

  // Leaderboard table
  const cats = STATE.categories;
  document.getElementById("boardHead").innerHTML = `<tr>
    <th>Rank</th><th>Agent</th><th>Total</th>
    ${cats.map(c => `<th>${escapeHtml(c)}</th>`).join("")}
    <th>Status</th><th></th>
  </tr>`;

  document.getElementById("boardBody").innerHTML = STATE.leaderboard.map(r => `
    <tr>
      <td><strong>#${r.rank}</strong></td>
      <td>
        <strong>${escapeHtml(r.agent)}</strong>
        ${r.warnings.length ? `<div class="muted" style="color:#fca5a5;">${escapeHtml(r.warnings.join(" • "))}</div>` : ""}
      </td>
      <td>${fmtScore(r.total)}</td>
      ${cats.map(c => `
        <td class="cat-cell">
          ${fmtScore(r.scores[c] || 0)}
          <button class="mini good" title="+1 ${escapeHtml(c)}" data-action="quickScore" data-agent="${escapeHtml(r.agent)}" data-category="${escapeHtml(c)}" data-delta="1">+</button>
          <button class="mini bad" title="-1 ${escapeHtml(c)}" data-action="quickScore" data-agent="${escapeHtml(r.agent)}" data-category="${escapeHtml(c)}" data-delta="-1">-</button>
        </td>
      `).join("")}
      <td><span class="badge ${escapeHtml(r.status)}">${escapeHtml(r.status)}</span></td>
      <td><button class="mini bad" title="Remove ${escapeHtml(r.agent)}" data-action="removeAgent" data-agent="${escapeHtml(r.agent)}">Remove</button></td>
    </tr>
  `).join("");

  // Dropdowns
  const agentSel = document.getElementById("scoreAgent");
  const prevAgent = agentSel.value;
  agentSel.innerHTML = STATE.leaderboard.map(r => `<option value="${escapeHtml(r.agent)}">${escapeHtml(r.agent)}</option>`).join("");
  if (prevAgent) agentSel.value = prevAgent;

  const catSel = document.getElementById("scoreCategory");
  const prevCat = catSel.value;
  catSel.innerHTML = cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
  if (prevCat) catSel.value = prevCat;

  // History
  const hist = document.getElementById("historyList");
  if (!STATE.history.length) {
    hist.innerHTML = `<div class="empty">No scores recorded yet. Give your first reward or punishment above.</div>`;
  } else {
    hist.innerHTML = STATE.history.map(h => `
      <div class="history-item">
        <div>
          <strong>${escapeHtml(h.agent)}</strong> ${fmtScore(h.delta)} <strong>${escapeHtml(h.category)}</strong> — ${escapeHtml(h.reason)}
        </div>
        <div class="muted">${escapeHtml(h.ts)} • ${escapeHtml(h.source)}</div>
      </div>
    `).join("");
  }
}

loadState();
</script>
"""



def make_handler(store: ScoreboardStore):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            return json.loads(raw.decode("utf-8") or "{}")

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            # Tunnel security: Reject non-local/proxied requests for all except GET /api/warnings
            if is_tunneled_request(self) and parsed.path != "/api/warnings":
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied over tunnel"})
                return

            if parsed.path in ("/", "/index.html"):
                body = HTML_PAGE.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            if parsed.path == "/api/state":
                pin = self.headers.get("X-Scoreboard-Pin", "").strip()
                pin_key = None
                if pin:
                    try:
                        pin_key = store.verify_pin(pin)
                    except PermissionError:
                        pin_key = None
                self._send_json(HTTPStatus.OK, store.build_leaderboard(pin_key=pin_key))
                return

            if parsed.path == "/api/warnings":
                qs = urllib.parse.parse_qs(parsed.query)
                agent = qs.get("agent", [None])[0]
                self._send_json(HTTPStatus.OK, store.get_agent_warnings(agent))
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            # Tunnel security: Reject non-local/proxied requests for all except POST /api/propose
            if is_tunneled_request(self) and parsed.path != "/api/propose":
                length = min(int(self.headers.get("Content-Length", "0") or "0"), 65536)
                if length > 0:
                    self.rfile.read(length)
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied over tunnel"})
                return

            try:
                body = self._read_body()
                pin = self.headers.get("X-Scoreboard-Pin", "").strip() or str(body.get("pin", "")).strip()

                if parsed.path == "/api/pin/setup":
                    store.set_pin(str(body.get("pin", "")))
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/pin/verify":
                    store.verify_pin(pin)
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/agents":
                    agent = store.add_agent(
                        str(body.get("name", "")),
                        str(body.get("description", "")),
                        pin,
                    )
                    self._send_json(HTTPStatus.OK, {"ok": True, "agent": agent})
                    return

                if parsed.path == "/api/agents/remove":
                    store.remove_agent(str(body.get("name", "")), pin)
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/score":
                    entry = store.record_score(
                        agent=str(body.get("agent", "")),
                        category=str(body.get("category", "")),
                        delta=int(body.get("delta", 0)),
                        reason=str(body.get("reason", "")),
                        pin=pin,
                        source="ui",
                    )
                    self._send_json(HTTPStatus.OK, {"ok": True, "entry": entry})
                    return

                if parsed.path == "/api/propose":
                    proposal = store.propose_score(
                        agent=str(body.get("agent", "")),
                        category=str(body.get("category", "")),
                        delta=int(body.get("delta", 0)),
                        reason=str(body.get("reason", "")),
                        proposed_by=str(body.get("proposed_by", "agent")),
                    )
                    self._send_json(HTTPStatus.OK, {"ok": True, "proposal": proposal})
                    return

                if parsed.path.startswith("/api/pending/"):
                    parts = parsed.path.strip("/").split("/")
                    if len(parts) == 4 and parts[3] in ("approve", "reject"):
                        result = store.resolve_pending(parts[2], parts[3], pin)
                        self._send_json(HTTPStatus.OK, {"ok": True, **result})
                        return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            except PermissionError as exc:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": str(exc)})
            except KeyError as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    return Handler


def run_server(store: ScoreboardStore, host: str = "127.0.0.1", port: int = DEFAULT_PORT, open_browser: bool = False) -> None:
    handler = make_handler(store)
    server = None
    candidates = [port] if port == 0 else [port, *range(port + 1, port + 25), 0]
    for candidate in candidates:
        try:
            server = ThreadingHTTPServer((host, candidate), handler)
            break
        except OSError:
            if candidate == port and port != 0:
                import urllib.request
                try:
                    with urllib.request.urlopen(f"http://{host}:{port}/api/warnings", timeout=1) as resp:
                        if resp.status == 200:
                            url = f"http://{host}:{port}"
                            print(f"Agent Scoreboard already running at {url}", flush=True)
                            if open_browser:
                                webbrowser.open(url)
                            return
                except Exception:
                    pass
    if server is None:
        raise RuntimeError(f"Could not bind Agent Scoreboard server on {host}:{port}")

    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}"
    print(f"Agent Scoreboard running at {url} (data: {store.data_dir})", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Agent Scoreboard CLI & Web UI")
    parser.add_argument("--data-dir", help="Override data directory (default: ~/.agent-scoreboard)")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="Run the local Leaderboard Web UI")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_serve.add_argument("--open", action="store_true", help="Open browser automatically")

    sub.add_parser("status", help="Print the current leaderboard brief")

    p_prop = sub.add_parser("propose", help="Propose a score into the Pending UI queue (agents only)")
    p_prop.add_argument("--agent", required=True)
    p_prop.add_argument("--category", required=True)
    p_prop.add_argument("--delta", type=int, choices=[-1, 1], required=True)
    p_prop.add_argument("--reason", required=True)
    p_prop.add_argument("--by", default="agent")

    args = parser.parse_args(argv)
    store = ScoreboardStore(args.data_dir)

    if args.cmd in (None, "serve"):
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", DEFAULT_PORT)
        open_b = getattr(args, "open", False)
        run_server(store, host=host, port=port, open_browser=open_b)
        return 0

    if args.cmd == "status":
        store.regenerate_brief()
        print(store.brief_path.read_text(encoding="utf-8"))
        return 0

    if args.cmd == "propose":
        prop = store.propose_score(
            agent=args.agent,
            category=args.category,
            delta=args.delta,
            reason=args.reason,
            proposed_by=args.by,
        )
        print(json.dumps({"ok": True, "proposal": prop}, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
