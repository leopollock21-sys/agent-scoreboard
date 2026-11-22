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
import ipaddress
import json
import errno
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from collections import deque
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
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_PENDING_PROPOSALS = 200
MAX_AGENT_NAME_LENGTH = 100
MAX_PROPOSAL_REASON_LENGTH = 2000
MAX_PROPOSED_BY_LENGTH = 100
REMOTE_PROPOSALS_PER_MINUTE = 30
ASSETS_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "assets"


class RequestTooLargeError(ValueError):
    pass


class UnsupportedMediaTypeError(ValueError):
    pass


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

    # A spoofable Host header must not make a direct network peer look local.
    try:
        peer_ip = ipaddress.ip_address(request.client_address[0])
        if isinstance(peer_ip, ipaddress.IPv6Address) and peer_ip.ipv4_mapped:
            peer_ip = peer_ip.ipv4_mapped
        if not peer_ip.is_loopback:
            return True
    except (AttributeError, IndexError, TypeError, ValueError):
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
        self.settings_path = self.data_dir / "settings.json"
        self._lock = threading.RLock()
        self._failed_pins = []  # Timestamps of failed attempts
        self._remote_proposal_attempts: deque[float] = deque()
        self._remote_proposal_rate_lock = threading.Lock()
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
        self.ensure_daily_backup()

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

    def list_backups(self) -> list[dict[str, Any]]:
        """List automatic PIN reset backups with UTC modification timestamps."""
        backups = []
        for path in sorted(self.data_dir.glob("scoreboard.backup.*.json"), key=lambda item: item.name):
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            backups.append({
                "name": path.name,
                "size": path.stat().st_size,
                "modified_utc": modified.strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        return backups

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

    def get_backup_dir(self) -> Path:
        default_dir = self.data_dir / "backups"
        if self.settings_path.is_file():
            try:
                cfg = self._load_settings()
                raw = str(cfg.get("backup_dir", "")).strip()
                if raw:
                    p = Path(raw).expanduser()
                    p.mkdir(parents=True, exist_ok=True)
                    return p
            except (OSError, ValueError):
                pass
        default_dir.mkdir(parents=True, exist_ok=True)
        return default_dir

    def set_backup_dir(self, folder: str) -> Path:
        p = Path(folder.strip()).expanduser()
        if not str(p):
            raise ValueError("Backup folder path cannot be empty.")
        p.mkdir(parents=True, exist_ok=True)
        with self._lock:
            cfg = self._load_settings()
            cfg["backup_dir"] = str(p)
            self._write_json(self.settings_path, cfg)
        self.ensure_daily_backup()
        return p

    def _load_settings(self) -> dict[str, Any]:
        if not self.settings_path.is_file():
            return {}
        try:
            data = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def rotate_api_token(self, pin: str) -> str:
        self.verify_pin(pin)
        token = secrets.token_urlsafe(32)
        with self._lock:
            settings = self._load_settings()
            settings["api_token_sha256"] = hashlib.sha256(token.encode("utf-8")).hexdigest()
            self._write_json(self.settings_path, settings)
        return token

    def verify_api_token(self, token: str) -> bool:
        stored_hash = self._load_settings().get("api_token_sha256")
        if not isinstance(stored_hash, str) or len(stored_hash) != 64:
            return False
        candidate_hash = hashlib.sha256((token or "").encode("utf-8")).hexdigest()
        return hmac.compare_digest(candidate_hash, stored_hash)

    def allow_remote_proposal(self) -> bool:
        now = time.monotonic()
        with self._remote_proposal_rate_lock:
            while self._remote_proposal_attempts and now - self._remote_proposal_attempts[0] >= 60:
                self._remote_proposal_attempts.popleft()
            if len(self._remote_proposal_attempts) >= REMOTE_PROPOSALS_PER_MINUTE:
                return False
            self._remote_proposal_attempts.append(now)
            return True

    def ensure_daily_backup(self) -> Path | None:
        """Automatically save one daily backup if today's file does not exist yet."""
        if not self.scoreboard_path.is_file():
            return None
        bdir = self.get_backup_dir()
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        target = bdir / f"scoreboard.auto.{today}.json"
        if not target.exists():
            with self._lock:
                data = self.load_scoreboard()
                self._write_json(target, data)
        return target

    def create_manual_backup(self) -> Path:
        bdir = self.get_backup_dir()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        target = bdir / f"scoreboard.manual.{stamp}.json"
        with self._lock:
            data = self.load_scoreboard()
            self._write_json(target, data)
        return target

    def list_backups(self) -> list[dict[str, Any]]:
        seen: dict[str, Path] = {}
        for folder in (self.get_backup_dir(), self.data_dir):
            if not folder.is_dir():
                continue
            for p in folder.glob("scoreboard.*.json"):
                if p.name == "scoreboard.json":
                    continue
                seen.setdefault(p.name, p)
        items: list[dict[str, Any]] = []
        for p in sorted(seen.values(), key=lambda x: x.stat().st_mtime, reverse=True):
            st = p.stat()
            items.append({
                "name": p.name,
                "size": st.st_size,
                "modified_utc": datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        return items

    def delete_backup(self, filename: str) -> None:
        filename = (filename or "").strip()
        valid = (
            (filename.startswith("scoreboard.backup.") or filename.startswith("scoreboard.auto.") or filename.startswith("scoreboard.manual."))
            and filename.endswith(".json")
            and "/" not in filename
            and "\\" not in filename
            and ".." not in filename
        )
        if not valid:
            raise ValueError("Invalid backup file name.")
        deleted = False
        for folder in (self.get_backup_dir(), self.data_dir):
            target = folder / filename
            if target.is_file():
                target.unlink()
                deleted = True
        if not deleted:
            raise KeyError(f"Backup '{filename}' not found.")

    def reset_pin_and_archive(self) -> Path:
        """Archive current scoreboard.json and clear PIN/ledger while keeping agents & categories."""
        with self._lock:
            with FileLock(self.scoreboard_path):
                data = self.load_scoreboard()
                stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                backup_path = self.data_dir / f"scoreboard.backup.{stamp}.json"
                self._write_json(backup_path, data)
                data["pin_salt"] = None
                data["pin_hash"] = None
                data["ledger"] = []
                self._write_json(self.scoreboard_path, data)
                settings = self._load_settings()
                if settings.pop("api_token_sha256", None) is not None:
                    self._write_json(self.settings_path, settings)
                self.regenerate_brief()
                return backup_path

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
                self.ensure_daily_backup()
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
        proposed_by = proposed_by.strip() or "agent"
        if not agent:
            raise ValueError("Agent name is required.")
        if len(agent) > MAX_AGENT_NAME_LENGTH:
            raise ValueError(f"Agent name must be {MAX_AGENT_NAME_LENGTH} characters or fewer.")
        if delta not in (-1, 1):
            raise ValueError("Delta must be +1 or -1.")
        if not reason:
            raise ValueError("Reason is required so the human can review why this score is proposed.")
        if len(reason) > MAX_PROPOSAL_REASON_LENGTH:
            raise ValueError(f"Reason must be {MAX_PROPOSAL_REASON_LENGTH} characters or fewer.")
        if len(proposed_by) > MAX_PROPOSED_BY_LENGTH:
            raise ValueError(f"Submitter name must be {MAX_PROPOSED_BY_LENGTH} characters or fewer.")

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
                if len(pending) >= MAX_PENDING_PROPOSALS:
                    raise ValueError(f"Pending queue is full ({MAX_PENDING_PROPOSALS} proposals). Review or remove items before adding more.")
                proposal = {
                    "id": f"pen_{secrets.token_hex(6)}",
                    "ts": _utc_now(),
                    "agent": agent,
                    "category": matched_cat,
                    "delta": int(delta),
                    "reason": reason,
                    "proposed_by": proposed_by,
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
<title>Agent Scoreboard — Chinlung Technologies</title>
<link rel="icon" type="image/png" href="/assets/app_icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root { color-scheme: dark; --bg:#090a0d; --card:rgba(22,24,30,.86); --line:rgba(255,255,255,.09); --text:#f5f5f7; --muted:#989aa4; --accent:#0a84ff; --green:#30d158; --red:#ff453a; --amber:#ffd60a; }
  * { box-sizing:border-box; }
  body { margin:0; background:radial-gradient(900px 420px at 50% -120px, rgba(10,132,255,.14), transparent 70%), var(--bg); color:var(--text); font:14.5px/1.55 "Inter",-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text","Segoe UI Variable","Segoe UI",sans-serif; -webkit-font-smoothing:antialiased; font-feature-settings:"cv02","cv03","cv04","cv11"; }
  .wrap { max-width:1440px; width:100%; margin:0 auto; padding:22px 24px 24px; }
  header { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:18px; margin-bottom:24px; }
  .brand { display:flex; align-items:center; gap:14px; min-width:240px; }
  .app-icon { width:44px; height:44px; border-radius:12px; object-fit:cover; box-shadow:0 6px 20px rgba(0,0,0,.35); }
  h1 { margin:0; font-size:24px; line-height:1.15; letter-spacing:-.03em; font-weight:700; }
  .sub { color:var(--muted); font-size:13px; margin-top:4px; overflow-wrap:anywhere; }
  .card { background:var(--card); backdrop-filter:blur(16px); border:1px solid var(--line); border-radius:18px; padding:24px; margin-bottom:16px; box-shadow:0 16px 40px rgba(0,0,0,.22); }
  .card h2 { margin:0 0 14px; font-size:16px; font-weight:600; letter-spacing:-.015em; }
  .banner { padding:14px 16px; border-radius:12px; margin-bottom:16px; font-weight:600; display:none; }
  .banner.tamper { background:rgba(255,69,58,.12); border:1px solid var(--red); color:#ffb4ad; }
  .banner.error { background:rgba(255,214,10,.1); border:1px solid var(--amber); color:#ffe985; }
  .row { display:flex; flex-wrap:wrap; gap:10px; align-items:center; }
  input,select { background:#0d0f13; color:var(--text); border:1px solid var(--line); border-radius:10px; padding:10px 13px; min-height:44px; font-size:14px; }
  button { min-height:44px; padding:9px 15px; border-radius:11px; border:1px solid var(--line); background:#202229; color:var(--text); font-weight:600; cursor:pointer; font-size:14px; transition:background .15s ease,border-color .15s ease; }
  button:hover { background:#2a2c34; }
  button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  button.good { background:rgba(48,209,88,.12); border-color:rgba(48,209,88,.38); color:#78e995; }
  button.bad { background:rgba(255,69,58,.12); border-color:rgba(255,69,58,.38); color:#ff938c; }
  button.mini { min-width:30px; min-height:30px; padding:4px 9px; font-size:12.5px; border-radius:8px; }
  .badge { display:inline-flex; align-items:center; padding:5px 10px; border-radius:999px; font-size:12px; font-weight:700; }
  .badge.TRUSTED { background:rgba(48,209,88,.16); color:#78e995; }
  .badge.ACTIVE { background:rgba(10,132,255,.17); color:#7dbbff; }
  .badge.WARNING { background:rgba(255,69,58,.18); color:#ff938c; }
  .segmented { display:flex; gap:4px; width:max-content; max-width:100%; overflow-x:auto; padding:4px; margin:0 0 22px; border:1px solid var(--line); border-radius:14px; background:#111216; }
  .segmented button { flex:0 0 auto; min-height:44px; padding:8px 18px; border:0; background:transparent; color:var(--muted); border-radius:10px; }
  .segmented button[aria-selected="true"] { background:#2a2b31; color:var(--text); box-shadow:0 1px 4px rgba(0,0,0,.25); }
  .tab-panel[hidden] { display:none; }
  table { width:100%; border-collapse:collapse; }
  th,td { padding:10px 8px; text-align:left; border-bottom:1px solid var(--line); font-size:13.5px; font-variant-numeric:tabular-nums; }
  th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; font-weight:600; }
  .cat-cell { white-space:nowrap; font-variant-numeric:tabular-nums; }
  .score-pos { color:#78e995; font-weight:700; }
  .score-neg { color:#ff938c; font-weight:700; }
  .score-zero,.muted { color:var(--muted); }
  .muted { font-size:13px; }
  .pending-item { display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:12px; padding:15px; border:1px solid var(--line); border-radius:12px; margin-bottom:10px; background:#111318; }
  .empty { color:var(--muted); font-size:14px; padding:12px 0; }
  .history-item,.backup-item { padding:14px 0; border-bottom:1px solid var(--line); font-size:14px; display:flex; flex-wrap:wrap; justify-content:space-between; align-items:center; gap:10px; }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  .faq-item { padding:18px 0; border-bottom:1px solid var(--line); }
  .faq-item:first-of-type { padding-top:0; }
  .faq-item:last-child { border:0; padding-bottom:0; }
  .faq-item h3 { margin:0 0 6px; font-size:15px; }
  .faq-item p { margin:0; color:var(--muted); }
  .about-brand { display:flex; align-items:center; gap:24px; flex-wrap:wrap; }
  .company-logo { width:96px; height:96px; object-fit:contain; filter:drop-shadow(0 6px 18px rgba(0,0,0,.4)); }
  .about-meta { display:grid; gap:8px; color:var(--muted); }
  .about-meta a { color:#7dbbff; }
  a.button { display:inline-flex; align-items:center; justify-content:center; min-height:44px; padding:9px 15px; border:1px solid var(--line); border-radius:11px; background:#202229; color:var(--text); font-size:14px; font-weight:600; text-decoration:none; }
  a.button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
  a.button.mini { padding:7px 12px; font-size:13px; }
  footer { display:flex; justify-content:center; align-items:center; gap:10px; padding:26px 8px 6px; color:var(--muted); font-size:13px; }
  .footer-logo { width:32px; height:32px; object-fit:contain; }
  dialog { background:var(--card); color:var(--text); border:1px solid var(--line); border-radius:16px; padding:24px; }
  dialog::backdrop { background:rgba(0,0,0,.65); backdrop-filter:blur(4px); }
  @media (max-width:760px) { .wrap{padding:20px 14px;} .grid-2{grid-template-columns:1fr;} .card{padding:19px;} .segmented{width:100%;} .segmented button{padding-inline:14px;} }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <img class="app-icon" src="/assets/app_icon.png" alt="Agent Scoreboard app icon">
      <div>
      <h1>Agent Scoreboard</h1>
      <div class="sub" id="subtitle">Loading scoreboard...</div>
      </div>
    </div>
    <div class="row" id="pinControls"></div>
  </header>

  <nav class="segmented" role="tablist" aria-label="Main navigation">
    <button role="tab" id="tab-board" aria-selected="true" aria-controls="panel-board" data-tab="board">Leaderboard</button>
    <button role="tab" id="tab-backup" aria-selected="false" aria-controls="panel-backup" data-tab="backup">Backup</button>
    <button role="tab" id="tab-connect" aria-selected="false" aria-controls="panel-connect" data-tab="connect">Remote Access</button>
    <button role="tab" id="tab-faq" aria-selected="false" aria-controls="panel-faq" data-tab="faq">FAQ</button>
    <button role="tab" id="tab-about" aria-selected="false" aria-controls="panel-about" data-tab="about">About Us</button>
  </nav>

  <div class="banner tamper" id="tamperBanner"></div>
  <div class="banner error" id="errorBanner"></div>

  <main class="tab-panel" id="panel-board" role="tabpanel" aria-labelledby="tab-board">
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
        <input type="text" id="addAgentName" placeholder="Agent name (or comma-separated list: research, browser)" style="flex:1;">
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
  </main>

  <section class="tab-panel" id="panel-backup" role="tabpanel" aria-labelledby="tab-backup" hidden>
    <div class="card">
      <div class="row" style="justify-content:space-between; margin-bottom:14px;">
        <div><h2 style="margin-bottom:5px;">Automatic Daily Backups</h2><div class="muted">One snapshot per day is saved automatically whenever you open or score.</div></div>
        <div class="row">
          <button class="primary" data-action="backupNow">Back Up Now</button>
          <a class="button" href="/api/backup/download">Download Current (.json)</a>
        </div>
      </div>
      <div class="row">
        <input type="text" id="backupFolderInput" placeholder="Backup folder path" style="flex:1; min-width:240px;">
        <button data-action="pickBackupFolder">Choose Folder</button>
        <button data-action="saveBackupFolder">Save Path</button>
      </div>
      <div class="muted" id="backupFolderNote" style="margin-top:8px;"></div>
    </div>
    <div class="card"><h2>Saved Backups</h2><div id="backupList" class="empty" aria-live="polite">Loading backups…</div></div>
  </section>

  <section class="tab-panel" id="panel-connect" role="tabpanel" aria-labelledby="tab-connect" hidden>
    <div class="card">
      <h2>Secure Remote Agent Access</h2>
      <p class="muted">The app is local-only by default. If you connect it through a public HTTPS tunnel, remote agents must use a bearer token to read warnings or submit score proposals.</p>
      <p class="muted">Unlock with your Owner PIN, then generate a token. Generating a new token immediately revokes the previous one. The token is shown once; save it in your remote action's authorization settings.</p>
      <div class="row" style="margin-top:12px;">
        <button class="primary" data-action="openGenerateApiToken">Generate / Replace API Token</button>
      </div>
      <div id="apiTokenResult" style="display:none; margin-top:16px;">
        <label for="apiTokenValue" class="muted">Copy this token now. It will not be shown again.</label>
        <div class="row" style="margin-top:8px;">
          <input id="apiTokenValue" type="text" readonly autocomplete="off" spellcheck="false" style="flex:1; min-width:260px;">
          <button data-action="copyApiToken">Copy Token</button>
        </div>
      </div>
    </div>
  </section>

  <section class="tab-panel" id="panel-faq" role="tabpanel" aria-labelledby="tab-faq" hidden>
    <div class="card">
      <h2>Frequently Asked Questions</h2>
      <div class="faq-item"><h3>What is Agent Scoreboard trying to do?</h3><p>AI agents do not feel pride or pain on their own, and letting an AI grade itself leads to fake scores. Agent Scoreboard creates real human-in-the-loop accountability: after every task, you reward (+1) or punish (-1) the agent with a specific reason, and that reason is fed back into the agent's startup context so it does not repeat past mistakes.</p></div>
      <div class="faq-item"><h3>What is the scoring system based on?</h3><p>It is based on five human-AI partnership pillars—<strong>Affection</strong> (kindness &amp; attitude), <strong>Trust</strong> (truthfulness &amp; verified proof), <strong>Faith</strong> (loyalty &amp; obedience to your rules), <strong>Execution</strong> (clean, finished results), and <strong>Wisdom</strong> (smart, simple root-cause thinking)—backed by a PIN-signed SHA-256 hash chain and a live <code>agent_brief.md</code> feedback loop.</p></div>
      <div class="faq-item"><h3>How does tamper protection work?</h3><p>Entries are linked in a SHA-256 chain and HMAC-signed with your Owner PIN. If an agent ever edits <code>scoreboard.json</code> directly, a red <strong>TAMPERED</strong> alert appears immediately.</p></div>
      <div class="faq-item"><h3>How do I connect a new AI agent?</h3><p>Add its name on the Leaderboard tab (comma-separated bulk add is supported), then click <strong>Copy Setup Prompt</strong> and paste it into that agent's chat or custom instructions.</p></div>
      <div class="faq-item"><h3>What happens if I forget my PIN?</h3><p>Click <strong>Forgot PIN?</strong> in the header and choose <strong>Start Fresh</strong>. Your old scores are archived as a backup, your agents stay on the board, and you can set a new PIN right away.</p></div>
      <div class="faq-item"><h3>How can I contact Chinlung Technologies?</h3><p>Email us anytime at <a href="mailto:chinlungtech@gmail.com" style="color:#7dbbff;">chinlungtech@gmail.com</a>.</p></div>
    </div>
  </section>

  <section class="tab-panel" id="panel-about" role="tabpanel" aria-labelledby="tab-about" hidden>
    <div class="card">
      <h2>About Us</h2>
      <div class="about-brand">
        <img class="company-logo" src="/assets/chinlung_logo.png" alt="Chinlung Technologies company logo">
        <div class="about-meta">
          <strong style="color:var(--text);font-size:18px;">Chinlung Technologies</strong>
          <span>Agent Scoreboard v1.2.0 • MIT Open Source</span>
          <span>Contact: <a href="mailto:chinlungtech@gmail.com">chinlungtech@gmail.com</a></span>
          <a href="https://github.com/leopollock21-sys/agent-scoreboard" target="_blank" rel="noopener noreferrer">View on GitHub</a>
        </div>
      </div>
      <p style="margin:16px 0 8px; color:var(--text);"><strong>Our Mission:</strong> Keep every AI assistant honest, accountable, and aligned with real human judgment.</p>
      <p class="muted" style="margin:0;">Agent Scoreboard is built on five human-AI trust pillars (Affection, Trust, Faith, Execution, and Wisdom) combined with a PIN-signed tamper-evident ledger and an automatic startup feedback brief (<code>agent_brief.md</code>) so every agent sees its rank, warnings, and specific past reward/punishment reasons before starting work.</p>
    </div>
  </section>

  <footer><img class="footer-logo" src="/assets/chinlung_logo.png" alt=""><span>Chinlung Technologies • Agent Scoreboard v1.2.0</span></footer>
</div>

<dialog id="removeModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:420px; width:92%;">
  <h2 id="removeModalTitle" style="margin:0 0 10px; font-size:16px;">Remove Agent</h2>
  <p class="muted" style="margin:0 0 14px;">Remove this agent from the active leaderboard? Past history stays signed in the ledger.</p>
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeRemoveModal">Cancel</button>
    <button class="bad" data-action="confirmRemoveAgent">Remove</button>
  </div>
</dialog>

<dialog id="resetPinModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:440px; width:92%;">
  <h2 style="margin:0 0 10px; font-size:16px;">Forgot Your PIN?</h2>
  <p class="muted" style="margin:0 0 14px;">This saves a backup of your old scores, keeps all your agents, and lets you set a new PIN. Current scores will reset to 0.</p>
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeResetPinModal">Cancel</button>
    <button class="bad" data-action="confirmResetPin">Start Fresh</button>
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

<dialog id="deleteBackupModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:420px; width:92%;">
  <h2 id="deleteBackupTitle" style="margin:0 0 10px; font-size:16px;">Delete Backup?</h2>
  <p class="muted" style="margin:0 0 14px;">Permanently delete this saved backup file from disk?</p>
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeDeleteBackupModal">Cancel</button>
    <button class="bad" data-action="confirmDeleteBackup">Delete</button>
  </div>
</dialog>

<dialog id="apiTokenModal" style="background:#171b24; color:#eef1f6; border:1px solid #262c3a; border-radius:12px; padding:20px; max-width:440px; width:92%;">
  <h2 style="margin:0 0 10px; font-size:16px;">Replace Remote API Token?</h2>
  <p class="muted" style="margin:0 0 14px;">Any remote action using the current token will stop working. The new token is shown once.</p>
  <div class="row" style="justify-content:flex-end;">
    <button data-action="closeApiTokenModal">Cancel</button>
    <button class="primary" data-action="confirmGenerateApiToken">Generate Token</button>
  </div>
</dialog>

<script>
let STATE = null;
let QUICK_CTX = null;
let REMOVE_TARGET = null;
let DELETE_BACKUP_TARGET = null;

document.addEventListener('click', (e) => {
  const tab = e.target.closest('[data-tab]');
  if (tab) { changeTab(tab.dataset.tab); return; }
  const target = e.target.closest('[data-action]');
  if (!target) return;
  const action = target.dataset.action;
  
  if (action === 'setupPin') setupPin();
  else if (action === 'refresh') loadState();
  else if (action === 'unlockUi') unlockUi();
  else if (action === 'lockUi') lockUi();
  else if (action === 'openResetPinModal') openResetPinModal();
  else if (action === 'closeResetPinModal') closeResetPinModal();
  else if (action === 'confirmResetPin') confirmResetPin();
  else if (action === 'backupNow') backupNow();
  else if (action === 'pickBackupFolder') pickBackupFolder();
  else if (action === 'saveBackupFolder') saveBackupFolder();
  else if (action === 'deleteBackup') openDeleteBackupModal(target.dataset.file);
  else if (action === 'closeDeleteBackupModal') closeDeleteBackupModal();
  else if (action === 'confirmDeleteBackup') confirmDeleteBackup();
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
  else if (action === 'loadBackups') loadBackups();
  else if (action === 'generateApiToken') generateApiToken();
  else if (action === 'copyApiToken') copyApiToken();
  else if (action === 'openGenerateApiToken') openGenerateApiToken();
  else if (action === 'closeApiTokenModal') closeApiTokenModal();
  else if (action === 'confirmGenerateApiToken') generateApiToken();
});

function changeTab(name) {
  for (const tabName of ['board', 'backup', 'connect', 'faq', 'about']) {
    const selected = tabName === name;
    document.getElementById(`tab-${tabName}`).setAttribute('aria-selected', String(selected));
    document.getElementById(`panel-${tabName}`).hidden = !selected;
  }
  if (name === 'backup') loadBackups();
}

async function loadBackups() {
  const list = document.getElementById('backupList');
  list.className = 'empty';
  list.textContent = 'Loading backups…';
  try {
    const data = await api('/api/backups');
    const folderInput = document.getElementById('backupFolderInput');
    const folderNote = document.getElementById('backupFolderNote');
    if (folderInput && data.backup_dir) folderInput.value = data.backup_dir;
    if (folderNote && data.backup_dir && !folderNote.textContent) folderNote.textContent = 'Active folder: ' + data.backup_dir;
    if (!data.backups.length) {
      list.textContent = 'No backups saved yet.';
      return;
    }
    list.className = '';
    list.innerHTML = data.backups.map(item => `
      <div class="backup-item">
        <div><strong>${escapeHtml(item.name)}</strong><div class="muted">${escapeHtml(item.modified_utc)} · ${(item.size / 1024).toFixed(1)} KB</div></div>
        <div class="row">
          <a class="button mini" href="/api/backup/download?file=${encodeURIComponent(item.name)}">Download</a>
          <button class="mini bad" data-action="deleteBackup" data-file="${escapeHtml(item.name)}">Delete</button>
        </div>
      </div>`).join('');
  } catch (err) {
    list.className = 'empty';
    list.innerHTML = `Could not load backups: ${escapeHtml(err.message)} <button class="mini" data-action="loadBackups">Retry</button>`;
  }
}

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
      <button data-action="openResetPinModal">Forgot PIN?</button>
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

function lockUi() {
  setSessionPin("");
  const result = document.getElementById("apiTokenResult");
  const tokenInput = document.getElementById("apiTokenValue");
  if (result) result.style.display = "none";
  if (tokenInput) tokenInput.value = "";
  loadState();
}

async function generateApiToken() {
  closeApiTokenModal();
  try {
    const result = await api("/api/api-token", { method: "POST", body: "{}" });
    document.getElementById("apiTokenValue").value = result.token;
    document.getElementById("apiTokenResult").style.display = "block";
  } catch (err) { showError(err.message); }
}

function openGenerateApiToken() {
  if (!requireUnlockedPin()) return;
  const dlg = document.getElementById("apiTokenModal");
  if (dlg.showModal) dlg.showModal();
  else dlg.setAttribute("open", "");
}

function closeApiTokenModal() {
  const dlg = document.getElementById("apiTokenModal");
  if (dlg.close) dlg.close();
  else dlg.removeAttribute("open");
}

async function copyApiToken() {
  const tokenInput = document.getElementById("apiTokenValue");
  if (!tokenInput || !tokenInput.value) return;
  tokenInput.focus();
  tokenInput.select();
  try {
    await navigator.clipboard.writeText(tokenInput.value);
  } catch (_) {
    showError("Token selected. Copy it now and store it in your remote action settings.");
  }
}

function openResetPinModal() {
  const dlg = document.getElementById("resetPinModal");
  if (dlg.showModal) dlg.showModal();
  else dlg.setAttribute("open", "");
}

function closeResetPinModal() {
  const dlg = document.getElementById("resetPinModal");
  if (dlg.close) dlg.close();
  else dlg.removeAttribute("open");
}

async function confirmResetPin() {
  closeResetPinModal();
  try {
    await api("/api/pin/reset", { method: "POST", body: "{}" });
    setSessionPin("");
    await loadState();
  } catch (err) { showError(err.message); }
}

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
  const raw = document.getElementById("addAgentName").value.trim();
  const description = document.getElementById("addAgentDesc").value.trim();
  const names = raw.split(",").map(s => s.trim()).filter(Boolean);
  if (!names.length) { showError("Enter an agent name."); return; }
  try {
    for (const name of names) {
      await api("/api/agents", { method: "POST", body: JSON.stringify({ name, description }) });
    }
    document.getElementById("addAgentName").value = "";
    document.getElementById("addAgentDesc").value = "";
    document.getElementById("agentSyncNote").textContent = `Added ${names.length} agent(s). Click "Copy Setup Prompt" to share instructions.`;
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

async function backupNow() {
  try {
    const res = await api("/api/backup/now", { method: "POST", body: "{}" });
    document.getElementById("backupFolderNote").textContent = "Saved backup: " + res.file;
    await loadBackups();
  } catch (err) { showError(err.message); }
}

async function saveBackupFolder() {
  const folder = document.getElementById("backupFolderInput").value.trim();
  if (!folder) { showError("Enter a backup folder path."); return; }
  try {
    const res = await api("/api/backup/folder", { method: "POST", body: JSON.stringify({ folder }) });
    document.getElementById("backupFolderInput").value = res.backup_dir;
    document.getElementById("backupFolderNote").textContent = "Backup folder saved: " + res.backup_dir;
    await loadBackups();
  } catch (err) { showError(err.message); }
}

async function pickBackupFolder() {
  try {
    const res = await api("/api/backup/pick-folder", { method: "POST", body: "{}" });
    if (res.backup_dir) {
      document.getElementById("backupFolderInput").value = res.backup_dir;
      document.getElementById("backupFolderNote").textContent = "Backup folder updated: " + res.backup_dir;
      await loadBackups();
    }
  } catch (err) { showError(err.message); }
}

function openDeleteBackupModal(file) {
  DELETE_BACKUP_TARGET = file;
  document.getElementById("deleteBackupTitle").textContent = `Delete "${file}"?`;
  const dlg = document.getElementById("deleteBackupModal");
  if (dlg.showModal) dlg.showModal();
  else dlg.setAttribute("open", "");
}

function closeDeleteBackupModal() {
  DELETE_BACKUP_TARGET = null;
  const dlg = document.getElementById("deleteBackupModal");
  if (dlg.close) dlg.close();
  else dlg.removeAttribute("open");
}

async function confirmDeleteBackup() {
  if (!DELETE_BACKUP_TARGET) return;
  const file = DELETE_BACKUP_TARGET;
  closeDeleteBackupModal();
  try {
    await api("/api/backup/delete", { method: "POST", body: JSON.stringify({ file }) });
    document.getElementById("backupFolderNote").textContent = "Deleted backup: " + file;
    await loadBackups();
  } catch (err) { showError(err.message); }
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
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> dict[str, Any]:
            if self.headers.get_content_type() != "application/json":
                raise UnsupportedMediaTypeError("Content-Type must be application/json.")
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length < 0:
                raise ValueError("Content-Length cannot be negative.")
            if length > MAX_REQUEST_BODY_BYTES:
                raise RequestTooLargeError(f"Request body exceeds {MAX_REQUEST_BODY_BYTES} bytes.")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object.")
            return body

        def _has_valid_bearer_token(self) -> bool:
            authorization = self.headers.get("Authorization", "").strip()
            scheme, separator, token = authorization.partition(" ")
            return bool(separator and scheme.lower() == "bearer" and store.verify_api_token(token.strip()))

        def _send_unauthorized(self) -> None:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Bearer realm="Agent Scoreboard"')
            self.send_header("Cache-Control", "no-store")
            body = json.dumps({"error": "Valid bearer token required."}).encode("utf-8")
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            tunneled = is_tunneled_request(self)
            # Only the explicitly documented agent read endpoint can cross a public tunnel.
            if tunneled and parsed.path != "/api/warnings":
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied over tunnel"})
                return
            if tunneled and not self._has_valid_bearer_token():
                self._send_unauthorized()
                return

            if parsed.path == "/favicon.ico":
                asset_name = "app_icon.ico"
                asset_path = ASSETS_DIR / asset_name
                self._send_asset(asset_path, "image/x-icon")
                return

            if parsed.path.startswith("/assets/"):
                asset_name = parsed.path.removeprefix("/assets/")
                asset_types = {
                    "app_icon.png": "image/png",
                    "app_icon.ico": "image/x-icon",
                    "chinlung_logo.png": "image/png",
                    "logo.svg": "image/svg+xml; charset=utf-8",
                }
                if asset_name not in asset_types:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
                    return
                self._send_asset(ASSETS_DIR / asset_name, asset_types[asset_name])
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

            if parsed.path == "/api/backups":
                self._send_json(HTTPStatus.OK, {
                    "backup_dir": str(store.get_backup_dir()),
                    "backups": store.list_backups(),
                })
                return

            if parsed.path == "/api/backup/download":
                query = urllib.parse.parse_qs(parsed.query)
                requested = query.get("file", [""])[0]
                is_backup_name = (
                    (requested.startswith("scoreboard.backup.") or requested.startswith("scoreboard.auto.") or requested.startswith("scoreboard.manual."))
                    and requested.endswith(".json")
                    and "/" not in requested
                    and "\\" not in requested
                )
                available = {item["name"] for item in store.list_backups()}
                if is_backup_name and requested in available:
                    filename = requested
                    path = store.get_backup_dir() / filename
                    if not path.is_file():
                        path = store.data_dir / filename
                else:
                    filename = "scoreboard.json"
                    path = store.scoreboard_path
                try:
                    payload = path.read_bytes()
                except OSError:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "Backup not found"})
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            if parsed.path == "/api/warnings":
                qs = urllib.parse.parse_qs(parsed.query)
                agent = qs.get("agent", [None])[0]
                self._send_json(HTTPStatus.OK, store.get_agent_warnings(agent))
                return

            self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

        def _send_asset(self, path: Path, content_type: str) -> None:
            try:
                payload = path.read_bytes()
            except OSError:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "Asset not found"})
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            tunneled = is_tunneled_request(self)
            # Only the documented agent proposal endpoint can cross a public tunnel.
            if tunneled and parsed.path != "/api/propose":
                self.close_connection = True
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "Access denied over tunnel"})
                return
            if tunneled and not self._has_valid_bearer_token():
                self.close_connection = True
                self._send_unauthorized()
                return
            if tunneled and not store.allow_remote_proposal():
                self.close_connection = True
                self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many remote proposals. Try again in a minute."})
                return

            if not tunneled:
                origin = self.headers.get("Origin")
                host = self.headers.get("Host", "").strip().lower()
                expected_origin = f"http://{host}" if host else ""
                if origin and origin != expected_origin:
                    self.close_connection = True
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "Cross-origin requests are not allowed."})
                    return

            try:
                body = self._read_body()
                pin = self.headers.get("X-Scoreboard-Pin", "").strip() or str(body.get("pin", "")).strip()

                if parsed.path == "/api/api-token":
                    token = store.rotate_api_token(pin)
                    self._send_json(HTTPStatus.OK, {"ok": True, "token": token})
                    return

                if parsed.path == "/api/pin/setup":
                    store.set_pin(str(body.get("pin", "")))
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/pin/verify":
                    store.verify_pin(pin)
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/pin/reset":
                    backup = store.reset_pin_and_archive()
                    self._send_json(HTTPStatus.OK, {"ok": True, "backup": str(backup)})
                    return

                if parsed.path == "/api/backup/now":
                    backup = store.create_manual_backup()
                    self._send_json(HTTPStatus.OK, {"ok": True, "file": backup.name})
                    return

                if parsed.path == "/api/backup/delete":
                    store.delete_backup(str(body.get("file", "")))
                    self._send_json(HTTPStatus.OK, {"ok": True})
                    return

                if parsed.path == "/api/backup/folder":
                    bdir = store.set_backup_dir(str(body.get("folder", "")))
                    self._send_json(HTTPStatus.OK, {"ok": True, "backup_dir": str(bdir)})
                    return

                if parsed.path == "/api/backup/pick-folder":
                    import tkinter as tk
                    from tkinter import filedialog
                    root = tk.Tk()
                    root.withdraw()
                    root.attributes("-topmost", True)
                    chosen = filedialog.askdirectory(title="Choose Agent Scoreboard Backup Folder")
                    root.destroy()
                    if not chosen:
                        self._send_json(HTTPStatus.OK, {"ok": True, "backup_dir": None})
                        return
                    bdir = store.set_backup_dir(chosen)
                    self._send_json(HTTPStatus.OK, {"ok": True, "backup_dir": str(bdir)})
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
            except RequestTooLargeError as exc:
                self.close_connection = True
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": str(exc)})
            except UnsupportedMediaTypeError as exc:
                self._send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": str(exc)})
            except KeyError as exc:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": str(exc)})
            except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

    return Handler


def _open_app_window(url: str) -> None:
    """Open the scoreboard in a Chromium app window when a browser is available."""
    for executable in ("msedge.exe", "chrome.exe"):
        browser_path = shutil.which(executable)
        if browser_path:
            try:
                subprocess.Popen([browser_path, f"--app={url}"])
                return
            except OSError:
                continue
    webbrowser.open(url)


def run_app(store: ScoreboardStore, host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> None:
    """Launch Agent Scoreboard in a native PyWebView desktop window (or Edge/Chrome --app fallback)."""
    handler = make_handler(store)
    server = None
    for candidate in ([port, *range(port + 1, port + 25), 0] if port != 0 else [0]):
        try:
            server = ThreadingHTTPServer((host, candidate), handler)
            break
        except OSError:
            pass
    if server is None:
        raise RuntimeError(f"Could not bind Agent Scoreboard server on {host}:{port}")
    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        import webview
        webview.create_window("Agent Scoreboard — Chinlung Technologies", url, width=1280, height=840, min_size=(960, 620))
        webview.start()
    except Exception:
        _open_app_window(url)
        try:
            t.join()
        except KeyboardInterrupt:
            pass
    finally:
        server.shutdown()
        server.server_close()


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
                                _open_app_window(url)
                            return
                except Exception:
                    pass
    if server is None:
        raise RuntimeError(f"Could not bind Agent Scoreboard server on {host}:{port}")

    actual_port = server.server_address[1]
    url = f"http://{host}:{actual_port}"
    print(f"Agent Scoreboard running at {url} (data: {store.data_dir})", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: _open_app_window(url)).start()
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

    sub.add_parser("reset-pin", help="Archive scoreboard and reset forgotten PIN (keeps agents & categories)")
    sub.add_parser("app", help="Launch Agent Scoreboard as a standalone desktop app window")

    args = parser.parse_args(argv)
    store = ScoreboardStore(args.data_dir)

    if args.cmd == "app" or (args.cmd is None and getattr(sys, "frozen", False)):
        run_app(store, host="127.0.0.1", port=DEFAULT_PORT)
        return 0

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

    if args.cmd == "reset-pin":
        backup = store.reset_pin_and_archive()
        print(f"PIN reset. Old scoreboard archived to: {backup}")
        print("Open the Leaderboard UI and set a new Owner PIN.")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
