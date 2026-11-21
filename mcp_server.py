#!/usr/bin/env python3
"""
Agent Scoreboard MCP Server (stdio JSON-RPC 2.0, zero external dependencies).

Exposes ONLY safe agent tools:
  - get_leaderboard: read-only ranked leaderboard & tamper status
  - get_agent_warnings: read-only warnings + specific past reward/punishment reasons
  - propose_score: submits a score to the human Pending approval queue (cannot alter official scores)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure sibling scoreboard.py is importable regardless of cwd
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scoreboard import ScoreboardStore

SERVER_INFO = {
    "name": "agent-scoreboard",
    "version": "1.0.0",
}

TOOLS = [
    {
        "name": "get_leaderboard",
        "description": (
            "Read the current Agent Scoreboard leaderboard, categories "
            "(Affection, Trust, Faith, Execution, Wisdom), and tamper integrity status. Read-only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "get_agent_warnings",
        "description": (
            "Read active warnings and specific past reward/punishment reasons for an agent "
            "(or all agents if agent is omitted). Call this when starting a task to learn from past feedback."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {
                    "type": "string",
                    "description": "Optional agent name (e.g., Antigravity, Claude, Codex, ChatGPT).",
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "propose_score",
        "description": (
            "Submit a user-requested reward (+1) or punishment (-1) into the Pending approval queue "
            "in the Agent Scoreboard UI. Only call this when the user explicitly tells you a score in chat. "
            "Agents cannot approve or alter official scores."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent": {"type": "string", "description": "Target agent name."},
                "category": {
                    "type": "string",
                    "enum": ["Affection", "Trust", "Faith", "Execution", "Wisdom"],
                    "description": "Scoring category.",
                },
                "delta": {
                    "type": "integer",
                    "enum": [-1, 1],
                    "description": "+1 for reward, -1 for punishment.",
                },
                "reason": {
                    "type": "string",
                    "description": "Specific reason stated by the user for this reward or punishment.",
                },
                "proposed_by": {
                    "type": "string",
                    "description": "Name of the agent submitting the user's score request.",
                },
            },
            "required": ["agent", "category", "delta", "reason"],
            "additionalProperties": False,
        },
    },
]


def handle_request(store: ScoreboardStore, req: dict[str, Any]) -> dict[str, Any] | None:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        try:
            if not isinstance(args, dict):
                raise ValueError("Tool arguments must be a JSON object.")
            if name == "get_leaderboard":
                board = store.build_leaderboard()
                result = {
                    "categories": board["categories"],
                    "integrity_ok": board["integrity"]["ok"],
                    "leaderboard": [
                        {
                            "rank": r["rank"],
                            "agent": r["agent"],
                            "total": r["total"],
                            "scores": r["scores"],
                            "status": r["status"],
                            "warnings": r["warnings"],
                        }
                        for r in board["leaderboard"]
                    ],
                }
            elif name == "get_agent_warnings":
                result = store.get_agent_warnings(args.get("agent"))
            elif name == "propose_score":
                proposal = store.propose_score(
                    agent=str(args.get("agent", "")),
                    category=str(args.get("category", "")),
                    delta=int(args.get("delta", 0)),
                    reason=str(args.get("reason", "")),
                    proposed_by=str(args.get("proposed_by", "agent")),
                )
                result = {
                    "ok": True,
                    "status": "pending_human_approval",
                    "message": "Queued in Pending Approvals. The user must approve it in the Leaderboard UI with their PIN.",
                    "proposal": proposal,
                }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {name}"},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2, ensure_ascii=False)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"ok": False, "error": str(exc)})}],
                    "isError": True,
                },
            }

    if req_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> int:
    store = ScoreboardStore()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(exc)}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
            continue
        resp = handle_request(store, req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
