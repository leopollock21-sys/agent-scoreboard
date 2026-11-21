#!/usr/bin/env python3
"""
One-step cross-platform installer for Agent Scoreboard.
- Installs the Antigravity plugin into ~/.gemini/config/plugins/agent-scoreboard
  with the resolved absolute path to mcp_server.py.
- Initializes ~/.agent-scoreboard/agent_brief.md.
- Prints ready-to-paste MCP config for Claude Desktop / Codex CLI.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))
from scoreboard import ScoreboardStore


def install_antigravity_plugin() -> Path:
    dest = Path.home() / ".gemini" / "config" / "plugins" / "agent-scoreboard"
    (dest / "assets").mkdir(parents=True, exist_ok=True)
    (dest / "skills" / "agent-scoreboard").mkdir(parents=True, exist_ok=True)
    (dest / "rules").mkdir(parents=True, exist_ok=True)

    shutil.copy2(REPO_ROOT / "plugin.json", dest / "plugin.json")
    shutil.copy2(REPO_ROOT / "assets" / "logo.svg", dest / "assets" / "logo.svg")
    shutil.copy2(
        REPO_ROOT / "skills" / "agent-scoreboard" / "SKILL.md",
        dest / "skills" / "agent-scoreboard" / "SKILL.md",
    )
    shutil.copy2(REPO_ROOT / "rules" / "AGENTS.md", dest / "rules" / "AGENTS.md")

    mcp_path = str((REPO_ROOT / "mcp_server.py").resolve())
    mcp_cfg = {
        "mcpServers": {
            "agent_scoreboard": {
                "command": sys.executable,
                "args": [mcp_path],
            }
        }
    }
    (dest / "mcp_config.json").write_text(
        json.dumps(mcp_cfg, indent=2) + "\n", encoding="utf-8"
    )
    return dest


def main() -> int:
    store = ScoreboardStore()
    store.regenerate_brief()
    plug_dir = install_antigravity_plugin()
    mcp_path = str((REPO_ROOT / "mcp_server.py").resolve())

    print(f"Initialized scoreboard data: {store.data_dir}")
    print(f"Installed Antigravity plugin: {plug_dir}")
    print("\nClaude Desktop / Codex MCP snippet:")
    print(
        json.dumps(
            {
                "mcpServers": {
                    "agent_scoreboard": {
                        "command": sys.executable,
                        "args": [mcp_path],
                    }
                }
            },
            indent=2,
        )
    )
    print(f"\nStart the Leaderboard UI with:\n  {sys.executable} \"{REPO_ROOT / 'scoreboard.py'}\" serve --open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
