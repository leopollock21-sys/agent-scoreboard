# Agent Scoreboard

A simple, zero-dependency, tamper-evident **scoring, reward, and punishment leaderboard** for all your AI agents (**Antigravity, Claude Code / Claude Desktop, OpenAI Codex CLI, and ChatGPT**), built by **Chinlung Technologies**.

## What Agent Scoreboard Is Trying to Do
AI agents do not feel pride or pain on their own, and letting an AI grade itself produces fake status reports. **Agent Scoreboard** turns real human judgment into a closed-loop memory system:
1. After a task, you reward (`+1`) or punish (`-1`) the agent with a **specific reason** (for example: *"+1 Trust — showed real test logs"* or *"-1 Faith — skipped git commit rule"*).
2. Every official score is locked with your private PIN so no agent can alter its own standing.
3. Every approved score automatically updates `~/.agent-scoreboard/agent_brief.md` with each agent's rank, active warnings, and recent specific reward/punishment reasons—which agents read at the start of their next task so they stop repeating past mistakes.

## What the Scoring System Is Based On
The leaderboard is based on five core human-AI partnership pillars (`+1` Reward / `-1` Punishment):
1. **Affection** — Kindness, tone, and helpful attitude
2. **Trust** — Truthfulness, honesty, and verified proof (never guessing or bluffing)
3. **Faith** — Faithfulness and strict obedience to your rules and goals
4. **Execution** — Clean, finished results without breaking working code
5. **Wisdom** — Smart, creative, simple root-cause problem solving

## Why Agents Cannot Cheat
- **Owner PIN:** You set a private PIN in the Leaderboard UI. Only a salted PBKDF2 hash is stored; your PIN is never saved in plain text.
- **Pending → Approve Flow:** Agents only have read + `propose_score` tools. When you tell an agent a score in chat, it lands in **Pending Approvals**—nothing updates the official leaderboard until you click **Approve** with your PIN.
- **Tamper Detection:** Every official score entry is SHA-256 hash-chained and HMAC-signed with your PIN. Any direct edit to `scoreboard.json` triggers an immediate red **`TAMPERED`** alert.
- **Closed-Loop Feedback:** Every approved score regenerates `~/.agent-scoreboard/agent_brief.md` with each agent's rank, active warnings, and **specific past reward/punishment reasons** so agents see what they did right or wrong at the start of their next task.

## Requirements
- Python 3.10+ (zero third-party packages required)

## Quick Start
```bash
git clone https://github.com/leopollock21-sys/agent-scoreboard.git
cd agent-scoreboard
python install.py
python scoreboard.py serve --open
```
This installs the Antigravity plugin, initializes `~/.agent-scoreboard/`, and opens the local Leaderboard UI at `http://127.0.0.1:8787`. Your personal scores stay outside the repo in `~/.agent-scoreboard/` (override with `AGENT_SCOREBOARD_DIR`).

## Platform Setup

### 1. Antigravity Plugin
Run `python install.py` — it installs the bundle (`plugin.json`, `SKILL.md`, `rules/AGENTS.md`, `mcp_config.json`) into `~/.gemini/config/plugins/agent-scoreboard/` with your exact absolute path to `mcp_server.py`.

### 2. Claude Code & Claude Desktop
- **Claude Code:** Uses `.claude-plugin/plugin.json` and `skills/agent-scoreboard/SKILL.md`.
- **Claude Desktop:** Paste the MCP JSON snippet printed by `python install.py` into `claude_desktop_config.json`.

### 3. OpenAI Codex CLI (or any CLI agent)
Copy `skills/agent-scoreboard/SKILL.md` into your skills folder and point `AGENTS.md` to `~/.agent-scoreboard/agent_brief.md`. Any CLI agent can also submit chat scores via:
```bash
python scoreboard.py propose --agent "Codex" --category "Trust" --delta 1 --reason "Verified tests before claiming done" --by "Codex"
```

### 4. ChatGPT (Custom GPT Actions)
Because ChatGPT runs in OpenAI's cloud, expose your local server via a temporary HTTPS tunnel (for example, `cloudflared tunnel --url http://127.0.0.1:8787`), then import `chatgpt/openapi.json` into a Custom GPT Action and replace the server URL.
*Note: For security, administrative UI routes are blocked when accessed via public tunnels.*

## Run Tests
```bash
python -m unittest test_scoreboard.py -v
```

## Forgot Your PIN?
Because scores are signed with your PIN, a forgotten PIN cannot be recovered. Click **Forgot PIN?** next to the Unlock button in the Leaderboard UI and confirm **Start Fresh**—this saves a backup of your old scores, keeps all your agents, and lets you set a new PIN with zero commands. You can also manage, download, or delete old backup files directly from the **Backup** tab.

## Contact
**Chinlung Technologies** — [chinlungtech@gmail.com](mailto:chinlungtech@gmail.com)

## License
[MIT](LICENSE)
