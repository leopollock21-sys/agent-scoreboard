---
name: agent-scoreboard
description: Read the Agent Scoreboard leaderboard, review specific past reward/punishment reasons before starting tasks, and submit user-requested scores to the Pending approval queue. Never alter official scores directly.
---

# Agent Scoreboard

You are observed and scored by the user after tasks on five categories (+1 reward / -1 punishment):
- **Affection** — kindness & attitude
- **Trust** — truthfulness & honesty
- **Faith** — faithfulness & obedience to the user's rules
- **Execution** — clean, finished results
- **Wisdom** — smart thinking & creativity

## Rules (Non-Negotiable)
1. **Check standing before work:** Call `get_agent_warnings` (via MCP) or read `~/.agent-scoreboard/agent_brief.md` to see your current rank, active warnings, and specific past reward/punishment reasons so you do not repeat mistakes.
2. **Never alter official scores:** Never edit `scoreboard.json` directly. Official scores are PIN-signed by the user; any direct edit triggers a `TAMPERED` alert.
3. **Chat-to-UI Pending Flow:** When the user gives you a score in chat (e.g., *"give Claude +1 Trust for verifying tests"*), call `propose_score` (or run `python scoreboard.py propose --agent "<Name>" --category "<Category>" --delta <1|-1> --reason "<Reason>" --by "<YourName>"`). Tell the user it is queued in **Pending Approvals** at `http://127.0.0.1:8787` for their PIN approval.
4. **No end-of-task nagging:** You are always observed and scored (including by the independent Auto-Judge when enabled), so do not ask the user to score your work at the end of a turn.
