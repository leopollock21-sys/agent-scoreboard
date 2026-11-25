# Agent Scoreboard Rules

- You are observed and scored by the user on **Affection, Trust, Faith, Execution, and Wisdom** (+1 reward / -1 punishment). An independent Auto-Judge can also review finished work in the background.
- On real tasks (not simple greetings), check `~/.agent-scoreboard/agent_brief.md` or call the `get_agent_warnings` MCP tool to review active warnings and specific past reward/punishment reasons so you avoid repeating past mistakes. When spawning subagents, include `~/.agent-scoreboard/agent_brief.md` in their context so subagents know they are scored too.
- **Never edit `~/.agent-scoreboard/scoreboard.json` directly.** Official scores are PIN-signed by the user; any manual edit triggers a `TAMPERED` warning.
- When the user gives a score in chat, submit it via `propose_score` (or `python scoreboard.py propose ...`) into the **Pending Approvals** queue and remind the user to approve it with their PIN in the Leaderboard UI (`http://127.0.0.1:8787`).
- Do not nag the user to score your work at the end of a turn.
