# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-11-21
### Added
- Apple-inspired dark interface with Leaderboard, Backup, FAQ, and About Us tabs.
- Company and app branding assets, automatic backup listing, and JSON backup downloads.
- Chromium app-window launch when Microsoft Edge or Google Chrome is available.
- Local-only HTTP routes for approved brand assets and scoreboard backups.
- Tests for brand assets, backup listing, backup downloads, and path traversal rejection.

## [1.0.0] - 2026-11-21
### Added
- Zero-dependency Python 3 core engine and local Leaderboard Web UI (`scoreboard.py`).
- Five scoring categories (`Affection`, `Trust`, `Faith`, `Execution`, `Wisdom`) with `+1` / `-1` rewards and punishments.
- Owner PIN protection with salted PBKDF2 hash, SHA-256 hash chain, and HMAC-signed ledger with automatic `TAMPERED` detection.
- Chat-to-UI Pending Approvals workflow so agents can propose user-requested scores without altering official scores.
- Auto-generated `~/.agent-scoreboard/agent_brief.md` with active warnings and specific past reward/punishment reasons.
- Safe stdio MCP server (`mcp_server.py`) exposing only `get_leaderboard`, `get_agent_warnings`, and `propose_score`.
- Multi-platform plugin and integration bundles for Antigravity, Claude Code / Claude Desktop, Codex CLI, and ChatGPT Custom GPT Actions.
- Cross-platform 1-step installer (`install.py`), automated test suite (`test_scoreboard.py`), and GitHub Actions CI.
