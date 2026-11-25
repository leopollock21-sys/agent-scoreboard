# Agent Scoreboard Project Plan

## Live Beacon
- Active release: 1.3.0 (Auto-Judge hook, provider engine, UI tab, and rebuilt unsigned Windows executable).
- Canonical branch: `main`.
- Latest EXE SHA-256: `002118ED793D5A4A0247632FF2F83F432624F7E6E2943E21FA7FB6844406944B` (registered in `OFFICIAL_RELEASES\Agent-Scoreboard\AgentScoreboard.exe`).
- Release gates: protect public tunnel routes with an owner-generated bearer token; keep `/api/auto-judge/*` strictly local-only and PIN-gated; bound HTTP and proposal input; protect local browser mutations from cross-origin requests; review public source for credentials and private paths.

## Security Release Checklist
- [x] Require bearer authentication for tunneled warning and proposal routes.
- [x] Provide owner-only UI flow to generate and copy a remote API token.
- [x] Enforce request, proposal field, proposal queue, and public proposal rate limits.
- [x] Validate same-origin browser POSTs and JSON content type.
- [x] Update ChatGPT OpenAPI and setup documentation.
- [x] Add regression coverage and run required checks.
- [x] Review the final public source diff for secrets, personal data, machine paths, and unrelated files.
- [x] Update release notes and version metadata.

## Change Log
- 2026-11-22: Completed 1.2.0 public-release hardening and local validation. A follow-up test found and fixed reset-prone early POST rejections; focused HTTP tests passed three consecutive runs. Source commit 50e52d6 is on GitHub main. The repository was made private on 2026-11-22. Rebuilt and smoke-tested the local v1.2.0 EXE; registered SHA-256 `24344BC868A06422BAA056986CF60C92482B65204B8650760CD15912096F5295`. Authenticode remains NotSigned because no valid Chinlung signing certificate or signtool is available. The desktop shortcut now targets the rebuilt copy; the running old processes were not terminated.
- 2026-11-22: User requested public GitHub distribution without signing. Confirmed the tracked source and Git history contain no detected private-key, GitHub/cloud-key, or machine-path patterns; confirmed the rebuilt executable remains Authenticode `NotSigned`. Made the repository public and published the rebuilt executable under `v1.2.0-rebuild-20261122` because the original v1.2.0 release is immutable. GitHub's uploaded asset SHA-256 matches local `24344BC868A06422BAA056986CF60C92482B65204B8650760CD15912096F5295`.
- 2026-11-25: Implemented independent Auto-Judge (`auto_judge.py`) supporting Gemini, OpenAI, OpenRouter, and local Ollama using Python stdlib only. Added Antigravity `Stop` hook registration in `install.py` (`hooks.json`), secret masking, turn deduplication (`auto_judge_state.json`), local-only `/api/auto-judge/*` routes and **Auto-Judge** UI tab in `scoreboard.py` (all proposals gated into Pending Approvals), plus `test_auto_judge.py` and `README.md` docs.


## Windows Executable Gate
- [x] Build a version-stamped one-file AgentScoreboard.exe from the committed source.
- [x] Smoke-test the executable using isolated temporary data.
- [x] Verify file version, SHA-256, and Authenticode status.
- [x] Register the artifact in OFFICIAL_RELEASES.
