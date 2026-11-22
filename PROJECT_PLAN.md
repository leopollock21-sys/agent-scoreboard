# Agent Scoreboard Project Plan

## Live Beacon
- Active release: 1.2.0 private source and local Windows test executable.
- Canonical branch: `main`.
- Baseline revision: `b6f97bb1cab96e9ead41a0359c4426a998561f9b`.
- Current state: GitHub repository is private. Rebuilt and registered the local v1.2.0 EXE as `AgentScoreboard-v1.2.0-rebuilt.exe`; the prior canonical EXE remains open in two running processes and was left untouched. No valid Chinlung code-signing certificate or signtool is available in the current Windows certificate stores.
- Release gates: protect public tunnel routes with an owner-generated bearer token; bound HTTP and proposal input; protect local browser mutations from cross-origin requests; review public source for credentials and private paths.

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


## Windows Executable Gate
- [x] Build a version-stamped one-file AgentScoreboard.exe from the committed source.
- [x] Smoke-test the executable using isolated temporary data.
- [x] Verify file version, SHA-256, and Authenticode status.
- [x] Register the artifact in OFFICIAL_RELEASES.
