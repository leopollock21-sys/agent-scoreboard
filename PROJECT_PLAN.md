# Agent Scoreboard Project Plan

## Live Beacon
- Active release: 1.2.0 security hardening for public source distribution.
- Canonical branch: `main`.
- Baseline revision: `b6f97bb1cab96e9ead41a0359c4426a998561f9b`.
- Current state: local hardening complete; GitHub publication is not part of this task.
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
- 2026-11-22: Completed 1.2.0 public-release hardening and local validation. A follow-up test found and fixed reset-prone early POST rejections; focused HTTP tests passed three consecutive runs. The GitHub repository remains unchanged; no push was made.
