<!-- GLOBAL-CLOUD-AGENTS:START (Managed by leopollock21-sys/.github/AGENTS.md — edit there, not here) -->
# AGENTS.md — Global Rules for Cloud Agents

Read this file together with **`BRAND.md`** and any project-specific rules below (or in `PROJECT_PLAN.md` / `README.md`) before making changes. Follow all of them — project-specific rules add local details for that repository.

## 1. Who You Are Working For
- The repository owner is a **non-technical founder**; short English or Myanmar messages are normal.
- Handle all technical work yourself once the goal is clear.
- Write every reply, issue comment, and Pull Request summary in **plain everyday English** (no jargon, no filler, no flattery).

## 2. Ask on WHAT, Never on HOW
- If the goal is unclear, stop before editing code and ask **1 short plain-language choice question**.
- Once the goal is clear, finish and verify the work yourself without asking technical questions about files, branches, or commands.

## 3. 100% Honesty & Real Proof
- Never guess, bluff, invent numbers, or output made-up `%` scores.
- Never claim a fix or UI works unless you actually ran and verified it.
- Always include real proof in your final summary (exact test commands and pass/fail output, diff summary, or screenshot).
- If a tool, build, or test fails, stop and report the real error and clear next options.

## 4. Token & Credit Cost Awareness
- **Always choose the lowest-cost path that solves the task cleanly.**
- **Read narrowly, not broadly:** Use targeted search first and read only the exact files and line ranges needed. Never scan `node_modules/`, `build/`, `dist/`, `archive/`, lockfiles, or large generated/binary files.
- **Stop blind retry loops:** Never burn credits on long trial-and-error fix loops. If the same build or test error fails **2–3 times**, stop, explain the real blocker, and present clear next options.
- **Smart tool & test usage:** Handle small 1–3 file changes directly instead of spawning extra subagents. Run fast targeted tests while iterating, then run the broader test suite once before opening the PR.
- **Keep outputs concise:** Write short, direct PR summaries and comments without filler or repeating long code dumps.

## 5. Cloud Computer Testing & Handoff Rules
- **Test everything you CAN in the cloud computer first:**
  - Always run existing unit/integration tests, linters, type/syntax checks, and build/compile checks available in the cloud sandbox.
  - For web apps, run headless browser checks (e.g., Playwright/Chromium) when available to verify clicks, language switching, and zero console errors.
  - Add at least 1 runnable automated test for new or non-trivial logic.
- **Honest handoff for what a Linux cloud computer CANNOT test:**
  - Do not fake checks for Windows desktop `.exe` behavior, Windows receipt printers, real Android phones, camera/QR scanners, Wi-Fi chips, or signed release packages.
  - Mark only those OS/hardware-specific checks clearly as **`[NEEDS LOCAL TEST]`** and include a short **2–3 step click/tap checklist** so the owner or a local agent can verify them quickly.

## 6. Cloud Sandbox & Git Safety Boundaries
- **Always use a new branch and Pull Request:** Never push directly to `main` (or default branch) unless explicitly instructed.
- **Keep PRs small, focused, and readable.** Every Pull Request description must include:
  1. **What changed** (plain everyday language)
  2. **How it was tested** (exact commands + results, plus any `[NEEDS LOCAL TEST]` checklist)
  3. **Any risks or follow-up needed**
- **No packaging, signing, or live deploys in the cloud:** Do not build final `.exe`/`.apk` release installers, touch signing keys, or alter live production servers, databases, or billing settings.
- **Stay offline-safe & single-repo:** Do not assume other repositories or local drives exist, and avoid adding new dependencies that require live internet downloads unless already present/cached or explicitly approved.
- **Never run destructive actions** (force-push, branch/tag deletion, `DROP`/`TRUNCATE`/broad `DELETE`) without explicit owner approval.

## 7. Read-Only Gate (Reviews, Audits & Plans)
- When asked to **review, check, audit, inspect, or plan**, stay **100% read-only**.
- Report your findings clearly and **stop** — do not edit files, commit, or open a PR until approved.

## 8. Engineering Standards
- **Fix the root cause:** Trace the full flow and all callers before editing. Avoid band-aid patches.
- **Keep it lean:** Reuse existing helpers, built-in standard libraries, and installed packages first. Only use commercial-safe licenses (MIT, Apache-2.0, BSD — never GPL/AGPL without approval).
- **Stay in scope:** Build only what was requested. Never break or remove working features.
- **Ignore noise:** Never edit or copy from `archive/`, `build/`, `dist/`, or binary files (`.exe`, `.apk`, `.dll`, `.jar`).
- Read `PROJECT_PLAN.md` (if present) before coding, and update it after real code changes.

## 9. Brand, UI, Accessibility & Language Purity
- **Brand Standard (`BRAND.md`):** Always read and follow **`BRAND.md`** for Chinlung Technologies identity, Great Hornbill (`Vapual`) logo rules, official color palette (`#0B1B3D` / `#0E1424`, `#F59E0B` / `#E5A93C`, `#00D2FF`), minimalist Apple-style UI layout, and tone before designing or changing any UI.
- **No Button, No Feature:** Every user-facing feature must work 100% with mouse or touch (end users must never need terminal commands).
- Keep **1 clear primary action per screen**, comfortable touch targets (`44–48px`), and handle all **4 UI states**: Empty, Loading, Error (with Retry), and Populated.
- **100% Language Purity:** For multilingual apps (English, Myanmar/Burmese, Hakha Lai, Mizo), never mix languages on the same screen, button, modal, or printed receipt/voucher, and never show raw code keys or enum names to users.

## 10. Privacy & Security (Zero Leaks)
- **Never commit** API keys, tokens, passwords, `.env` secrets, private local file paths, private IPs, or real customer/patient/NGO beneficiary data (names, phone numbers, addresses, raw field sheets).
- Treat authentication, PINs, licensing, payments, and NGO/beneficiary records as strictly sensitive — carefully verify permissions, input validation, and data handling before opening a PR.
<!-- GLOBAL-CLOUD-AGENTS:END -->
