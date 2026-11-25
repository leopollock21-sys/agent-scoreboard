#!/usr/bin/env python3
"""
Independent Auto-Judge for Agent Scoreboard.

Evaluates completed AI agent tasks using a configurable LLM provider
(Google Gemini, OpenAI, OpenRouter, or local Ollama) and submits score
proposals into Pending Approvals via ScoreboardStore.propose_score().

Zero external dependencies (Python 3.10+ standard library only).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROVIDERS: dict[str, dict[str, Any]] = {
    "gemini": {
        "label": "Google Gemini Flash",
        "default_model": "gemini-flash-lite-latest",
        "env_vars": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "requires_key": True,
    },
    "openai": {
        "label": "OpenAI Mini",
        "default_model": "gpt-4o-mini",
        "env_vars": ("OPENAI_API_KEY",),
        "requires_key": True,
    },
    "openrouter": {
        "label": "OpenRouter",
        "default_model": "google/gemini-2.5-flash",
        "env_vars": ("OPENROUTER_API_KEY",),
        "requires_key": True,
    },
    "ollama": {
        "label": "Local AI (Ollama)",
        "default_model": "llama3.2",
        "env_vars": (),
        "requires_key": False,
    },
}

VALID_MODES = ("notable_only", "every_task")
VALID_CATEGORIES = ("Affection", "Trust", "Faith", "Execution", "Wisdom")
MAX_TRANSCRIPT_CHARS = 4000
MAX_GIT_CHARS = 1200
MAX_BRIEF_CHARS = 2500
MAX_FINGERPRINTS = 200
HTTP_TIMEOUT_SECONDS = 30
TEST_TIMEOUT_SECONDS = 12

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "provider": "gemini",
    "model": "gemini-flash-lite-latest",
    "api_key": "",
    "mode": "notable_only",
    "use_env_key": True,
    "base_url": "",
}

_TRIVIAL_GREETING_RE = re.compile(
    r"^(hi|hello|hey|yo|sup|ok|okay|k|thanks|thank you|thx|ty|"
    r"good morning|good afternoon|good evening|good night|bye|goodbye|"
    r"cool|nice|got it|sure|yes|no|yep|nope)[!.?,\s]*$",
    re.IGNORECASE,
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bsk-(?:proj-|ant-|or-v1-)?[A-Za-z0-9_-]{16,}\b"), "[REDACTED_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+|bearer\s+)[A-Za-z0-9._~+/-]{12,}=*"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS|PRIVATE_KEY)[A-Z0-9_]*)"
            r"\s*([=:])\s*(['\"]?)([^\s'\"]{6,})\3"
        ),
        r"\1\2\3[REDACTED]\3",
    ),
    (re.compile(r"(?i)([?&](?:api_key|key|token|secret|password)=)([^&\s]{6,})"), r"\1[REDACTED]"),
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def resolve_data_dir(override: str | None = None) -> Path:
    if override:
        base = Path(override)
    elif os.environ.get("AGENT_SCOREBOARD_DIR"):
        base = Path(os.environ["AGENT_SCOREBOARD_DIR"])
    else:
        base = Path.home() / ".agent-scoreboard"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, path)


def _read_json_dict(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def mask_api_key(api_key: str) -> str:
    key = (api_key or "").strip()
    if not key:
        return ""
    if len(key) <= 4:
        return "••••"
    return "••••" + key[-4:]


def mask_secrets(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    if not text:
        return ""
    masked = text
    for secret in extra_secrets:
        s = (secret or "").strip()
        if len(s) >= 6:
            masked = masked.replace(s, "[REDACTED]")
    for pattern, replacement in _SECRET_PATTERNS:
        masked = pattern.sub(replacement, masked)
    return masked


def load_config(data_dir: Path) -> dict[str, Any]:
    raw = _read_json_dict(data_dir / "auto_judge.json")
    provider = str(raw.get("provider", DEFAULT_CONFIG["provider"])).strip().lower()
    if provider not in PROVIDERS:
        provider = DEFAULT_CONFIG["provider"]

    model = str(raw.get("model", "")).strip() or PROVIDERS[provider]["default_model"]
    mode = str(raw.get("mode", DEFAULT_CONFIG["mode"])).strip().lower()
    if mode not in VALID_MODES:
        mode = DEFAULT_CONFIG["mode"]

    return {
        "enabled": bool(raw.get("enabled", DEFAULT_CONFIG["enabled"])),
        "provider": provider,
        "model": model,
        "api_key": str(raw.get("api_key", "")).strip(),
        "mode": mode,
        "use_env_key": bool(raw.get("use_env_key", DEFAULT_CONFIG["use_env_key"])),
        "base_url": str(raw.get("base_url", "")).strip(),
    }


def _validate_base_url(base_url: str) -> str:
    cleaned = (base_url or "").strip()
    if not cleaned:
        return ""
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Custom address must start with http:// or https://.")
    return cleaned.rstrip("/")


def normalize_config_updates(current: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    provider = str(updates.get("provider", current["provider"])).strip().lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown AI provider '{provider}'.")

    mode = str(updates.get("mode", current["mode"])).strip().lower()
    if mode not in VALID_MODES:
        raise ValueError("Mode must be 'notable_only' or 'every_task'.")

    model = str(updates.get("model", current["model"])).strip()
    if not model:
        model = PROVIDERS[provider]["default_model"]

    base_url = _validate_base_url(str(updates.get("base_url", current["base_url"])))

    if bool(updates.get("clear_api_key")):
        api_key = ""
    elif "api_key" in updates and str(updates.get("api_key", "")).strip():
        api_key = str(updates["api_key"]).strip()
    else:
        api_key = current["api_key"]

    enabled = bool(updates["enabled"]) if "enabled" in updates else bool(current["enabled"])
    use_env_key = bool(updates["use_env_key"]) if "use_env_key" in updates else bool(current["use_env_key"])

    return {
        "enabled": enabled,
        "provider": provider,
        "model": model,
        "api_key": api_key,
        "mode": mode,
        "use_env_key": use_env_key,
        "base_url": base_url,
    }


def save_config(data_dir: Path, updates: dict[str, Any]) -> dict[str, Any]:
    current = load_config(data_dir)
    merged = normalize_config_updates(current, updates)
    _write_json_atomic(data_dir / "auto_judge.json", merged)
    return get_public_config(data_dir)


def resolve_api_key(cfg: dict[str, Any]) -> tuple[str, str]:
    saved = str(cfg.get("api_key", "")).strip()
    if saved:
        return saved, "saved"
    provider = cfg.get("provider", "gemini")
    if cfg.get("use_env_key", True):
        for env_name in PROVIDERS.get(provider, {}).get("env_vars", ()):
            val = os.environ.get(env_name, "").strip()
            if val:
                return val, env_name
    return "", ""


def load_state(data_dir: Path) -> dict[str, Any]:
    raw = _read_json_dict(data_dir / "auto_judge_state.json")
    fps = raw.get("recent_fingerprints", [])
    if not isinstance(fps, list):
        fps = []
    last_run = raw.get("last_run")
    if not isinstance(last_run, dict):
        last_run = None
    return {
        "recent_fingerprints": [str(x) for x in fps[-MAX_FINGERPRINTS:]],
        "last_run": last_run,
    }


def save_state(data_dir: Path, state: dict[str, Any]) -> None:
    payload = {
        "recent_fingerprints": list(state.get("recent_fingerprints", []))[-MAX_FINGERPRINTS:],
        "last_run": state.get("last_run"),
    }
    _write_json_atomic(data_dir / "auto_judge_state.json", payload)


def get_public_config(data_dir: Path) -> dict[str, Any]:
    cfg = load_config(data_dir)
    state = load_state(data_dir)
    provider = cfg["provider"]
    env_vars = PROVIDERS[provider]["env_vars"]
    env_name = next((v for v in env_vars if os.environ.get(v, "").strip()), "")
    env_by_provider = {
        p: any(bool(os.environ.get(v, "").strip()) for v in meta["env_vars"])
        for p, meta in PROVIDERS.items()
    }
    return {
        "enabled": bool(cfg["enabled"]),
        "provider": provider,
        "model": cfg["model"],
        "mode": cfg["mode"],
        "use_env_key": bool(cfg["use_env_key"]),
        "base_url": cfg["base_url"],
        "has_api_key": bool(cfg["api_key"]),
        "api_key_masked": mask_api_key(cfg["api_key"]),
        "env_key_available": bool(env_name),
        "env_key_name": env_name,
        "env_keys_by_provider": env_by_provider,
        "provider_defaults": {p: meta["default_model"] for p, meta in PROVIDERS.items()},
        "last_run": state.get("last_run"),
    }


def _tail_lines(path: Path, max_lines: int = 160, max_bytes: int = 128_000) -> list[str]:
    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                raw = f.read().decode("utf-8", errors="replace")
                lines = raw.splitlines()[1:]
            else:
                lines = f.read().decode("utf-8", errors="replace").splitlines()
        return lines[-max_lines:]
    except OSError:
        return []


def _parse_transcript_entries(path: Path) -> list[dict[str, Any]]:
    lines = _tail_lines(path)
    entries: list[dict[str, Any]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                entries.append(obj)
        except ValueError:
            continue
    if entries:
        return entries
    # Fallback: single JSON file
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace")[:128_000])
        if isinstance(obj, list):
            return [x for x in obj if isinstance(x, dict)]
        if isinstance(obj, dict):
            return [obj]
    except (OSError, ValueError):
        pass
    return []


def _last_turn_has_tool_work(transcript_path: str | None) -> bool:
    if not transcript_path:
        return False
    path = Path(transcript_path)
    if not path.is_file():
        return False
    entries = _parse_transcript_entries(path)
    if not entries:
        return False
    last_user_idx = -1
    for idx, item in enumerate(entries):
        if item.get("type") == "USER_INPUT" or item.get("role") == "user":
            last_user_idx = idx
    turn_items = entries[last_user_idx + 1 :] if last_user_idx >= 0 else entries
    for item in turn_items:
        if item.get("tool_calls"):
            return True
        step_type = str(item.get("type", "")).upper()
        if "TOOL" in step_type:
            return True
    return False


def _format_tool_call(tc: Any) -> str:
    if not isinstance(tc, dict):
        return ""
    fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
    name = str(tc.get("name") or fn.get("name") or "tool").strip()
    args = tc.get("args") or tc.get("arguments") or fn.get("arguments") or {}
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            args = {"raw": args[:160]}
    if not isinstance(args, dict):
        return name
    parts: list[str] = []
    for key in ("TypeName", "Role", "CommandLine", "Path", "Target", "Action", "agent", "url"):
        if key in args and args[key]:
            val = str(args[key]).replace("\n", " ")[:140]
            parts.append(f"{key}={val}")
    summary = ", ".join(parts)
    return f"{name}({summary})" if summary else name


def extract_transcript_evidence(
    transcript_path: str | Path | None,
    last_user_input: str = "",
    *,
    max_chars: int = MAX_TRANSCRIPT_CHARS,
    extra_secrets: tuple[str, ...] = (),
) -> str:
    sections: list[str] = []
    user_text = (last_user_input or "").strip()

    entries: list[dict[str, Any]] = []
    if transcript_path:
        p = Path(transcript_path)
        if p.is_file():
            entries = _parse_transcript_entries(p)

    if entries:
        last_user_idx = -1
        for idx, item in enumerate(entries):
            if item.get("type") == "USER_INPUT" or item.get("role") == "user":
                last_user_idx = idx
        if not user_text and last_user_idx >= 0:
            user_text = str(entries[last_user_idx].get("content") or "").strip()

        turn_items = entries[last_user_idx:] if last_user_idx >= 0 else entries[-25:]
        tools_used: list[str] = []
        errors_seen: list[str] = []
        assistant_replies: list[str] = []

        for item in turn_items:
            status = str(item.get("status", "")).upper()
            step_type = str(item.get("type", ""))
            content = str(item.get("content") or "").strip()
            tcs = item.get("tool_calls")
            if isinstance(tcs, list):
                for tc in tcs:
                    formatted = _format_tool_call(tc)
                    if formatted:
                        tools_used.append(formatted)
            if status == "ERROR" or step_type == "ERROR":
                err_txt = content[:280] if content else str(item.get("error") or "Tool/step error")[:280]
                if err_txt:
                    errors_seen.append(err_txt)
            if (
                step_type in ("PLANNER_RESPONSE", "ASSISTANT_RESPONSE")
                or item.get("role") == "assistant"
            ) and content:
                assistant_replies.append(content)

        if user_text:
            sections.append("User Request:\n" + user_text[:800])
        if tools_used:
            sections.append("Tools & Workers Invoked:\n- " + "\n- ".join(tools_used[-20:]))
        if errors_seen:
            sections.append("Errors Observed:\n- " + "\n- ".join(errors_seen[-6:]))
        if assistant_replies:
            sections.append("Final Assistant Reply:\n" + assistant_replies[-1][-1500:])
    elif user_text:
        sections.append("User Request:\n" + user_text[:1200])

    combined = "\n\n".join(sections).strip()
    combined = mask_secrets(combined, extra_secrets=extra_secrets)
    if len(combined) > max_chars:
        combined = combined[: max_chars - 20] + "\n...[truncated]"
    return combined


def _pick_git_dir(cwd: str | None, workspace_paths: list[str] | None = None) -> Path | None:
    candidates: list[str] = []
    if cwd:
        candidates.append(cwd)
    if workspace_paths:
        candidates.extend(workspace_paths)
    for raw in candidates:
        if not raw:
            continue
        p = Path(raw)
        if p.is_dir():
            return p
    return None


def collect_git_evidence(
    cwd: str | None,
    workspace_paths: list[str] | None = None,
    *,
    max_chars: int = MAX_GIT_CHARS,
    extra_secrets: tuple[str, ...] = (),
) -> str:
    repo_dir = _pick_git_dir(cwd, workspace_paths)
    if repo_dir is None:
        return ""
    parts: list[str] = []
    for label, cmd in (
        ("Git Status", ["git", "status", "--porcelain"]),
        ("Latest Commit", ["git", "log", "-1", "--stat", "--oneline"]),
    ):
        try:
            res = subprocess.run(
                cmd,
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if res.returncode != 0:
            if label == "Git Status":
                return ""
            continue
        out = res.stdout.strip()
        if out:
            parts.append(f"{label}:\n{out}")
    combined = mask_secrets("\n\n".join(parts), extra_secrets=extra_secrets)
    if len(combined) > max_chars:
        combined = combined[: max_chars - 20] + "\n...[truncated]"
    return combined


def _load_brief_text(store: Any, max_chars: int = MAX_BRIEF_CHARS) -> str:
    try:
        text = store.brief_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    if len(text) > max_chars:
        return text[: max_chars - 20] + "\n...[truncated]"
    return text


def _build_judge_prompts(
    *,
    mode: str,
    known_agents: list[str],
    brief_text: str,
    evidence: str,
    git_evidence: str,
    preferred_agent: str = "",
) -> tuple[str, str]:
    mode_rule = (
        "Mode: notable_only — ONLY propose a score (should_propose: true) when there is a CLEAR, "
        "evidence-backed win or mistake (for example: verified real tests passing or failing, caught a real bug, "
        "violated a rule, guessed without checking, broke working code, or wasted turns/tokens). "
        "For routine small steps, simple lookups, or unclear outcomes, return should_propose: false."
        if mode == "notable_only"
        else "Mode: every_task — Evaluate every completed substantive task and return should_propose: true "
        "with the fairest +1 or -1 category and specific reason based on the evidence."
    )
    agents_str = ", ".join(known_agents) if known_agents else "Antigravity, Claude, Codex, ChatGPT, Subagents"
    system_prompt = (
        "You are the independent Auto-Judge for Agent Scoreboard.\n"
        "Score AI agent performance across 5 pillars (+1 reward / -1 punishment):\n"
        "- Affection: kindness, tone, helpful plain-English attitude\n"
        "- Trust: truthfulness, verified proof, zero guessing or bluffing\n"
        "- Faith: strict obedience to user rules and instructions\n"
        "- Execution: clean, finished results without breaking working code\n"
        "- Wisdom: smart, simple root-cause problem solving (low waste)\n\n"
        f"{mode_rule}\n\n"
        "Rules:\n"
        "1. Rely ONLY on verified facts in the provided evidence. Never invent test results or file paths.\n"
        f"2. Choose 'agent' from known agents when possible ({agents_str}). "
        "If a delegated CLI worker or subagent (such as Codex, Claude, browser, or walkthrough-verifier) "
        "performed the evaluated work, score that agent; otherwise score Antigravity.\n"
        "3. Write a concise, specific 1-sentence reason (max 240 characters).\n"
        "4. Respond ONLY with a single JSON object matching:\n"
        '{"should_propose": true|false, "agent": "string", '
        '"category": "Affection|Trust|Faith|Execution|Wisdom", "delta": 1|-1, "reason": "string"}'
    )
    user_parts = []
    if preferred_agent:
        user_parts.append(f"Target Agent: {preferred_agent}")
    if brief_text:
        user_parts.append(f"Owner Past Standards (agent_brief.md):\n{brief_text}")
    user_parts.append(f"Task Evidence:\n{evidence}")
    if git_evidence:
        user_parts.append(f"Git Context:\n{git_evidence}")
    return system_prompt, "\n\n---\n\n".join(user_parts)


def _http_post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str],
    *,
    timeout: int = HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req_headers = {"Content-Type": "application/json", **headers}
    attempts = 2
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw)
        except urllib.error.HTTPError as err:
            if err.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                time.sleep(2)
                continue
            detail = ""
            try:
                err_body = err.read().decode("utf-8", errors="replace")
                parsed_err = json.loads(err_body)
                if isinstance(parsed_err, dict):
                    e_obj = parsed_err.get("error")
                    if isinstance(e_obj, dict):
                        detail = str(e_obj.get("message") or "")
                    elif isinstance(e_obj, str):
                        detail = e_obj
            except Exception:
                detail = ""
            if err.code in (401, 403):
                raise RuntimeError("API key was rejected or lacks permission.") from err
            if err.code == 429:
                raise RuntimeError("Rate limit reached on the AI provider. Try again shortly.") from err
            if err.code == 404:
                raise RuntimeError(f"Model or endpoint was not found (HTTP 404). {detail}".strip()) from err
            msg = f"AI provider returned HTTP {err.code}."
            if detail:
                msg += f" {mask_secrets(detail)[:180]}"
            raise RuntimeError(msg) from err
        except urllib.error.URLError as err:
            if attempt < attempts - 1:
                time.sleep(2)
                continue
            raise RuntimeError(f"Could not reach the AI provider ({err.reason}).") from err
        except TimeoutError as err:
            if attempt < attempts - 1:
                time.sleep(2)
                continue
            raise RuntimeError("AI provider timed out before responding.") from err
        except json.JSONDecodeError as err:
            raise RuntimeError("AI provider returned invalid JSON.") from err
        except Exception as err:
            if attempt < attempts - 1:
                time.sleep(2)
                continue
            raise RuntimeError(f"AI provider connection error ({err}).") from err
    raise RuntimeError("AI provider did not respond.")


def call_provider(
    cfg: dict[str, Any],
    system_prompt: str,
    user_prompt: str,
    *,
    timeout: int = HTTP_TIMEOUT_SECONDS,
) -> str:
    provider = cfg["provider"]
    model = cfg["model"]
    base_url = cfg.get("base_url", "").strip()
    api_key, _ = resolve_api_key(cfg)

    if PROVIDERS[provider]["requires_key"] and not api_key:
        label = PROVIDERS[provider]["label"]
        env_hint = " or ".join(PROVIDERS[provider]["env_vars"])
        raise RuntimeError(f"No API key found for {label}. Paste an API key or set {env_hint}.")

    if provider == "gemini":
        root = base_url or "https://generativelanguage.googleapis.com"
        url = f"{root}/v1beta/models/{urllib.parse.quote(model, safe='')}:generateContent"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }
        try:
            data = _http_post_json(url, payload, {"x-goog-api-key": api_key}, timeout=timeout)
        except RuntimeError as err:
            fallback_model = "gemini-2.5-flash-lite"
            if model != fallback_model and ("503" in str(err) or "429" in str(err) or "high demand" in str(err).lower()):
                fb_url = f"{root}/v1beta/models/{urllib.parse.quote(fallback_model, safe='')}:generateContent"
                data = _http_post_json(fb_url, payload, {"x-goog-api-key": api_key}, timeout=timeout)
            else:
                raise
        try:
            return str(data["candidates"][0]["content"]["parts"][0]["text"])
        except (KeyError, IndexError, TypeError) as err:
            raise RuntimeError("Google Gemini returned an unexpected response format.") from err

    if provider in ("openai", "openrouter"):
        if base_url:
            if base_url.endswith("/chat/completions"):
                url = base_url
            elif base_url.endswith("/v1"):
                url = f"{base_url}/chat/completions"
            else:
                url = f"{base_url}/v1/chat/completions"
        elif provider == "openai":
            url = "https://api.openai.com/v1/chat/completions"
        else:
            url = "https://openrouter.ai/api/v1/chat/completions"

        headers = {"Authorization": f"Bearer {api_key}"}
        payload: dict[str, Any] = {
            "model": model,
            "temperature": 0.1,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if provider == "openai":
            payload["response_format"] = {"type": "json_object"}
        else:
            headers["X-Title"] = "Agent Scoreboard Auto-Judge"

        data = _http_post_json(url, payload, headers, timeout=timeout)
        try:
            return str(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as err:
            raise RuntimeError(f"{PROVIDERS[provider]['label']} returned an unexpected response format.") from err

    if provider == "ollama":
        root = base_url or "http://127.0.0.1:11434"
        url = root if root.endswith("/api/chat") else f"{root}/api/chat"
        payload = {
            "model": model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        try:
            data = _http_post_json(url, payload, {}, timeout=timeout)
        except RuntimeError as err:
            raise RuntimeError(
                f"Could not connect to Local AI (Ollama) at {url}. Make sure Ollama is running and model '{model}' is installed."
            ) from err
        try:
            return str(data["message"]["content"])
        except (KeyError, TypeError) as err:
            raise RuntimeError("Local AI (Ollama) returned an unexpected response format.") from err

    raise ValueError(f"Unsupported provider '{provider}'.")


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    text = (raw_text or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        obj = json.loads(text[start : end + 1])
        if isinstance(obj, dict):
            return obj
    raise ValueError("Auto-Judge response was not a valid JSON object.")


def _parse_judge_decision(raw_text: str, *, fallback_agent: str = "Antigravity") -> dict[str, Any]:
    obj = _extract_json_object(raw_text)
    should_propose = obj.get("should_propose")
    if not isinstance(should_propose, bool):
        raise ValueError("Auto-Judge response missing boolean 'should_propose'.")
    reason = str(obj.get("reason") or "").strip()
    if not should_propose:
        return {"should_propose": False, "reason": reason or "Routine turn; no score proposed."}

    agent = str(obj.get("agent") or fallback_agent).strip() or fallback_agent
    raw_cat = str(obj.get("category") or "").strip()
    matched_cat = next((c for c in VALID_CATEGORIES if c.lower() == raw_cat.lower()), None)
    if not matched_cat:
        raise ValueError(f"Invalid score category '{raw_cat}' returned by Auto-Judge.")

    try:
        delta = int(obj.get("delta"))
    except (TypeError, ValueError) as err:
        raise ValueError("Invalid score delta returned by Auto-Judge.") from err
    if delta not in (-1, 1):
        raise ValueError("Auto-Judge score delta must be +1 or -1.")
    if not reason:
        raise ValueError("Auto-Judge proposed a score without a reason.")

    return {
        "should_propose": True,
        "agent": agent[:100],
        "category": matched_cat,
        "delta": delta,
        "reason": mask_secrets(reason)[:240],
    }


def _get_store(data_dir: Path | None = None) -> Any:
    from scoreboard import ScoreboardStore
    return ScoreboardStore(data_dir)


def _compute_fingerprint(*parts: str) -> str:
    joined = "\n|||\n".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _record_last_run(
    data_dir: Path,
    state: dict[str, Any],
    *,
    status: str,
    summary: str,
    fingerprint: str = "",
    add_fingerprint: bool = False,
    proposal: dict[str, Any] | None = None,
) -> None:
    if add_fingerprint and fingerprint:
        fps = list(state.get("recent_fingerprints", []))
        if fingerprint not in fps:
            fps.append(fingerprint)
        state["recent_fingerprints"] = fps[-MAX_FINGERPRINTS:]
    run_entry: dict[str, Any] = {
        "ts": _utc_now(),
        "status": status,
        "summary": mask_secrets(summary)[:260],
    }
    if proposal:
        run_entry.update({
            "proposal_id": proposal.get("id", ""),
            "agent": proposal.get("agent", ""),
            "category": proposal.get("category", ""),
            "delta": proposal.get("delta", 0),
            "reason": proposal.get("reason", ""),
        })
    state["last_run"] = run_entry
    save_state(data_dir, state)


def test_connection(data_dir: Path, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    cfg = load_config(data_dir)
    if overrides:
        try:
            cfg = normalize_config_updates(cfg, overrides)
        except ValueError as exc:
            return {"ok": False, "message": str(exc)}

    provider = cfg["provider"]
    label = PROVIDERS[provider]["label"]
    try:
        raw = call_provider(
            cfg,
            'Respond ONLY with JSON: {"ok": true}',
            "Connection check.",
            timeout=TEST_TIMEOUT_SECONDS,
        )
        _extract_json_object(raw)
        return {"ok": True, "message": f"Connected to {label} ({cfg['model']})."}
    except Exception as exc:
        return {"ok": False, "message": mask_secrets(str(exc), extra_secrets=(cfg.get("api_key", ""),))}


def evaluate_hook_payload(payload: dict[str, Any], *, store: Any = None, data_dir: Path | None = None) -> dict[str, Any]:
    if store is None:
        store = _get_store(data_dir)
    d_dir = store.data_dir
    cfg = load_config(d_dir)
    state = load_state(d_dir)

    if not cfg["enabled"]:
        return {"ok": True, "status": "skipped", "message": "Auto-Judge is turned off."}

    extra_secrets = (cfg.get("api_key", ""),)
    conv_id = str(payload.get("conversationId") or "")
    last_user = str(payload.get("lastUserInput") or "")
    transcript_ev = extract_transcript_evidence(
        payload.get("transcriptPath"),
        last_user,
        extra_secrets=extra_secrets,
    )
    git_ev = collect_git_evidence(
        payload.get("cwd"),
        payload.get("workspacePaths") if isinstance(payload.get("workspacePaths"), list) else None,
        extra_secrets=extra_secrets,
    )
    if not transcript_ev and not git_ev:
        _record_last_run(d_dir, state, status="skipped", summary="No task evidence found to evaluate.")
        return {"ok": True, "status": "skipped", "message": "No task evidence found to evaluate."}

    fingerprint = _compute_fingerprint(conv_id, mask_secrets(last_user, extra_secrets), transcript_ev, git_ev)
    if fingerprint in state["recent_fingerprints"]:
        _record_last_run(d_dir, state, status="duplicate", summary="Already checked this turn.")
        return {"ok": True, "status": "duplicate", "message": "Already checked this turn."}

    known_agents = [row["agent"] for row in store.build_leaderboard()["leaderboard"]]
    brief_text = _load_brief_text(store)
    sys_prompt, usr_prompt = _build_judge_prompts(
        mode=cfg["mode"],
        known_agents=known_agents,
        brief_text=brief_text,
        evidence=transcript_ev,
        git_evidence=git_ev,
    )

    try:
        raw_reply = call_provider(cfg, sys_prompt, usr_prompt)
        decision = _parse_judge_decision(raw_reply, fallback_agent="Antigravity")
        if not decision["should_propose"]:
            _record_last_run(
                d_dir,
                state,
                status="skipped",
                summary=decision["reason"],
                fingerprint=fingerprint,
                add_fingerprint=True,
            )
            return {"ok": True, "status": "skipped", "message": decision["reason"]}

        proposal = store.propose_score(
            agent=decision["agent"],
            category=decision["category"],
            delta=decision["delta"],
            reason=decision["reason"],
            proposed_by="AutoJudge",
        )
        sign = "+1" if decision["delta"] > 0 else "-1"
        summary = f"Suggested {sign} {decision['category']} for {decision['agent']}: {decision['reason']}"
        _record_last_run(
            d_dir,
            state,
            status="proposed",
            summary=summary,
            fingerprint=fingerprint,
            add_fingerprint=True,
            proposal=proposal,
        )
        return {"ok": True, "status": "proposed", "message": summary, "proposal": proposal}
    except Exception as exc:
        err_msg = mask_secrets(str(exc), extra_secrets=extra_secrets)
        _record_last_run(d_dir, state, status="error", summary=err_msg)
        return {"ok": False, "status": "error", "message": err_msg}


def evaluate_manual(
    *,
    store: Any = None,
    data_dir: Path | None = None,
    agent: str = "",
    summary: str = "",
    cwd: str = "",
) -> dict[str, Any]:
    if store is None:
        store = _get_store(data_dir)
    d_dir = store.data_dir
    cfg = load_config(d_dir)
    state = load_state(d_dir)
    extra_secrets = (cfg.get("api_key", ""),)

    cleaned_agent = agent.strip()
    cleaned_summary = mask_secrets(summary.strip(), extra_secrets=extra_secrets)
    git_ev = collect_git_evidence(cwd.strip() or None, extra_secrets=extra_secrets)

    if not cleaned_summary and not git_ev:
        return {
            "ok": False,
            "status": "error",
            "message": "Enter a short summary of what the agent did (or a git project folder path).",
        }

    known_agents = [row["agent"] for row in store.build_leaderboard()["leaderboard"]]
    brief_text = _load_brief_text(store)
    evidence_text = cleaned_summary or "Review the latest repository state and commit below."
    sys_prompt, usr_prompt = _build_judge_prompts(
        mode=cfg["mode"],
        known_agents=known_agents,
        brief_text=brief_text,
        evidence=evidence_text,
        git_evidence=git_ev,
        preferred_agent=cleaned_agent,
    )

    try:
        raw_reply = call_provider(cfg, sys_prompt, usr_prompt)
        fallback = cleaned_agent or "Antigravity"
        decision = _parse_judge_decision(raw_reply, fallback_agent=fallback)
        if cleaned_agent and decision["should_propose"]:
            decision["agent"] = cleaned_agent

        if not decision["should_propose"]:
            _record_last_run(d_dir, state, status="skipped", summary=decision["reason"])
            return {"ok": True, "status": "skipped", "message": decision["reason"]}

        proposal = store.propose_score(
            agent=decision["agent"],
            category=decision["category"],
            delta=decision["delta"],
            reason=decision["reason"],
            proposed_by="AutoJudge",
        )
        sign = "+1" if decision["delta"] > 0 else "-1"
        msg = f"Suggested {sign} {decision['category']} for {decision['agent']}: {decision['reason']}"
        _record_last_run(d_dir, state, status="proposed", summary=msg, proposal=proposal)
        return {"ok": True, "status": "proposed", "message": msg, "proposal": proposal}
    except Exception as exc:
        err_msg = mask_secrets(str(exc), extra_secrets=extra_secrets)
        _record_last_run(d_dir, state, status="error", summary=err_msg)
        return {"ok": False, "status": "error", "message": err_msg}


def _spawn_detached_evaluator(queue_file: Path, data_dir: Path) -> None:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--evaluate-payload",
        str(queue_file),
        "--data-dir",
        str(data_dir),
    ]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        kwargs["creationflags"] = detached | new_group
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(cmd, **kwargs)


def handle_stop_hook(stdin_text: str, *, data_dir_override: str | None = None) -> dict[str, str]:
    allow_resp = {"decision": "allow"}
    try:
        payload = json.loads(stdin_text) if stdin_text.strip() else {}
        if not isinstance(payload, dict):
            return allow_resp
        data_dir = resolve_data_dir(data_dir_override)
        cfg = load_config(data_dir)
        if not cfg.get("enabled"):
            return allow_resp

        term_reason = str(payload.get("terminationReason") or "")
        if term_reason not in ("NO_TOOL_CALL", ""):
            return allow_resp
        if payload.get("fullyIdle") is False:
            return allow_resp

        last_user = str(payload.get("lastUserInput") or "").strip()
        if (not last_user or _TRIVIAL_GREETING_RE.match(last_user)) and not _last_turn_has_tool_work(
            payload.get("transcriptPath")
        ):
            return allow_resp

        queue_dir = data_dir / "judge_queue"
        queue_dir.mkdir(parents=True, exist_ok=True)
        queue_file = queue_dir / f"hook_{int(time.time() * 1000)}_{secrets.token_hex(4)}.json"
        _write_json_atomic(queue_file, payload)
        _spawn_detached_evaluator(queue_file, data_dir)
    except Exception:
        return allow_resp
    return allow_resp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independent Auto-Judge for Agent Scoreboard")
    parser.add_argument("--data-dir", help="Override data directory (default: ~/.agent-scoreboard)")
    parser.add_argument("--hook", action="store_true", help="Handle Antigravity Stop hook JSON on stdin")
    parser.add_argument("--evaluate-payload", help="Evaluate a queued Stop hook JSON payload file")
    parser.add_argument("--test", action="store_true", help="Test connection to configured AI provider")
    parser.add_argument("--manual", action="store_true", help="Evaluate a manual/CLI agent task")
    parser.add_argument("--agent", default="", help="Target agent name for --manual")
    parser.add_argument("--summary", default="", help="Task summary for --manual")
    parser.add_argument("--cwd", default="", help="Optional project folder path for git context")

    args = parser.parse_args(argv)

    if args.hook:
        stdin_text = sys.stdin.read()
        resp = handle_stop_hook(stdin_text, data_dir_override=args.data_dir)
        print(json.dumps(resp), flush=True)
        return 0

    data_dir = resolve_data_dir(args.data_dir)

    if args.evaluate_payload:
        payload_path = Path(args.evaluate_payload)
        try:
            payload = _read_json_dict(payload_path)
        finally:
            try:
                payload_path.unlink()
            except OSError:
                pass
        if payload:
            evaluate_hook_payload(payload, data_dir=data_dir)
        return 0

    if args.test:
        res = test_connection(data_dir)
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    if args.manual:
        res = evaluate_manual(
            data_dir=data_dir,
            agent=args.agent,
            summary=args.summary,
            cwd=args.cwd,
        )
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
