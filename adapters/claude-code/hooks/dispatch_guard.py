#!/usr/bin/env python3
"""Claude Code PreToolUse(Agent) hook: guards against recursive nesting and unbudgeted models."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from _common import load_config  # noqa: E402


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    if payload.get("tool_name") not in ("Agent", "Task"):
        return 0

    cwd = payload.get("cwd") or "."
    cfg = load_config(cwd)
    dcfg = cfg.get("delegation", {})

    # 1. Prevent nested subagent fan-out when already running inside a subagent
    if dcfg.get("block_nested_subagents", True) and payload.get("agent_id"):
        print(
            "context-slim blocked nested subagent dispatch inside an active subagent (`agent_id` present). "
            "Execute directly with tools/scripts and return structured findings to the parent.",
            file=sys.stderr,
        )
        return 2

    # 2. Require explicit model on typed fresh subagents so lookups don't silently burn top-tier model tokens
    tool_input = payload.get("tool_input") or {}
    sub_type = str(tool_input.get("subagent_type") or "").strip()
    model = str(tool_input.get("model") or "").strip()

    if (
        dcfg.get("require_model_on_scoped_subagents", True)
        and sub_type
        and sub_type.lower() != "fork"
        and not model
    ):
        print(
            f"context-slim: subagent_type='{sub_type}' omitted `model`. "
            "Specify an explicit `model` (prefer `haiku`/`sonnet` for scoped lookups; use `opus` only when deep reasoning is required), "
            "or use fork mode only when full parent history is strictly needed.",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
