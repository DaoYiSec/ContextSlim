#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
TARGETS="agents"
PROJECT_DIR=""
INSTALL_CLI=1
INSTALL_CLAUDE_HOOKS=0
UNINSTALL_CLAUDE_HOOKS=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Install context-slim skill across AI coding agents.

Usage:
  ./install.sh [options]

Options:
  --target LIST             Comma-separated targets: agents,claude,codex,cursor,gemini,antigravity,opencode,all (default: agents)
  --project [DIR]           Install into project-local .agents/skills/context-slim (default DIR: current directory)
  --no-cli                  Skip symlinking `cslim` to ~/.local/bin/cslim
  --with-claude-hooks       Merge/update optional PreToolUse/UserPromptSubmit hooks in ~/.claude/settings.json (creates .bak)
  --uninstall-claude-hooks  Remove context-slim hooks from ~/.claude/settings.json (creates .bak)
  --dry-run                 Print actions without modifying files
  -h, --help                Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) TARGETS="${2:-}"; shift 2 ;;
    --project)
      if [[ $# -gt 1 && "${2:0:1}" != "-" ]]; then
        PROJECT_DIR="$2"; shift 2
      else
        PROJECT_DIR="$(pwd)"; shift
      fi
      ;;
    --no-cli) INSTALL_CLI=0; shift ;;
    --with-claude-hooks) INSTALL_CLAUDE_HOOKS=1; shift ;;
    --uninstall-claude-hooks) UNINSTALL_CLAUDE_HOOKS=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

run_cmd() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

link_skill() {
  local dest="$1"
  local parent
  parent="$(dirname "$dest")"
  run_cmd mkdir -p "$parent"
  if [[ -L "$dest" || -d "$dest" ]]; then
    if [[ "$dest" == "$REPO_DIR" ]]; then
      echo "Already installed at $dest"
      return 0
    fi
    run_cmd rm -rf "$dest"
  fi
  run_cmd ln -s "$REPO_DIR" "$dest"
  echo "Linked skill -> $dest"
}

run_cmd chmod +x "$REPO_DIR/bin/cslim" "$REPO_DIR/scripts/"*.py "$REPO_DIR/adapters/claude-code/hooks/"*.py

if [[ "$UNINSTALL_CLAUDE_HOOKS" -eq 0 ]]; then
  if [[ -n "$PROJECT_DIR" ]]; then
    link_skill "${PROJECT_DIR%/}/.agents/skills/context-slim"
  else
    IFS=',' read -r -a target_arr <<< "$TARGETS"
    for raw_t in "${target_arr[@]}"; do
      t="${raw_t//[[:space:]]/}"
      [[ -z "$t" ]] && continue
      case "$t" in
        agents)      link_skill "$HOME/.agents/skills/context-slim" ;;
        claude)      link_skill "$HOME/.claude/skills/context-slim" ;;
        codex)       link_skill "$HOME/.codex/skills/context-slim" ;;
        cursor)      link_skill "$HOME/.cursor/skills/context-slim" ;;
        gemini)      link_skill "$HOME/.gemini/skills/context-slim" ;;
        antigravity) link_skill "$HOME/.gemini/antigravity/skills/context-slim" ;;
        opencode)    link_skill "$HOME/.config/opencode/skills/context-slim" ;;
        all)
          link_skill "$HOME/.agents/skills/context-slim"
          link_skill "$HOME/.claude/skills/context-slim"
          link_skill "$HOME/.codex/skills/context-slim"
          link_skill "$HOME/.cursor/skills/context-slim"
          link_skill "$HOME/.gemini/skills/context-slim"
          link_skill "$HOME/.gemini/antigravity/skills/context-slim"
          link_skill "$HOME/.config/opencode/skills/context-slim"
          ;;
        *) echo "Unknown target: $t" >&2; exit 1 ;;
      esac
    done
  fi

  if [[ "$INSTALL_CLI" -eq 1 ]]; then
    run_cmd mkdir -p "$HOME/.local/bin"
    run_cmd ln -sf "$REPO_DIR/bin/cslim" "$HOME/.local/bin/cslim"
    echo "Linked CLI -> $HOME/.local/bin/cslim (ensure ~/.local/bin is in PATH)"
  fi
fi

if [[ "$INSTALL_CLAUDE_HOOKS" -eq 1 || "$UNINSTALL_CLAUDE_HOOKS" -eq 1 ]]; then
  action_mode="merge"
  if [[ "$UNINSTALL_CLAUDE_HOOKS" -eq 1 ]]; then
    action_mode="remove"
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] Would $action_mode Claude Code hooks in $HOME/.claude/settings.json"
  else
    python3 - "$REPO_DIR" "$HOME/.claude/settings.json" "$action_mode" <<'PY'
import json
import shutil
import sys
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
settings_path = Path(sys.argv[2])
mode = sys.argv[3]

if mode == "remove" and not settings_path.is_file():
    print(f"No {settings_path} found; nothing to remove.")
    raise SystemExit(0)

data = {}
if settings_path.is_file():
    raw_text = settings_path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw_text or "{}")
    except json.JSONDecodeError as exc:
        print(f"Error: {settings_path} contains invalid JSON ({exc}); aborting without modification.", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(data, dict):
        print(f"Error: {settings_path} root must be a JSON object.", file=sys.stderr)
        raise SystemExit(1)
    shutil.copy2(settings_path, settings_path.with_suffix(".json.bak"))

hook_names = ("context_monitor.py", "bash_guard.py", "read_guard.py", "dispatch_guard.py")

def is_cslim_cmd(cmd: str) -> bool:
    return any(f"adapters/claude-code/hooks/{name}" in cmd for name in hook_names)

existing = data.setdefault("hooks", {})
if isinstance(existing, dict):
    for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "PreCompact"):
        entries = existing.get(event)
        if not isinstance(entries, list):
            continue
        cleaned_entries = []
        for entry in entries:
            if not isinstance(entry, dict):
                cleaned_entries.append(entry)
                continue
            hooks_list = entry.get("hooks")
            if isinstance(hooks_list, list):
                kept = [
                    h for h in hooks_list
                    if not (isinstance(h, dict) and is_cslim_cmd(str(h.get("command") or "")))
                ]
                if kept:
                    new_entry = dict(entry)
                    new_entry["hooks"] = kept
                    cleaned_entries.append(new_entry)
            else:
                cleaned_entries.append(entry)
        if cleaned_entries:
            existing[event] = cleaned_entries
        else:
            existing.pop(event, None)

if mode == "merge":
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    hooks_dir = repo / "adapters" / "claude-code" / "hooks"
    new_hooks = {
        "UserPromptSubmit": [
            {"hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "context_monitor.py"}"'}]}
        ],
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "bash_guard.py"}"'}]},
            {"matcher": "Read", "hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "read_guard.py"}"'}]},
            {"matcher": "Agent", "hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "dispatch_guard.py"}"'}]},
        ],
        "PostToolUse": [
            {"matcher": ".*", "hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "context_monitor.py"}"'}]}
        ],
        "PreCompact": [
            {"hooks": [{"type": "command", "command": f'python3 "{hooks_dir / "context_monitor.py"}"'}]}
        ],
    }
    for event, new_entries in new_hooks.items():
        existing.setdefault(event, []).extend(new_entries)
elif not existing:
    data.pop("hooks", None)

settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"Updated Claude Code hooks ({mode}) in {settings_path} (backup saved if existed)")
PY
  fi
fi
