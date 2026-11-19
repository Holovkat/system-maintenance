#!/usr/bin/env python3
"""Small registry-backed entry point; usable from any working directory."""
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def registry(root=ROOT):
    data = json.loads((root / "commands.json").read_text())
    names = set()
    for command in data["commands"]:
        name = command["name"]
        if name in names:
            raise ValueError(f"Duplicate command: {name}")
        names.add(name)
        for key in ("skill", "entry"):
            if key not in command:
                continue
            target = (root / command[key]).resolve()
            if not target.is_relative_to(root.resolve()) or not target.is_file():
                raise ValueError(f"Missing or external command {key}: {name}")
    return data


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    data = registry()
    name = args.pop(0) if args else "help"
    if name in ("help", "--help", "-h"):
        print("| Command | Purpose |\n|---|---|")
        for row in data["commands"]:
            print(f"| `{data['namespace']}:{row['name']}` | {row['summary']} |")
        print("\nDiscovery: storage (or recover) → native collection → System 1 → final handoff report. The agent only analyses and presents that report.")
        print("Approved cleanup: session plan → explicit owner approval → run → verify/report. Discovery never cleans. Explicit legacy raw modes remain available; they are not a fallback around a failed decision gate.")
        return 0
    row = next((r for r in data["commands"] if r["name"] == name), None)
    if row is None or "entry" not in row:
        raise SystemExit(f"Unknown tool: {name}. Use system-maintenance:help.")
    entry = ROOT / row["entry"]
    if name == "storage":
        # Preserve explicit legacy modes; plain storage is now the automatic
        # collector → System 1 → report entry, including --goal/--sections.
        legacy = args
        if args[:1] == ["--state-dir"]:
            legacy = args[2:]
        elif args and args[0].startswith("--state-dir="):
            legacy = args[1:]
        if legacy and legacy[0] in {"audit", "report", "plan", "clean"}:
            entry = ROOT / "scripts/storage.py"
    return subprocess.run([sys.executable, str(entry), *args], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
