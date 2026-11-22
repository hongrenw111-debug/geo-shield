"""Unified validation runner: ruff -> boundary check -> pytest."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _run(step: str, cmd: list[str]) -> int:
    print(f"\n==> [{step}] {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=ROOT)
    if proc.returncode != 0:
        print(f"==> [{step}] FAILED (exit={proc.returncode})")
    else:
        print(f"==> [{step}] PASSED")
    return proc.returncode


def main() -> int:
    steps = [
        ("ruff", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]),
        ("boundaries", [sys.executable, "scripts/check_boundaries.py"]),
        ("pytest", [sys.executable, "-m", "pytest", "-v"]),
    ]
    for name, cmd in steps:
        code = _run(name, cmd)
        if code != 0:
            return code
    print("\nAll validation checks PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
