"""AST-based module boundary and dependency DAG checker for GeoShield."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = ROOT / "src" / "geo_shield"
TESTS_ROOT = ROOT / "tests"

ALLOWED_DEPS: dict[str, set[str]] = {
    "sanitize": set(),
    "geo_score": set(),
    "retrieval": set(),
    "verify": {"sanitize", "geo_score", "retrieval"},
    "mcp_server": {"verify", "sanitize", "geo_score"},
    "web": {"verify", "sanitize", "geo_score"},
    "cli": {"verify", "sanitize", "geo_score", "retrieval", "mcp_server", "web"},
}


def _owner_module(path: Path) -> str | None:
    """Return top-level geo_shield submodule name for a source file, or None for tests/root."""
    try:
        rel = path.relative_to(SRC_ROOT)
    except ValueError:
        return None
    parts = rel.parts
    if not parts or parts[0] == "__init__.py":
        return None
    name = parts[0]
    return name[:-3] if name.endswith(".py") else name


def _resolve_relative_import(file_path: Path, module: str | None, level: int) -> str | None:
    """Resolve a relative import inside src/geo_shield to an absolute dotted module path."""
    if level <= 0:
        return module
    try:
        rel = file_path.relative_to(SRC_ROOT)
    except ValueError:
        return None
    package_parts = ["geo_shield", *rel.parts[:-1]]
    up = level - 1
    if up > len(package_parts):
        return None
    base_parts = package_parts[: len(package_parts) - up]
    if module:
        return ".".join([*base_parts, *module.split(".")])
    return ".".join(base_parts)


def _check_target(
    violations: list[str],
    file_path: Path,
    lineno: int,
    owner: str | None,
    dotted_target: str,
) -> None:
    if not dotted_target.startswith("geo_shield"):
        return
    parts = dotted_target.split(".")
    if len(parts) == 1:
        return
    target_mod = parts[1]

    # Rule A: disallow importing any other module's _internal (including from tests)
    if "_internal" in parts[2:]:
        if owner is None or owner != target_mod:
            violations.append(
                f"{file_path.relative_to(ROOT)}:{lineno}: forbidden private import '{dotted_target}' "
                f"(owner={owner or 'tests'})"
            )
            return

    # Rule B: enforce acyclic dependency DAG among src/geo_shield modules
    if owner is not None and target_mod != owner and target_mod in ALLOWED_DEPS:
        allowed = ALLOWED_DEPS.get(owner, set())
        if target_mod not in allowed:
            violations.append(
                f"{file_path.relative_to(ROOT)}:{lineno}: forbidden dependency "
                f"'{owner}' -> '{target_mod}' (allowed: {sorted(allowed)})"
            )


def check_file(file_path: Path) -> list[str]:
    source = file_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(file_path))
    owner = _owner_module(file_path)
    violations: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _check_target(violations, file_path, node.lineno, owner, alias.name)
        elif isinstance(node, ast.ImportFrom):
            resolved = _resolve_relative_import(file_path, node.module, node.level)
            if not resolved:
                continue
            _check_target(violations, file_path, node.lineno, owner, resolved)
            for alias in node.names:
                if alias.name != "*":
                    _check_target(
                        violations,
                        file_path,
                        node.lineno,
                        owner,
                        f"{resolved}.{alias.name}",
                    )
    return violations


def main() -> int:
    files: list[Path] = []
    if SRC_ROOT.exists():
        files.extend(sorted(SRC_ROOT.rglob("*.py")))
    if TESTS_ROOT.exists():
        files.extend(sorted(TESTS_ROOT.rglob("*.py")))

    all_violations: list[str] = []
    for path in files:
        all_violations.extend(check_file(path))

    if all_violations:
        print("Architecture boundary check FAILED:")
        for item in all_violations:
            print(f"  - {item}")
        return 1

    print(f"Architecture boundary check PASSED ({len(files)} files verified).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
