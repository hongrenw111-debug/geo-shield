# GeoShield Repository Guidelines

## Architecture & Module Boundaries (Enforced)

`src/geo_shield/` follows the **Deep Module** pattern:

- Every business module exposes its **public contract exclusively through `__init__.py`**.
- Implementation details live under `<module>/_internal/` and are strictly private.
- Neither other `geo_shield` modules nor `tests/` may import any `<module>._internal` path.
- Dependency DAG:
  - Leaf modules (zero intra-project dependencies): `sanitize`, `geo_score`, `retrieval`
  - Orchestration: `verify` -> (`sanitize`, `geo_score`, `retrieval`)
  - Delivery surfaces: `mcp_server`, `web` -> (`verify`, `sanitize`, `geo_score`); `cli` -> public module interfaces

## Standard Validation Command

Run the full check suite (`ruff` + AST boundary check + `pytest`) before claiming any change is ready:

```powershell
uv run python scripts/validate.py
```

Boundary checker alone:

```powershell
uv run python scripts/check_boundaries.py
```
