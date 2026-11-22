"""Agent-Reach Exa web search adapter (read-only subprocess JSON)."""

from __future__ import annotations

import json
import shutil
import subprocess

from .models import SearchResult


def search_agent_reach(
    query: str, max_results: int = 10, timeout: float = 20.0
) -> list[SearchResult]:
    exe = shutil.which("agent-reach")
    if not exe:
        raise RuntimeError("agent-reach CLI not found on PATH")

    proc = subprocess.run(
        [exe, "web", "search", query, "--limit", str(max_results)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"agent-reach exited with {proc.returncode}: {proc.stderr.strip()}")

    payload = json.loads(proc.stdout)
    if not payload.get("ok"):
        err = payload.get("error") or {}
        raise RuntimeError(f"agent-reach failed: {err.get('code', 'ERROR')} {err.get('message', '')}")

    results: list[SearchResult] = []
    for idx, item in enumerate(payload.get("items", []), start=1):
        url = str(item.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        text = str(item.get("text") or "").strip()
        results.append(
            SearchResult(
                title=str(item.get("title") or url),
                url=url,
                snippet=text[:400],
                full_text=text,
                rank=idx,
                engine="agent-reach-exa",
            )
        )
        if len(results) >= max_results:
            break
    return results
