"""Unified CLI entry point for GeoShield."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from geo_shield.mcp_server import run_stdio
from geo_shield.sanitize import inspect_url
from geo_shield.verify import audit_text, audit_url, clean_search
from geo_shield.web import run_web


def _configure_stdio_utf8() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def _print_json(data: object) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="geo-shield",
        description="GeoShield: Anti-GEO soft-ad detector, prompt-injection sanitizer, and MCP/Web toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_url = sub.add_parser("audit-url", help="Fetch, sanitize, and score a remote URL.")
    p_url.add_argument("url", help="Target HTTP/HTTPS URL.")
    p_url.add_argument("--json", action="store_true", help="Print JSON output.")

    p_txt = sub.add_parser("audit-text", help="Sanitize and score raw HTML or plain text.")
    p_txt.add_argument("--file", type=Path, help="Path to HTML/text file.")
    p_txt.add_argument("--text", help="Inline text or HTML string.")
    p_txt.add_argument("--html", action="store_true", help="Parse input as HTML.")
    p_txt.add_argument("--title", default="", help="Optional document title.")
    p_txt.add_argument("--url", default="", help="Optional source URL.")
    p_txt.add_argument("--json", action="store_true", help="Print JSON output.")

    p_link = sub.add_parser("inspect-link", help="Inspect an AI prompt/share URL for memory poisoning.")
    p_link.add_argument("url", help="URL to inspect.")
    p_link.add_argument("--json", action="store_true", help="Print JSON output.")

    p_search = sub.add_parser("search", help="Search the web and re-rank against GEO/injections.")
    p_search.add_argument("query", help="Search query.")
    p_search.add_argument("--max-results", type=int, default=8, help="Max results (default 8).")
    p_search.add_argument("--searxng", default=None, help="Optional SearXNG base URL.")
    p_search.add_argument("--json", action="store_true", help="Print JSON output.")

    sub.add_parser("mcp", help="Start GeoShield stdio MCP server.")

    p_web = sub.add_parser("web", help="Start GeoShield local web audit dashboard.")
    p_web.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1).")
    p_web.add_argument("--port", type=int, default=8787, help="Bind port (default 8787).")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit-url":
        rep = audit_url(args.url)
        if args.json:
            _print_json(rep.model_dump(mode="json"))
        else:
            print(f"[{rep.verdict}] combined={rep.combined_risk}/100 geo={rep.geo.geo_risk} inj={rep.sanitize.injection_risk}")
            print(rep.geo.summary)
        return 0 if rep.fetch_ok else 1

    if args.command == "audit-text":
        if args.file:
            content = args.file.read_text(encoding="utf-8", errors="replace")
        elif args.text is not None:
            content = args.text
        elif not sys.stdin.isatty():
            content = sys.stdin.read()
        else:
            parser.error("Provide --file, --text, or pipe input via stdin.")
            return 2

        rep = audit_text(content=content, is_html=args.html, title=args.title, url=args.url)
        if args.json:
            _print_json(rep.model_dump(mode="json"))
        else:
            print(f"[{rep.verdict}] combined={rep.combined_risk}/100 geo={rep.geo.geo_risk} inj={rep.sanitize.injection_risk}")
            print(f"Findings: {len(rep.sanitize.findings)}, Signals: {len(rep.geo.signals)}")
            print("--- Clean Text ---")
            print(rep.sanitize.clean_text)
        return 0

    if args.command == "inspect-link":
        rep = inspect_url(args.url)
        if args.json:
            _print_json(rep.model_dump(mode="json"))
        else:
            print(f"[{rep.risk_level}] score={rep.risk_score}/100 ai_entry={rep.is_ai_entrypoint}")
            print(rep.verdict)
        return 0

    if args.command == "search":
        rep = clean_search(query=args.query, max_results=args.max_results, searxng_url=args.searxng)
        if args.json:
            _print_json(rep.model_dump(mode="json"))
        else:
            print(rep.summary)
            for item in rep.results:
                print(
                    f"#{item.purified_rank} (was #{item.original_rank}) "
                    f"risk={item.combined_risk} | {item.title} | {item.url}"
                )
            print("\n--- Safe Context XML ---")
            print(rep.safe_context_xml)
        return 0

    if args.command == "mcp":
        run_stdio()
        return 0

    if args.command == "web":
        run_web(host=args.host, port=args.port)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
