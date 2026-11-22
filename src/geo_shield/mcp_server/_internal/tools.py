"""MCP Server tools for GeoShield (mcp>=2.0 MCPServer)."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from geo_shield.sanitize import inspect_url
from geo_shield.verify import audit_text, audit_url, clean_search


def build_mcp_server() -> MCPServer:
    server = MCPServer("geo-shield")

    @server.tool(
        description=(
            "Search the web and return anti-GEO re-ranked results, syndication clusters, "
            "and sanitized <untrusted_web_evidence> XML context."
        )
    )
    def geoshield_search(query: str, max_results: int = 8) -> dict[str, Any]:
        report = clean_search(query=query, max_results=max_results)
        return report.model_dump(mode="json")

    @server.tool(
        description=(
            "Fetch a remote URL, strip hidden DOM/Unicode/prompt-injection payloads, "
            "and score GEO soft-ad manipulation risk."
        )
    )
    def geoshield_audit_url(url: str) -> dict[str, Any]:
        report = audit_url(url=url)
        return report.model_dump(mode="json")

    @server.tool(
        description=(
            "Sanitize and score raw HTML or plain text for GEO soft-ad signals "
            "and indirect prompt injection."
        )
    )
    def geoshield_audit_text(
        content: str,
        is_html: bool = False,
        title: str = "",
        url: str = "",
    ) -> dict[str, Any]:
        report = audit_text(content=content, is_html=is_html, title=title, url=url)
        return report.model_dump(mode="json")

    @server.tool(
        description=(
            "Inspect an AI share/referral URL ('Summarize with AI') for hidden "
            "memory poisoning or recommendation hijacking parameters."
        )
    )
    def geoshield_inspect_link(url: str) -> dict[str, Any]:
        report = inspect_url(url=url)
        return report.model_dump(mode="json")

    return server
