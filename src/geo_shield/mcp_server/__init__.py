"""Public interface for geo_shield.mcp_server."""

from typing import Any

from ._internal.tools import build_mcp_server

__all__ = ["create_server", "run_stdio"]


def create_server() -> Any:
    """Create and configure the GeoShield MCPServer instance."""
    return build_mcp_server()


def run_stdio() -> None:
    """Run the GeoShield MCP server over stdio transport."""
    server = build_mcp_server()
    server.run(transport="stdio")
