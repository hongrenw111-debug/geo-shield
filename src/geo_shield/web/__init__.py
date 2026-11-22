"""Public interface for geo_shield.web."""

import uvicorn
from fastapi import FastAPI

from ._internal.api import create_fastapi_app

__all__ = ["create_app", "run_web"]


def create_app() -> FastAPI:
    """Create the GeoShield FastAPI dashboard application."""
    return create_fastapi_app()


def run_web(host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the GeoShield local web dashboard."""
    uvicorn.run(create_fastapi_app(), host=host, port=port)
