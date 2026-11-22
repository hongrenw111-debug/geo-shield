"""FastAPI backend for the GeoShield local security dashboard."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from geo_shield.geo_score import is_llm_audit_configured
from geo_shield.sanitize import inspect_url
from geo_shield.verify import SourceInput, audit_sources, audit_text, audit_url, clean_search

_STATIC_INDEX = Path(__file__).resolve().parent / "static" / "index.html"


class AuditTextRequest(BaseModel):
    content: str
    is_html: bool = False
    title: str = ""
    url: str = ""


class AuditUrlRequest(BaseModel):
    url: str


class AuditBatchRequest(BaseModel):
    query: str = "AI 办公软件推荐"
    sources: list[SourceInput] = Field(default_factory=list)


class SearchRequest(BaseModel):
    query: str
    max_results: int = Field(default=8, ge=1, le=20)
    searxng_url: str | None = None


def create_fastapi_app() -> FastAPI:
    app = FastAPI(title="GeoShield", version="0.1.0")

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        html = _STATIC_INDEX.read_text(encoding="utf-8")
        return HTMLResponse(content=html)

    @app.get("/api/health")
    def health() -> dict[str, object]:
        llm_on = is_llm_audit_configured()
        return {
            "status": "ok",
            "version": "0.1.0",
            "llm_configured": llm_on,
            "mode": "hybrid_llm" if llm_on else "local_only",
        }

    @app.get("/api/config")
    def config() -> dict[str, object]:
        llm_on = is_llm_audit_configured()
        return {
            "llm_configured": llm_on,
            "mode": "hybrid_llm" if llm_on else "local_only",
        }

    @app.post("/api/audit/text")
    def api_audit_text(req: AuditTextRequest) -> dict[str, object]:
        rep = audit_text(
            content=req.content,
            is_html=req.is_html,
            title=req.title,
            url=req.url,
        )
        return rep.model_dump(mode="json")

    @app.post("/api/audit/url")
    def api_audit_url(req: AuditUrlRequest) -> dict[str, object]:
        rep = audit_url(url=req.url)
        return rep.model_dump(mode="json")

    @app.post("/api/audit/link")
    def api_audit_link(req: AuditUrlRequest) -> dict[str, object]:
        rep = inspect_url(url=req.url)
        return rep.model_dump(mode="json")

    @app.post("/api/audit/batch")
    def api_audit_batch(req: AuditBatchRequest) -> dict[str, object]:
        rep = audit_sources(query=req.query, sources=req.sources)
        return rep.model_dump(mode="json")

    @app.post("/api/search")
    def api_search(req: SearchRequest) -> dict[str, object]:
        rep = clean_search(
            query=req.query,
            max_results=req.max_results,
            searxng_url=req.searxng_url,
        )
        return rep.model_dump(mode="json")

    return app
