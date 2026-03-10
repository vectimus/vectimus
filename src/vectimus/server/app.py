"""FastAPI application factory for the Vectimus governance server."""

from __future__ import annotations

import hmac

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vectimus.core.evaluator import PolicyEngine
from vectimus.core.loader import PolicyLoader
from vectimus.core.session_store import SessionStore
from vectimus.server.config import ServerConfig

logger = structlog.get_logger(__name__)


def create_app(config: ServerConfig | None = None) -> FastAPI:
    """Build and return the FastAPI application.

    The PolicyEngine and ServerConfig are stored on ``app.state`` so that
    route handlers can access them via ``request.app.state``.
    """
    if config is None:
        config = ServerConfig.load()

    app = FastAPI(
        title="Vectimus",
        description="Deterministic governance for AI coding tools and autonomous agents",
        version="0.1.0",
    )

    # When a custom policy_dir is set, load policies directly from that
    # directory (flat .cedar files, no pack structure required).
    # Otherwise use PolicyLoader for full pack discovery, MCP allowlisting
    # and per-rule overrides.
    if config.policy_dir:
        engine = PolicyEngine(policy_dir=config.policy_dir, observe=config.observe)
    else:
        loader = PolicyLoader(
            mcp_allowed_override=(
                config.mcp_allowed_servers if config.mcp_allowed_servers else None
            ),
        )
        engine = PolicyEngine(loader=loader, observe=config.observe)
    app.state.engine = engine
    app.state.config = config

    # Initialise the session store for temporal pattern detection
    app.state.session_store = SessionStore(
        spawn_limit=config.session_spawn_limit,
        message_limit=config.session_message_limit,
        ttl_seconds=config.session_ttl_seconds,
    )

    # API key middleware: when VECTIMUS_API_KEY is set, require it on
    # all endpoints except /health.
    if config.api_key:

        @app.middleware("http")
        async def check_api_key(request: Request, call_next):  # type: ignore[no-untyped-def]
            """Reject requests missing a valid API key (except /health)."""
            if request.url.path != "/health":
                provided = request.headers.get("X-Vectimus-API-Key", "")
                if not hmac.compare_digest(provided, config.api_key):
                    logger.warning("auth_rejected", path=request.url.path)
                    return JSONResponse(
                        status_code=401,
                        content={"error": "Invalid or missing API key"},
                    )
            return await call_next(request)

    # Register routes
    from vectimus.server.routes import router  # noqa: E402

    app.include_router(router)

    return app
