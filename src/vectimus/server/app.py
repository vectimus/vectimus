"""FastAPI application factory for the Vectimus governance server."""

from __future__ import annotations

import hmac
import time
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import vectimus
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.session_store import SessionStore
from vectimus.exporters.jsonl import JsonlExporter
from vectimus.server.config import ServerConfig

logger = structlog.get_logger(__name__)

# Paths exempt from API key auth (probes + health).
_AUTH_EXEMPT_PATHS = {"/health", "/healthz", "/ready"}


@asynccontextmanager
async def _lifespan(app: FastAPI):  # type: ignore[type-arg]
    """Startup/shutdown lifecycle for the application."""
    app.state.start_time = time.monotonic()
    logger.info("server_starting", version=vectimus.__version__)
    yield
    logger.info("server_shutting_down")
    # Close the exporter so any buffered writes are flushed.
    if hasattr(app.state, "exporter"):
        app.state.exporter.close()


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
        version=vectimus.__version__,
        lifespan=_lifespan,
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

    # Single exporter instance shared across all requests
    app.state.exporter = JsonlExporter(log_dir=config.log_dir)

    # Set start_time here as fallback; lifespan will override it.
    app.state.start_time = time.monotonic()

    # API key middleware: supports both single key and named keys.
    # Probe endpoints (/health, /healthz, /ready) are always exempt.
    api_key_lookup = config.resolve_api_keys()
    if api_key_lookup:

        @app.middleware("http")
        async def check_api_key(request: Request, call_next):  # type: ignore[no-untyped-def]
            """Reject requests missing a valid API key."""
            if request.method == "OPTIONS" or request.url.path in _AUTH_EXEMPT_PATHS:
                return await call_next(request)

            provided = request.headers.get("X-Vectimus-API-Key", "")
            matched_name: str | None = None
            for key, name in api_key_lookup.items():
                if hmac.compare_digest(provided, key):
                    matched_name = name
                    break

            if matched_name is None:
                logger.warning("auth_rejected", path=request.url.path)
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid or missing API key"},
                )

            # Stash identity for structured logging in routes
            request.state.api_key_name = matched_name
            return await call_next(request)

    # CORS middleware registered after auth so it wraps all responses
    # (including 401s) with Access-Control-Allow-Origin headers.
    # Starlette middleware is LIFO: last added = outermost = runs first.
    if config.cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.cors_origins,
            allow_methods=["GET", "POST"],
            allow_headers=["X-Vectimus-Source", "X-Vectimus-API-Key", "Content-Type"],
        )

    # Register routes
    from vectimus.server.routes import router  # noqa: E402

    app.include_router(router)

    return app
