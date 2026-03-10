"""``vectimus server`` -- start the Vectimus HTTP server.

Requires the ``server`` extra: ``pip install vectimus[server]``.
"""

from __future__ import annotations

import click


@click.group("server")
def server_cmd() -> None:
    """Manage the Vectimus HTTP server (requires vectimus[server])."""


@server_cmd.command("start")
@click.option("--host", default=None, help="Bind host.  Default: 0.0.0.0.")
@click.option("--port", default=None, type=int, help="Bind port.  Default: 8420.")
@click.option(
    "--policy-dir",
    default=None,
    help="Policy directory.  Defaults to built-in policies.",
)
@click.option(
    "--observe",
    is_flag=True,
    default=False,
    help="Enable observe mode (log decisions but always allow).",
)
def server_start(
    host: str | None,
    port: int | None,
    policy_dir: str | None,
    observe: bool,
) -> None:
    """Start the Vectimus governance server."""
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        click.echo(
            "The server requires additional dependencies.\n"
            "Install them with: pip install vectimus[server]",
            err=True,
        )
        raise SystemExit(1)

    from vectimus.server.config import ServerConfig

    config = ServerConfig.load()
    if host is not None:
        config.host = host
    if port is not None:
        config.port = port
    if policy_dir is not None:
        config.policy_dir = policy_dir
    if observe:
        config.observe = True

    if config.api_key is None:
        click.echo(
            "Warning: No API key configured. The /evaluate endpoint is unprotected.\n"
            "Set VECTIMUS_API_KEY or add api_key to config.toml.",
            err=True,
        )

    click.echo(f"Starting Vectimus server on {config.host}:{config.port}")

    import uvicorn

    uvicorn.run(
        "vectimus.server.app:create_app",
        factory=True,
        host=config.host,
        port=config.port,
    )
