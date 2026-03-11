"""``vectimus server`` -- start the Vectimus HTTP server.

Requires the ``server`` extra: ``pip install vectimus[server]``.
"""

from __future__ import annotations

import click


@click.group("server")
def server_cmd() -> None:
    """Manage the Vectimus HTTP server (requires vectimus[server])."""


@server_cmd.command("start")
@click.option("--host", default=None, help="Bind host.  Default: 127.0.0.1.")
@click.option("--port", default=None, type=int, help="Bind port.  Default: 8420.")
@click.option("--workers", default=None, type=int, help="Number of worker processes.  Default: 1.")
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
@click.option(
    "--ssl-certfile",
    default=None,
    type=click.Path(exists=True),
    help="Path to SSL certificate file for HTTPS.",
)
@click.option(
    "--ssl-keyfile",
    default=None,
    type=click.Path(exists=True),
    help="Path to SSL private key file for HTTPS.",
)
def server_start(
    host: str | None,
    port: int | None,
    workers: int | None,
    policy_dir: str | None,
    observe: bool,
    ssl_certfile: str | None,
    ssl_keyfile: str | None,
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
    if workers is not None:
        config.workers = workers
    if policy_dir is not None:
        config.policy_dir = policy_dir
    if observe:
        config.observe = True
    if ssl_certfile is not None:
        config.ssl_certfile = ssl_certfile
    if ssl_keyfile is not None:
        config.ssl_keyfile = ssl_keyfile

    if not config.resolve_api_keys():
        click.echo(
            "Warning: No API key configured. The /evaluate endpoint is unprotected.\n"
            "Set VECTIMUS_API_KEY or add api_keys to config.toml.",
            err=True,
        )

    protocol = "https" if config.ssl_certfile else "http"
    click.echo(f"Starting Vectimus server on {protocol}://{config.host}:{config.port}")
    if config.workers > 1:
        click.echo(f"Workers: {config.workers}")

    import uvicorn

    uvicorn_kwargs: dict = {
        "host": config.host,
        "port": config.port,
        "workers": config.workers,
    }
    # uvicorn does not allow --factory with --workers > 1;
    # multi-worker mode resolves the import string directly.
    if config.workers <= 1:
        uvicorn_kwargs["factory"] = True
    if config.ssl_certfile and config.ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = config.ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = config.ssl_keyfile

    uvicorn.run("vectimus.server.app:create_app", **uvicorn_kwargs)
