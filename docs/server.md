# Running Vectimus as a shared server

The Vectimus server provides HTTP endpoints for centralised policy evaluation.  This is useful for small teams who want shared governance without setting up enterprise infrastructure.

The server is an optional component.  The default `pip install vectimus` gives you local-only evaluation via command hooks.  The server extends this with a shared `/evaluate` endpoint that multiple developers can point their hooks at.

## Installation

```bash
pip install vectimus[server]
```

This installs FastAPI and uvicorn alongside the core Vectimus package.

## Starting the server

```bash
vectimus server start
```

Options:

```bash
vectimus server start --host 0.0.0.0 --port 8420
vectimus server start --policy-dir ./my-policies
```

Or run directly with uvicorn:

```bash
uvicorn vectimus.server.app:create_app --factory --host 0.0.0.0 --port 8420
```

## Authentication

Set the `VECTIMUS_API_KEY` environment variable on both the server and clients to enable API key authentication.  When set, the server requires a valid `X-Vectimus-API-Key` header on `/evaluate` requests.  The `/health` and `/policies` endpoints remain open for monitoring.

```bash
# Server
export VECTIMUS_API_KEY="your-secret-key"
vectimus server start

# Client (shims read the same env var)
export VECTIMUS_API_KEY="your-secret-key"
export VECTIMUS_SERVER_URL="https://vectimus.internal.example.com"
```

When `VECTIMUS_API_KEY` is not set, no authentication is required.  The server is designed for trusted networks.  Do not expose it to the public internet without additional network-level controls.

## Observe mode

The server supports observe mode.  Set `VECTIMUS_OBSERVE=true` on the server to log all decisions without blocking any actions.

```bash
VECTIMUS_OBSERVE=true vectimus server start
```

## Docker

```bash
docker compose up -d
```

The Dockerfile installs `vectimus[server]` and starts uvicorn on port 8420.

```bash
docker run -e VECTIMUS_API_KEY=secret \
           -e VECTIMUS_MCP_ALLOWED=github,slack \
           -p 8420:8420 vectimus
```

## Connecting tools to the server

Run `vectimus init --server-url https://vectimus.internal.example.com` to configure your tools to send hook events to the server instead of evaluating locally.

## Endpoints

| Method | Path | Purpose | Auth required |
|--------|------|---------|---------------|
| POST | `/evaluate` | Evaluate a tool event against policies | Yes (when API key set) |
| GET | `/policies` | List loaded policies with metadata | No |
| GET | `/health` | Server status, policy count, uptime | No |
| GET | `/events` | SSE stream of real-time evaluation events | No |

The `/evaluate` endpoint accepts an `X-Vectimus-Source` header to identify the source tool (`claude-code`, `cursor` or `copilot`).

## Configuration

The server reads configuration from the same sources as the CLI:

1. `./vectimus.toml` (project-level)
2. `~/.vectimus/config.toml` (user-level)
3. Environment variables

```toml
[server]
host = "0.0.0.0"
port = 8420

[policies]
dir = "./policies"

[mcp]
allowed_servers = ["github", "slack"]

[logging]
dir = "~/.vectimus/logs"
```

### Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VECTIMUS_HOST` | Bind address | `0.0.0.0` |
| `VECTIMUS_PORT` | Bind port | `8420` |
| `VECTIMUS_POLICY_DIR` | Policy directory | Built-in policies |
| `VECTIMUS_LOG_DIR` | Audit log directory | `~/.vectimus/logs` |
| `VECTIMUS_API_KEY` | API key for auth | None (no auth) |
| `VECTIMUS_OBSERVE` | Observe mode (`true`/`1`) | Off |
| `VECTIMUS_MCP_ALLOWED` | Approved MCP servers (comma-separated) | None (all blocked) |

## Enterprise

The open-source server provides the core evaluation API.  Vectimus Enterprise extends it with SSO, personas, a dashboard frontend, SIEM exporters and compliance reporting.
