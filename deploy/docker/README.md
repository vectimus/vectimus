# Docker deployment

Run Vectimus as a containerised service.

## Quick start

```bash
docker compose up -d
```

This starts the Vectimus server on port 8420 with the built-in policy set.

## Configuration

All server settings are configurable via environment variables. See the [server docs](https://vectimus.com/docs/server) for the full list.

```yaml
services:
  vectimus:
    build: .
    ports:
      - "8420:8420"
    environment:
      - VECTIMUS_WORKERS=2
      - VECTIMUS_API_KEYS=team1:key1,team2:key2
      - VECTIMUS_CORS_ORIGINS=https://dashboard.example.com
```

## TLS

Mount your certificates and set the env vars:

```yaml
    environment:
      - VECTIMUS_SSL_CERTFILE=/certs/cert.pem
      - VECTIMUS_SSL_KEYFILE=/certs/key.pem
    volumes:
      - ./certs:/certs:ro
```

## Custom policies

Mount a directory of `.cedar` policy files:

```bash
docker run -p 8420:8420 \
           -e VECTIMUS_POLICY_DIR=/policies \
           -v ./policies:/policies:ro \
           vectimus
```

## Health checks

The container includes a built-in health check against `/healthz`. For k8s deployments:

- **Liveness**: `GET /healthz` (always 200 if process is alive)
- **Readiness**: `GET /ready` (200 when policies are loaded, 503 otherwise)
