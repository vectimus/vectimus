# Docker deployment

Run Vectimus as a containerised service.

## Quick start

```bash
docker compose up -d
```

This starts the Vectimus server on port 8420 with the built-in policy set.

## Custom policies

Mount a directory of `.cedar` policy files:

```bash
docker run -p 8420:8420 -v ./policies:/policies vectimus:latest
```

Set the `VECTIMUS_POLICY_DIR` environment variable to `/policies`.

## Health check

```bash
curl http://localhost:8420/health
```
