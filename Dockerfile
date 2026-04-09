FROM python:3.14-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

RUN useradd --create-home --shell /bin/bash vectimus
USER vectimus

ENV VECTIMUS_HOST=0.0.0.0
ENV VECTIMUS_PORT=8420
ENV VECTIMUS_WORKERS=1

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/healthz')" || exit 1

CMD ["vectimus", "server", "start"]
