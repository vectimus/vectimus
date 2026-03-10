FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir ".[server]"

RUN useradd --create-home --shell /bin/bash vectimus
USER vectimus

ENV VECTIMUS_HOST=0.0.0.0
ENV VECTIMUS_PORT=8420

EXPOSE 8420

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8420/health')" || exit 1

CMD ["uvicorn", "vectimus.server.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8420"]
