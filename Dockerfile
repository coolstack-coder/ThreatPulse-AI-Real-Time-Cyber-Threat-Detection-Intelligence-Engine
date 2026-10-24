# ---- dashboard build ----
FROM node:22-alpine AS ui
WORKDIR /ui
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- engine ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 THREATPULSE_DB=/data/threatpulse.db
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 threatpulse && mkdir -p /data && chown threatpulse /data
WORKDIR /app
COPY pyproject.toml README.md ./
COPY threatpulse/ threatpulse/
RUN pip install --no-cache-dir ".[capture]"
COPY config/ config/
COPY --from=ui /ui/dist frontend/dist
USER threatpulse
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health')"
ENTRYPOINT ["threatpulse"]
CMD ["run", "--host", "0.0.0.0", "--port", "8000", "--auto-attack", "90"]
