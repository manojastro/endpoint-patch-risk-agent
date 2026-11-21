# Patch Risk Sentinel - single-container image (API + static SPA).
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Backend package, static frontend, and evaluation ground truth.
COPY backend /app/backend
COPY frontend /app/frontend
COPY evaluation /app/evaluation

# Simulated world lives here; mount a volume for persistence.
RUN mkdir -p /app/backend/data
VOLUME ["/app/backend/data"]

EXPOSE 8014

ENV DATABASE_URL="sqlite:////app/backend/data/patch_risk.db" \
    ESTATE_SIZE="2500" \
    SIM_SEED="1337" \
    LLM_MODE="mock" \
    LOG_LEVEL="INFO"

WORKDIR /app/backend

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8014/health', timeout=3).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8014"]
