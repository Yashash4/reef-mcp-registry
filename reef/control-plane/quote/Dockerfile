# Reef Quote — Underwriter + RIA generator (Layer 7) container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first so they cache across code edits.
COPY pyproject.toml /app/pyproject.toml
COPY README.md /app/README.md
COPY app /app/app

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -e ".[dev]"

EXPOSE 8082

CMD ["python", "-m", "uvicorn", "app.api.app:app", "--host", "0.0.0.0", "--port", "8082"]
