# Reef Atlas — MCP signature registry container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so they cache across code edits.
COPY pyproject.toml /app/pyproject.toml
COPY app /app/app
COPY README.md /app/README.md

# Use the stock pip shipped with python:3.12-slim. Upgrading to pip-26+
# pulls a release that silently corrupts wheel installs to zero-byte
# Python files in this image registry — see commit fixing policy-bus.
RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
