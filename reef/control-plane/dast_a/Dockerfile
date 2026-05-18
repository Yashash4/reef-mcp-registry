# Reef DAST-A — PPO RL adversary + attack pack catalog (Layer 6) container.
#
# Note: this image ships the pre-trained 168 KB MLP policy from
# checkpoints/dast_a_baseline.zip. Playwright Chromium is NOT installed in
# this image — Gemini-Pro red-team flows that drive a real browser are
# expected to run on the host or in a sidecar Playwright container. The
# FastAPI surface + PPO runner + pack catalog all work without Chromium.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first so they cache across code edits.
COPY pyproject.toml /app/pyproject.toml
COPY README.md /app/README.md
COPY app /app/app
COPY checkpoints /app/checkpoints
COPY scripts /app/scripts

# Use the stock pip shipped with python:3.12-slim. Upgrading to pip-26+
# pulls a release that silently corrupts wheel installs to zero-byte
# Python files in this image registry — see commit fixing policy-bus.
RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8083

# Bind to 0.0.0.0:8083 inside the container so the host port (also 8083)
# maps cleanly. The default app.main:main entrypoint reads
# REEF_DAST_A_HOST / REEF_DAST_A_PORT from the env which we set in
# docker-compose.yml.
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8083"]
