# Reef Policy Bus — TerraFabric-shaped gRPC bus container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY app /app/app
COPY README.md /app/README.md

RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -e ".[dev]"

EXPOSE 50051 50052

CMD ["python", "-m", "app.main"]
