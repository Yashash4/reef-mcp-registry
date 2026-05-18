# Reef Policy Bus — TerraFabric-shaped gRPC bus container.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml /app/pyproject.toml
COPY app /app/app
COPY README.md /app/README.md
COPY proto /app/proto
COPY scripts /app/scripts

# Use the stock pip shipped with python:3.12-slim. Upgrading to pip-26+
# pulls a release that silently corrupts wheel installs to zero-byte
# Python files (root cause of the original docker compose up failure
# where policy-bus crashed with AttributeError on protobuf.runtime_version).
RUN pip install --no-cache-dir -e ".[dev]"

# Regenerate the protobuf + gRPC Python stubs against whatever protobuf
# version pip just resolved, so the generator-vs-runtime version check
# inside policy_bus_pb2.py always matches. The committed stubs target a
# specific protobuf version; rebuilding here avoids cross-version drift.
# Call grpc_tools.protoc directly (the gen_protos.py helper expects a
# full repo checkout layout for its Go side, which we don't have here).
RUN python -m grpc_tools.protoc \
        -Iproto \
        --python_out=app/gen \
        --grpc_python_out=app/gen \
        --pyi_out=app/gen \
        proto/policy_bus.proto && \
    sed -i 's|^import policy_bus_pb2 as policy__bus__pb2$|from app.gen import policy_bus_pb2 as policy__bus__pb2|' \
        app/gen/policy_bus_pb2_grpc.py

EXPOSE 50051 50052

CMD ["python", "-m", "app.main"]
