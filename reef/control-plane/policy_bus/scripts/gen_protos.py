"""Regenerate the Python + Go stubs from proto/policy_bus.proto.

Usage:

    python scripts/gen_protos.py

Requires `grpcio-tools` for the Python side. The Go side uses the standard
`protoc-gen-go` + `protoc-gen-go-grpc` plugins on PATH; if absent, the Go
generation step is skipped with a warning (Python stubs still update).

The generated Python file `policy_bus_pb2_grpc.py` imports `policy_bus_pb2`
as a flat module by default. We post-patch it to use the package-relative
form `from app.gen import policy_bus_pb2` so the stubs work both when
imported as `app.gen.policy_bus_pb2_grpc` AND when used from tests.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
POLICY_BUS_DIR = Path(__file__).resolve().parents[1]
PROTO_DIR = POLICY_BUS_DIR / "proto"
PY_OUT_DIR = POLICY_BUS_DIR / "app" / "gen"
GO_OUT_DIR = REPO_ROOT / "lobstertrap-reef" / "pkg" / "policysync" / "proto"


def _python_gen() -> None:
    PY_OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"-I{PROTO_DIR}",
        f"--python_out={PY_OUT_DIR}",
        f"--grpc_python_out={PY_OUT_DIR}",
        f"--pyi_out={PY_OUT_DIR}",
        str(PROTO_DIR / "policy_bus.proto"),
    ]
    print("[gen] python:", " ".join(cmd))
    subprocess.run(cmd, check=True)

    grpc_stub = PY_OUT_DIR / "policy_bus_pb2_grpc.py"
    text = grpc_stub.read_text(encoding="utf-8")
    patched = text.replace(
        "import policy_bus_pb2 as policy__bus__pb2",
        "from app.gen import policy_bus_pb2 as policy__bus__pb2",
    )
    grpc_stub.write_text(patched, encoding="utf-8")
    print(f"[gen] python: patched relative import in {grpc_stub.name}")


def _go_gen() -> None:
    protoc = shutil.which("protoc")
    if not protoc:
        print("[gen] go: protoc not on PATH — skipping Go stub generation")
        return
    GO_OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        protoc,
        f"-I{PROTO_DIR}",
        f"--go_out={GO_OUT_DIR}",
        "--go_opt=paths=source_relative",
        f"--go-grpc_out={GO_OUT_DIR}",
        "--go-grpc_opt=paths=source_relative",
        str(PROTO_DIR / "policy_bus.proto"),
    ]
    print("[gen] go:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def main() -> None:
    _python_gen()
    _go_gen()
    print("[gen] done.")


if __name__ == "__main__":
    main()
