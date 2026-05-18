"""Audit Merkle root: shells out to the Go ``lobstertrap audit signed-root`` CLI.

The Reef Merkle audit log is the property of the Go binary (A-6). To embed
its signed root into the RIA PDF we call the new CLI subcommand added
alongside A-10:

    lobstertrap audit signed-root --dir <REEF_AUDIT_DIR> [--signer-priv-key <path>]

Returns a JSON document with ``root``, ``signature``, ``count``,
``timestamp``. We parse that here and surface a clear
:class:`AuditRootError` on any failure mode (binary missing, audit dir
unreadable, malformed JSON).

The path to the binary is resolved in this order:

1. ``REEF_LOBSTERTRAP_BIN`` env var
2. ``lobstertrap`` on ``$PATH`` (production)
3. ``../lobstertrap-reef/lobstertrap`` (dev workspace)

The path to the audit dir is resolved in this order:

1. Explicit ``audit_dir`` argument
2. ``REEF_AUDIT_DIR`` env var
3. ``./audit`` (the Go binary's own default)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.data_sources import AuditRootError

logger = logging.getLogger("quote.data_sources.audit_root")


@dataclass
class SignedMerkleRoot:
    root_hex: str
    signature_b64: str
    count: int
    timestamp_iso: str
    signed: bool
    dir: str
    hash_algo: str = "sha256"
    signature_algo: str = "ed25519-over-raw-root-bytes"

    @property
    def is_empty(self) -> bool:
        return self.count == 0 or not self.root_hex

    def short_root(self, n: int = 16) -> str:
        return (self.root_hex[:n] + "…") if len(self.root_hex) > n else self.root_hex

    def short_signature(self, n: int = 16) -> str:
        return (
            (self.signature_b64[:n] + "…")
            if len(self.signature_b64) > n
            else self.signature_b64
        )


def _resolve_binary_path(override: Optional[str] = None) -> Path:
    """Locate the ``lobstertrap`` binary or raise :class:`AuditRootError`."""
    if override:
        p = Path(override)
        if p.exists():
            return p.resolve()
        raise AuditRootError(
            f"REEF_LOBSTERTRAP_BIN={override!r} does not exist on disk"
        )
    env_path = os.environ.get("REEF_LOBSTERTRAP_BIN")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p.resolve()
        raise AuditRootError(
            f"REEF_LOBSTERTRAP_BIN={env_path!r} does not exist on disk"
        )
    on_path = shutil.which("lobstertrap")
    if on_path:
        return Path(on_path).resolve()
    # Dev workspace fallback — relative to this package, two parents up
    # lands at the Reef workspace root.
    here = Path(__file__).resolve()
    workspace = here.parents[4]
    for candidate in (
        workspace / "lobstertrap-reef" / "lobstertrap",
        workspace / "lobstertrap-reef" / "lobstertrap.exe",
    ):
        if candidate.exists():
            return candidate.resolve()
    raise AuditRootError(
        "lobstertrap binary not found: set REEF_LOBSTERTRAP_BIN, install it on "
        "$PATH, or build it at lobstertrap-reef/lobstertrap"
    )


def fetch_signed_merkle_root(
    *,
    audit_dir: Optional[str] = None,
    signer_priv_key_path: Optional[str] = None,
    binary_override: Optional[str] = None,
    timeout_s: float = 5.0,
) -> SignedMerkleRoot:
    """Invoke ``lobstertrap audit signed-root`` and return the parsed root."""
    binary = _resolve_binary_path(binary_override)

    dir_arg = audit_dir or os.environ.get("REEF_AUDIT_DIR") or "./audit"
    cmd: list[str] = [str(binary), "audit", "signed-root", "--dir", dir_arg, "--indent=false"]
    key_path = signer_priv_key_path or os.environ.get("REEF_AUDIT_SIGNER_PRIV_KEY") or os.environ.get(
        "REEF_POLICY_SIGNER_PRIV_KEY"
    )
    if key_path:
        cmd.extend(["--signer-priv-key", key_path])

    try:
        proc = subprocess.run(  # noqa: S603 (controlled CLI invocation)
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AuditRootError(
            f"lobstertrap binary at {binary!r} could not be executed: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise AuditRootError(
            f"lobstertrap audit signed-root timed out after {timeout_s}s"
        ) from exc

    if proc.returncode != 0:
        raise AuditRootError(
            "lobstertrap audit signed-root failed: "
            f"rc={proc.returncode} stderr={proc.stderr.strip()!r}"
        )

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AuditRootError(
            f"lobstertrap audit signed-root produced non-JSON output: {proc.stdout[:256]!r}"
        ) from exc

    return SignedMerkleRoot(
        root_hex=str(data.get("root", "")),
        signature_b64=str(data.get("signature", "")),
        count=int(data.get("count", 0)),
        timestamp_iso=str(data.get("timestamp", "")),
        signed=bool(data.get("signed", False)),
        dir=str(data.get("dir", dir_arg)),
        hash_algo=str(data.get("hash_algo", "sha256")),
        signature_algo=str(data.get("signature_algo", "ed25519-over-raw-root-bytes")),
    )


# ---------------------------------------------------------------------------
# Deterministic stub for sample-RIA generation when the Go binary isn't on PATH
# ---------------------------------------------------------------------------


def stub_signed_merkle_root() -> SignedMerkleRoot:
    """A clearly-marked fake root used by the boot-time sample generator.

    The PDF that ships with the public sample is honest about being a
    sample (page-1 watermark). The Merkle root here is deterministic so
    the sample bytes are reproducible across builds; the demo never
    relies on this root verifying against a real ed25519 key.
    """
    return SignedMerkleRoot(
        root_hex="0" * 64,
        signature_b64="",
        count=0,
        timestamp_iso="1970-01-01T00:00:00Z",
        signed=False,
        dir="<sample — no live audit log>",
    )


__all__ = [
    "SignedMerkleRoot",
    "fetch_signed_merkle_root",
    "stub_signed_merkle_root",
]
