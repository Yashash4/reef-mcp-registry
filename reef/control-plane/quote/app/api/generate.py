"""POST /quote/ria/generate — assemble + sign a fresh RIA PDF."""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from app.data_sources import (
    AtlasUnreachable,
    AuditRootError,
    DastAUnreachable,
    PolicyBusUnreachable,
)
from app.ria_generator import RIAArtifact, RIAGenerateOptions, generate_ria
from app.underwriter_agent import (
    GeminiCallFailed,
    InvalidUnderwriterOutput,
    MissingGeminiAPIKey,
    MissingGeminiProModel,
)

logger = logging.getLogger("quote.api.generate")

router = APIRouter(prefix="/quote")


class GenerateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fleet_id: str = Field(default="prod-fleet", min_length=1, max_length=64)
    audit_window_days: int = Field(default=30, ge=1, le=365)
    include_demo_data: bool = Field(default=False)
    coverage_amount_usd: Optional[int] = Field(default=None, ge=0)
    # When true, missing Gemini key or unreachable upstream services trigger
    # the sample fallback path (deterministic stub data + sample agent).
    allow_sample_fallback: bool = Field(default=False)


class GenerateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ria_id: str
    download_url: str
    verify_url: str
    score_summary: dict[str, Any]
    sha256: str
    signature_hex_short: str
    signature_b64_short: str
    signer_key_id: str
    sample_mode: bool


def _summary(score) -> dict[str, Any]:
    return {
        "reef_risk_tier": score.reef_risk_tier,
        "tier_label_with_framing": score.tier_label_with_framing,
        "estimated_premium_low": score.estimated_premium_range_usd_annual.low,
        "estimated_premium_high": score.estimated_premium_range_usd_annual.high,
        "coverage_amount_usd": score.estimated_premium_range_usd_annual.coverage_amount_usd,
        "phase_2_disclaimer": score.phase_2_disclaimer,
    }


@router.post("/ria/generate", response_model=GenerateResponse)
def generate(req: GenerateRequest, request: Request) -> GenerateResponse:
    signer = request.app.state.signer
    data_dir = request.app.state.data_dir
    opts = RIAGenerateOptions(
        fleet_id=req.fleet_id,
        audit_window_days=req.audit_window_days,
        coverage_amount_usd=req.coverage_amount_usd,
        data_dir=str(data_dir),
        signer=signer,
        include_demo_seed_telemetry=req.include_demo_data,
        fallback_on_data_source_error=req.allow_sample_fallback,
    )
    try:
        artifact: RIAArtifact = generate_ria(opts)
    except AtlasUnreachable as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except PolicyBusUnreachable as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except DastAUnreachable as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except AuditRootError as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (MissingGeminiAPIKey, MissingGeminiProModel) as exc:
        raise HTTPException(
            status_code=503,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except GeminiCallFailed as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except InvalidUnderwriterOutput as exc:
        raise HTTPException(
            status_code=502,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc

    return GenerateResponse(
        ria_id=artifact.ria_id,
        download_url=f"/quote/ria/{artifact.ria_id}/download",
        verify_url=f"/quote/ria/{artifact.ria_id}/verify",
        score_summary=_summary(artifact.score),
        sha256=artifact.pdf_sha256_hex,
        signature_hex_short=artifact.signature_hex[:24] + "…",
        signature_b64_short=artifact.signature_b64[:32] + "…",
        signer_key_id=artifact.signer_key_id,
        sample_mode=artifact.sample_mode,
    )


__all__ = ["router", "GenerateRequest", "GenerateResponse"]
