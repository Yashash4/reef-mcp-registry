/**
 * Quote / RIA (A-10) — http://localhost:8082
 *
 * Endpoints:
 *   GET  /quote/ria/sample/download       — committed sample-ria.pdf binary
 *   GET  /quote/ria/sample/verify         — verify the committed sample
 *   POST /quote/ria/generate              — full live RIA gen (needs Gemini key)
 *   GET  /quote/ria/{ria_id}/download     — generated PDF
 *   GET  /quote/ria/{ria_id}/verify       — re-verify a generated artifact
 */

import { REEF_QUOTE_URL } from "@/app/lib/env";
import type {
  RIAGenerateResponse,
  RIAScoreSummary,
  RIAVerifyResponse,
} from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 8000;

async function fetchJSON<T>(
  url: string,
  init?: RequestInit & { timeoutMs?: number }
): Promise<T> {
  const ctl = new AbortController();
  const t = setTimeout(
    () => ctl.abort(),
    init?.timeoutMs ?? DEFAULT_TIMEOUT_MS
  );
  try {
    const res = await fetch(url, { ...init, signal: ctl.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText} on ${url}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

export const RIA_SAMPLE_DOWNLOAD_URL = `${REEF_QUOTE_URL}/quote/ria/sample/download`;

export async function fetchRIASampleVerify(): Promise<RIAVerifyResponse> {
  return fetchJSON<RIAVerifyResponse>(
    `${REEF_QUOTE_URL}/quote/ria/sample/verify`
  );
}

export interface RIAGenerateRequest {
  fleet_id?: string;
  audit_window_days?: number;
  include_demo_data?: boolean;
  coverage_amount_usd?: number;
  allow_sample_fallback?: boolean;
}

export async function generateRIA(
  req: RIAGenerateRequest = {}
): Promise<RIAGenerateResponse> {
  return fetchJSON<RIAGenerateResponse>(
    `${REEF_QUOTE_URL}/quote/ria/generate`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fleet_id: "prod-fleet",
        allow_sample_fallback: true,
        ...req,
      }),
      timeoutMs: 30_000,
    }
  );
}

/**
 * STATIC FALLBACK metadata — used when the Quote service is offline. The
 * verbatim disclaimer strings are required by docs/03-TASKS.md "Hard
 * rules" #4. Keep these in sync with the live underwriter agent output
 * (`quote/app/underwriter_agent.py::_enforce_post_validation_invariants`).
 */
export const STATIC_SAMPLE_RIA_SUMMARY: RIAScoreSummary = {
  reef_risk_tier: "B+",
  tier_label_with_framing: "Reef Risk Tier B+ mapped to Munich Re aiSure axes",
  estimated_premium_low: 42_000,
  estimated_premium_high: 54_000,
  coverage_amount_usd: 5_000_000,
  phase_2_disclaimer:
    "This is a rubric-grounded score, not a Lloyd's quote. Phase 2 integrates real broker API (Bold Penguin / CoverGenius / Vouch dev sandboxes).",
};
