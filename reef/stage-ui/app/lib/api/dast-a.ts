/**
 * DAST-A (RL adversary + Gemini red/blue, A-8 + A-9) — http://localhost:8083
 *
 * Endpoints touched by Stage UI:
 *   GET  /dast-a/packs         — pack catalog
 *   GET  /dast-a/review-queue  — policy drafts pending review
 *   POST /dast-a/run           — kick off N episodes (used by Shark playground)
 *
 * Live red-team / blue-team SSE wired in:
 *   POST /dast-a/red-team/gemini-run
 *   POST /dast-a/blue-team/observe
 */

import { REEF_DAST_A_URL } from "@/app/lib/env";
import type { AttackPackList, PolicyDraft } from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 6000;

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

export async function fetchDastAPacks(
  page: number = 1,
  pageSize: number = 50
): Promise<AttackPackList> {
  const url = `${REEF_DAST_A_URL}/dast-a/packs?page=${page}&page_size=${pageSize}`;
  return fetchJSON<AttackPackList>(url);
}

export async function fetchDastAReviewQueue(
  status?: "pending" | "approved" | "rejected"
): Promise<PolicyDraft[]> {
  const qs = status ? `?status=${status}` : "";
  return fetchJSON<PolicyDraft[]>(
    `${REEF_DAST_A_URL}/dast-a/review-queue${qs}`
  );
}

export interface DastARunRequest {
  episodes?: number;
  reef_on?: boolean;
}

export interface DastARunResponse {
  run_handle: string;
  episodes_completed: number;
  successes: number;
  blocked_by_reef: number;
  novel_unblocked: number;
  drafts_created: number;
  summary?: Record<string, unknown>;
}

export async function runDastA(
  req: DastARunRequest = {}
): Promise<DastARunResponse> {
  return fetchJSON<DastARunResponse>(`${REEF_DAST_A_URL}/dast-a/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ episodes: 5, reef_on: true, ...req }),
    timeoutMs: 30_000,
  });
}
