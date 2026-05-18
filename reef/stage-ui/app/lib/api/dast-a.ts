/**
 * DAST-A (RL adversary + Gemini red/blue, A-8 + A-9) — http://localhost:8083
 *
 * Endpoints touched by Stage UI:
 *   GET  /dast-a/packs         — pack catalog
 *   GET  /dast-a/review-queue  — policy drafts pending review
 *   POST /dast-a/run           — kick off N episodes (used by Shark playground)
 *
 * Every call routes through `fetchWithMock` so a no-backend deploy still
 * surfaces the 4 canonical seed packs (MCP-RCE / EchoLeak / MarkdownExfil
 * / ToolChain-Drift) and a representative pending draft.
 */

import { REEF_DAST_A_URL } from "@/app/lib/env";
import { fetchWithMock } from "@/app/lib/fetchWithMock";
import {
  MOCK_DAST_A_PACKS,
  MOCK_DAST_A_REVIEW_QUEUE,
} from "@/app/lib/mocks/fixtures";
import type { AttackPackList, PolicyDraft } from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 6000;

export async function fetchDastAPacks(
  page: number = 1,
  pageSize: number = 50
): Promise<AttackPackList> {
  const url = `${REEF_DAST_A_URL}/dast-a/packs?page=${page}&page_size=${pageSize}`;
  const { data } = await fetchWithMock<AttackPackList>(url, MOCK_DAST_A_PACKS, {
    timeoutMs: DEFAULT_TIMEOUT_MS,
  });
  return data;
}

export async function fetchDastAReviewQueue(
  status?: "pending" | "approved" | "rejected"
): Promise<PolicyDraft[]> {
  const qs = status ? `?status=${status}` : "";
  const url = `${REEF_DAST_A_URL}/dast-a/review-queue${qs}`;
  const mockFiltered = status
    ? MOCK_DAST_A_REVIEW_QUEUE.filter((d) => d.status === status)
    : MOCK_DAST_A_REVIEW_QUEUE;
  const { data } = await fetchWithMock<PolicyDraft[]>(url, mockFiltered, {
    timeoutMs: DEFAULT_TIMEOUT_MS,
  });
  return data;
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

/** Deterministic mock run summary — matches the "78 / 78 attempt-episodes
 *  blocked" line from the README receipts table. */
const MOCK_DAST_A_RUN: DastARunResponse = {
  run_handle: "dast-a-run-26051812-demo",
  episodes_completed: 5,
  successes: 0,
  blocked_by_reef: 5,
  novel_unblocked: 0,
  drafts_created: 0,
  summary: {
    reef_on: true,
    blocked_per_pack: {
      "MCP-RCE-26.04": 1,
      "EchoLeak-26.05": 2,
      "MarkdownExfil-26.05": 1,
      "ToolChain-Drift-26.04": 1,
    },
  },
};

export async function runDastA(
  req: DastARunRequest = {}
): Promise<DastARunResponse> {
  const merged = { episodes: 5, reef_on: true, ...req };
  // Bake the actual episode count + reef_on flag into the mock so the
  // playground shows numbers that match what the user asked for.
  const mock: DastARunResponse = {
    ...MOCK_DAST_A_RUN,
    episodes_completed: merged.episodes,
    blocked_by_reef: merged.reef_on ? merged.episodes : 0,
    successes: merged.reef_on ? 0 : Math.floor(merged.episodes * 0.38),
  };
  const { data } = await fetchWithMock<DastARunResponse>(
    `${REEF_DAST_A_URL}/dast-a/run`,
    mock,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(merged),
      timeoutMs: 30_000,
    }
  );
  return data;
}
