/**
 * Atlas (MCP signature registry, A-5) — http://localhost:8080
 *
 * Endpoints touched by Stage UI:
 *   GET  /healthz           — verified / quarantined / poisoned counts
 *   GET  /registry/entries  — full list (used by /stage/discover AI-BOM panel)
 *   POST /verify            — used by MCPRegistryBeat for the live block beat
 */

import { REEF_ATLAS_URL } from "@/app/lib/env";
import type {
  AtlasEntriesList,
  AtlasHealthz,
  AtlasVerifyResponse,
} from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 4000;

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

export async function fetchAtlasHealth(): Promise<AtlasHealthz> {
  return fetchJSON<AtlasHealthz>(`${REEF_ATLAS_URL}/healthz`);
}

export async function fetchAtlasEntries(): Promise<AtlasEntriesList> {
  return fetchJSON<AtlasEntriesList>(`${REEF_ATLAS_URL}/registry/entries`);
}

export interface AtlasVerifyRequest {
  mcpName: string;
  version: string;
  transport: "stdio" | "http" | "sse" | "websocket";
  agent_id: string;
  request_id: string;
  claimed_sdk_version?: string;
  claimed_entrypoint_hash?: string;
  claimed_tools?: string[];
}

export async function verifyAtlas(
  req: AtlasVerifyRequest
): Promise<AtlasVerifyResponse> {
  return fetchJSON<AtlasVerifyResponse>(`${REEF_ATLAS_URL}/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
}
