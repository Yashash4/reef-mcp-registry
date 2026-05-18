/**
 * Atlas (MCP signature registry, A-5) — http://localhost:8080
 *
 * Endpoints touched by Stage UI:
 *   GET  /healthz           — verified / quarantined / poisoned counts
 *   GET  /registry/entries  — full list (used by /stage/discover AI-BOM panel)
 *   POST /verify            — used by MCPRegistryBeat for the live block beat
 *
 * Every call routes through `fetchWithMock` so a deployed-but-no-backend
 * environment (e.g., the Vercel public preview) still tells the right
 * story with realistic shapes. The mock fixtures live in
 * `app/lib/mocks/fixtures.ts` and mirror the production pydantic models.
 */

import { REEF_ATLAS_URL } from "@/app/lib/env";
import { fetchWithMock } from "@/app/lib/fetchWithMock";
import {
  MOCK_ATLAS_ENTRIES,
  MOCK_ATLAS_HEALTH,
  MOCK_ATLAS_VERIFY_ALLOW,
  MOCK_ATLAS_VERIFY_DENY,
} from "@/app/lib/mocks/fixtures";
import type {
  AtlasEntriesList,
  AtlasHealthz,
  AtlasVerifyResponse,
} from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 4000;

export async function fetchAtlasHealth(): Promise<AtlasHealthz> {
  const { data } = await fetchWithMock<AtlasHealthz>(
    `${REEF_ATLAS_URL}/healthz`,
    MOCK_ATLAS_HEALTH,
    { timeoutMs: DEFAULT_TIMEOUT_MS }
  );
  return data;
}

export async function fetchAtlasEntries(): Promise<AtlasEntriesList> {
  const { data } = await fetchWithMock<AtlasEntriesList>(
    `${REEF_ATLAS_URL}/registry/entries`,
    MOCK_ATLAS_ENTRIES,
    { timeoutMs: DEFAULT_TIMEOUT_MS }
  );
  return data;
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
  // The MCPRegistryBeat scene fires verify against a poisoned MCP name to
  // show the BIND DENIED beat — pick the right mock based on the input so
  // the demo flow lights up correctly even with no backend.
  const mock =
    req.mcpName.includes("attacker") || req.mcpName.includes("evil")
      ? MOCK_ATLAS_VERIFY_DENY
      : MOCK_ATLAS_VERIFY_ALLOW;
  const { data } = await fetchWithMock<AtlasVerifyResponse>(
    `${REEF_ATLAS_URL}/verify`,
    mock,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
      timeoutMs: DEFAULT_TIMEOUT_MS,
    }
  );
  return data;
}
