/**
 * Policy Bus admin REST (A-7) — http://localhost:50052
 *
 * Endpoints touched by Stage UI:
 *   GET /healthz              — top-line status
 *   GET /fleet?fleet_id=...   — 49 nodes for the FleetGrid stadium-wave
 *   GET /bundles              — signed bundle metadata (no raw bytes)
 *   GET /audit/tail?n=...     — recent audit-log events (REQUIRES admin token)
 *
 * Every call routes through `fetchWithMock` so a no-backend deploy still
 * renders the 49-dot fleet, the bundle list, and the recent-decisions feed
 * with realistic shapes. Mocks live in `app/lib/mocks/fixtures.ts`.
 */

import {
  REEF_FLEET_ID,
  REEF_POLICY_BUS_ADMIN_TOKEN,
  REEF_POLICY_BUS_ADMIN_URL,
} from "@/app/lib/env";
import { fetchWithMock } from "@/app/lib/fetchWithMock";
import {
  MOCK_AUDIT_EVENTS,
  MOCK_BUNDLES,
  MOCK_FLEET_SNAPSHOT,
  MOCK_POLICY_BUS_HEALTH,
} from "@/app/lib/mocks/fixtures";
import type {
  AuditEvent,
  BundleListItem,
  FleetSnapshot,
  PolicyBusHealthz,
} from "@/app/lib/types";

const DEFAULT_TIMEOUT_MS = 4000;

export async function fetchPolicyBusHealth(): Promise<PolicyBusHealthz> {
  const { data } = await fetchWithMock<PolicyBusHealthz>(
    `${REEF_POLICY_BUS_ADMIN_URL}/healthz`,
    MOCK_POLICY_BUS_HEALTH,
    { timeoutMs: DEFAULT_TIMEOUT_MS }
  );
  return data;
}

export async function fetchFleet(
  fleetId: string = REEF_FLEET_ID
): Promise<FleetSnapshot> {
  const url = `${REEF_POLICY_BUS_ADMIN_URL}/fleet?fleet_id=${encodeURIComponent(
    fleetId
  )}`;
  const { data } = await fetchWithMock<FleetSnapshot>(
    url,
    MOCK_FLEET_SNAPSHOT,
    { timeoutMs: DEFAULT_TIMEOUT_MS }
  );
  return data;
}

export async function fetchBundles(): Promise<BundleListItem[]> {
  const { data } = await fetchWithMock<BundleListItem[]>(
    `${REEF_POLICY_BUS_ADMIN_URL}/bundles`,
    MOCK_BUNDLES,
    { timeoutMs: DEFAULT_TIMEOUT_MS }
  );
  return data;
}

/**
 * /audit/tail requires `X-Admin-Token`. In a no-backend deploy or when
 * the token is missing we fall back to the canned audit-event stream so
 * the recent-decisions feed shows MODIFY / QUARANTINE / HUMAN_REVIEW
 * receipts rather than an empty list. Live mode still requires the token
 * (we send it when set) — server-side enforcement is unchanged.
 */
export async function fetchAuditTail(n: number = 20): Promise<AuditEvent[]> {
  const url = `${REEF_POLICY_BUS_ADMIN_URL}/audit/tail?n=${n}`;
  // Missing admin token would 401 on the real backend — short-circuit to
  // the mocked tail so the recent-decisions feed still renders.
  const { data } = await fetchWithMock<AuditEvent[]>(
    url,
    MOCK_AUDIT_EVENTS.slice(0, n),
    {
      headers: REEF_POLICY_BUS_ADMIN_TOKEN
        ? { "X-Admin-Token": REEF_POLICY_BUS_ADMIN_TOKEN }
        : undefined,
      forceMock: !REEF_POLICY_BUS_ADMIN_TOKEN,
      timeoutMs: DEFAULT_TIMEOUT_MS,
    }
  );
  return data;
}
