/**
 * Policy Bus admin REST (A-7) — http://localhost:50052
 *
 * Endpoints touched by Stage UI:
 *   GET /healthz              — top-line status
 *   GET /fleet?fleet_id=...   — 49 nodes for the FleetGrid stadium-wave
 *   GET /bundles              — signed bundle metadata (no raw bytes)
 *   GET /audit/tail?n=...     — recent audit-log events (REQUIRES admin token)
 */

import {
  REEF_FLEET_ID,
  REEF_POLICY_BUS_ADMIN_TOKEN,
  REEF_POLICY_BUS_ADMIN_URL,
} from "@/app/lib/env";
import type {
  AuditEvent,
  BundleListItem,
  FleetSnapshot,
  PolicyBusHealthz,
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

export async function fetchPolicyBusHealth(): Promise<PolicyBusHealthz> {
  return fetchJSON<PolicyBusHealthz>(
    `${REEF_POLICY_BUS_ADMIN_URL}/healthz`
  );
}

export async function fetchFleet(
  fleetId: string = REEF_FLEET_ID
): Promise<FleetSnapshot> {
  const url = `${REEF_POLICY_BUS_ADMIN_URL}/fleet?fleet_id=${encodeURIComponent(
    fleetId
  )}`;
  return fetchJSON<FleetSnapshot>(url);
}

export async function fetchBundles(): Promise<BundleListItem[]> {
  return fetchJSON<BundleListItem[]>(
    `${REEF_POLICY_BUS_ADMIN_URL}/bundles`
  );
}

/**
 * /audit/tail requires `X-Admin-Token`. Without one we throw a typed
 * "admin token missing" error so the hook can surface a 'service offline'
 * badge gracefully — no silent empty array.
 */
export async function fetchAuditTail(n: number = 20): Promise<AuditEvent[]> {
  if (!REEF_POLICY_BUS_ADMIN_TOKEN) {
    throw new Error(
      "Policy bus admin token missing — set NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_TOKEN in .env.local to enable the audit feed."
    );
  }
  return fetchJSON<AuditEvent[]>(
    `${REEF_POLICY_BUS_ADMIN_URL}/audit/tail?n=${n}`,
    {
      headers: { "X-Admin-Token": REEF_POLICY_BUS_ADMIN_TOKEN },
    }
  );
}
