/**
 * Resolves the upstream-service URLs the Stage UI talks to.
 *
 * All five services run locally during the demo:
 *   - Atlas (A-5)           — http://localhost:8080  (FastAPI + ed25519)
 *   - Policy Bus admin (A-7)— http://localhost:50052 (FastAPI)
 *   - DAST-A (A-8)          — http://localhost:8083  (FastAPI)
 *   - Quote / RIA (A-10)    — http://localhost:8082  (FastAPI)
 *   - Victim (A-2)          — http://localhost:3001  (Next.js)
 *
 * Each env-var falls back to the local-default so `pnpm dev` works without
 * any .env.local. Operators deploying a real instance set the
 * NEXT_PUBLIC_REEF_* vars from .env.local.
 */

export const REEF_ATLAS_URL =
  process.env.NEXT_PUBLIC_REEF_ATLAS_URL || "http://localhost:8080";

export const REEF_POLICY_BUS_ADMIN_URL =
  process.env.NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_URL ||
  "http://localhost:50052";

export const REEF_DAST_A_URL =
  process.env.NEXT_PUBLIC_REEF_DAST_A_URL || "http://localhost:8083";

export const REEF_QUOTE_URL =
  process.env.NEXT_PUBLIC_REEF_QUOTE_URL || "http://localhost:8082";

export const REEF_VICTIM_URL =
  process.env.NEXT_PUBLIC_REEF_VICTIM_URL || "http://localhost:3001";

export const REEF_FLEET_ID =
  process.env.NEXT_PUBLIC_REEF_FLEET_ID || "prod-fleet";

export const REEF_POLICY_BUS_ADMIN_TOKEN =
  process.env.NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_TOKEN || "";

export const REEF_GITHUB_URL = "https://github.com/Yashash4/reef-mcp-registry";
