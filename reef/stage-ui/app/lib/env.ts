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
 *
 * When `NEXT_PUBLIC_REEF_DEMO_MODE=true` (e.g. Vercel preview / production
 * with no backend), the localhost fallbacks are SUPPRESSED — every URL
 * returns the empty string. That keeps a remote visitor from ever seeing
 * a broken `http://localhost:NNNN` URL leak into iframes, error banners,
 * or visible labels. `fetchWithMock` already short-circuits on an empty
 * URL, so the data path is unaffected — only direct URL consumers (iframes,
 * error strings) need to guard with `REEF_DEMO_MODE ? null : src` and show
 * a placeholder when the URL is blank.
 */

const DEMO_MODE = process.env.NEXT_PUBLIC_REEF_DEMO_MODE === "true";

/** In demo mode we return an empty string instead of the localhost
 *  fallback. Direct consumers (iframes, error messages, anchor hrefs) must
 *  check the URL is non-empty before using it; `fetchWithMock` already
 *  treats empty URLs as "use the mock". */
const fallback = (url: string) => (DEMO_MODE ? "" : url);

export const REEF_ATLAS_URL =
  process.env.NEXT_PUBLIC_REEF_ATLAS_URL || fallback("http://localhost:8080");

export const REEF_POLICY_BUS_ADMIN_URL =
  process.env.NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_URL ||
  fallback("http://localhost:50052");

export const REEF_DAST_A_URL =
  process.env.NEXT_PUBLIC_REEF_DAST_A_URL || fallback("http://localhost:8083");

export const REEF_QUOTE_URL =
  process.env.NEXT_PUBLIC_REEF_QUOTE_URL || fallback("http://localhost:8082");

export const REEF_VICTIM_URL =
  process.env.NEXT_PUBLIC_REEF_VICTIM_URL || fallback("http://localhost:3001");

export const REEF_FLEET_ID =
  process.env.NEXT_PUBLIC_REEF_FLEET_ID || "prod-fleet";

export const REEF_POLICY_BUS_ADMIN_TOKEN =
  process.env.NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_TOKEN || "";

export const REEF_GITHUB_URL = "https://github.com/Yashash4/reef-mcp-registry";

/** True when the app is running in static / no-backend mode. Components
 *  that render direct URLs (iframes, error banners, anchor hrefs) should
 *  branch on this to show a styled placeholder instead of a broken URL. */
export const REEF_DEMO_MODE = DEMO_MODE;
