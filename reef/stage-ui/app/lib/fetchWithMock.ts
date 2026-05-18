/**
 * `fetchWithMock` — single chokepoint for every Stage UI service fetch.
 *
 * Behaviour:
 *   - If `NEXT_PUBLIC_REEF_DEMO_MODE === 'true'` OR the env URL is blank,
 *     skip the network entirely and return the mock with `isMocked = true`.
 *   - Otherwise fetch with a 3 s AbortController timeout. On any failure
 *     (network error, non-OK status, timeout, JSON parse error), fall back
 *     to the mock and set `isMocked = true`.
 *   - When the real fetch succeeds, return `{ data, isMocked: false }`.
 *
 * On the first time any call falls back to the mock, we flip a module-level
 * "demo mode active" flag and dispatch a CustomEvent so the global banner
 * can light up without prop-drilling through 14 components. The flag is
 * sticky for the session — even if subsequent fetches recover, the banner
 * still says "DEMO MODE" because some panel saw a mock at least once.
 */

export interface FetchWithMockOptions extends RequestInit {
  /** Override the default 3 s abort timeout. */
  timeoutMs?: number;
  /** If true, skip the live fetch and return the mock immediately. */
  forceMock?: boolean;
}

export interface FetchWithMockResult<T> {
  data: T;
  isMocked: boolean;
}

// ─── Module-level demo-mode tracker ──────────────────────────────────

const DEMO_MODE_EVENT = "reef:demo-mode-active";
let _demoModeActive = false;

export function isDemoModeActive(): boolean {
  return _demoModeActive;
}

export function subscribeToDemoMode(cb: () => void): () => void {
  if (typeof window === "undefined") return () => {};
  const handler = () => cb();
  window.addEventListener(DEMO_MODE_EVENT, handler);
  return () => window.removeEventListener(DEMO_MODE_EVENT, handler);
}

function markDemoMode(): void {
  if (_demoModeActive) return;
  _demoModeActive = true;
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(DEMO_MODE_EVENT));
  }
}

// ─── Env-driven demo mode opt-in ──────────────────────────────────────

/** Read the env every call — Next inlines `process.env.NEXT_PUBLIC_*` at
 *  build time so this is effectively a constant once the bundle ships. */
function envDemoModeOn(): boolean {
  return process.env.NEXT_PUBLIC_REEF_DEMO_MODE === "true";
}

// ─── The actual wrapper ───────────────────────────────────────────────

export async function fetchWithMock<T>(
  url: string,
  mockData: T,
  options: FetchWithMockOptions = {}
): Promise<FetchWithMockResult<T>> {
  const { timeoutMs = 3000, forceMock = false, ...init } = options;

  // Two ways to skip the network:
  //   - `forceMock` opt-in from the caller
  //   - global demo-mode env flag
  //   - empty URL (production deploy with no backend configured)
  if (forceMock || envDemoModeOn() || !url || url.endsWith("//") || !looksLikeAbsoluteUrl(url)) {
    markDemoMode();
    return { data: mockData, isMocked: true };
  }

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: ctl.signal });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText} on ${url}`);
    }
    const data = (await res.json()) as T;
    return { data, isMocked: false };
  } catch {
    markDemoMode();
    return { data: mockData, isMocked: true };
  } finally {
    clearTimeout(timer);
  }
}

/** Service URLs must be absolute (`http://...` / `https://...`) for the
 *  browser fetch to work. Anything else is treated as "no backend wired"
 *  and falls back to mocks immediately. */
function looksLikeAbsoluteUrl(url: string): boolean {
  return /^https?:\/\//i.test(url);
}
