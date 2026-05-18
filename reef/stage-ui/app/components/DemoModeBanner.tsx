"use client";

import { useEffect, useState } from "react";
import {
  isDemoModeActive,
  subscribeToDemoMode,
} from "@/app/lib/fetchWithMock";

/**
 * DEMO MODE banner — sticky amber bar that lights up when any panel has
 * fallen back to mocked data. Driven by the module-level demo-mode flag
 * in `app/lib/fetchWithMock.ts`. Sticks across the session so judges
 * always know they're looking at canned data, even if a subsequent fetch
 * happens to recover.
 *
 * In production (Vercel deploy with no backend URLs) the env var
 * `NEXT_PUBLIC_REEF_DEMO_MODE=true` short-circuits every API call to its
 * mock — the banner lights up on the first render.
 */
export function DemoModeBanner() {
  // Read env synchronously so the banner is present on SSR if we're
  // explicitly in env-driven demo mode (Vercel deploy).
  const initialOn =
    typeof process !== "undefined" &&
    process.env.NEXT_PUBLIC_REEF_DEMO_MODE === "true";

  const [active, setActive] = useState<boolean>(initialOn);
  const [dismissed, setDismissed] = useState<boolean>(false);

  useEffect(() => {
    // Pick up any fetches that may have already flipped the flag before
    // this component mounted (unlikely but defensive).
    if (isDemoModeActive()) setActive(true);
    const unsubscribe = subscribeToDemoMode(() => setActive(true));
    return unsubscribe;
  }, []);

  if (!active || dismissed) return null;

  return (
    <div
      className="sticky top-0 z-50 border-b border-amber/30 bg-amber-soft backdrop-blur-md"
      role="status"
      aria-live="polite"
    >
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-10 py-2.5 flex items-center justify-between gap-4">
        <div className="flex items-center gap-3 text-sm">
          <span
            className="inline-flex items-center justify-center h-5 px-2 rounded-md bg-amber/20 text-amber font-mono text-[10px] uppercase tracking-widest border border-amber/40"
            aria-hidden
          >
            Demo Mode
          </span>
          <span className="text-text-2">
            Backend services unreachable. Data is mocked but realistic — every
            shape matches the production pydantic models.{" "}
            <span className="text-text-3">
              Run the full stack locally with{" "}
              <code className="font-mono text-[12px] px-1 py-0.5 rounded bg-surface-2 border border-border text-amber/90">
                docker compose up
              </code>{" "}
              for live numbers.
            </span>
          </span>
        </div>
        <button
          type="button"
          onClick={() => setDismissed(true)}
          className="shrink-0 text-text-3 hover:text-text transition-colors text-xs font-mono uppercase tracking-wider"
          aria-label="Dismiss demo mode banner"
        >
          dismiss
        </button>
      </div>
    </div>
  );
}
