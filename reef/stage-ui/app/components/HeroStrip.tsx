"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";

interface HeroStripProps {
  className?: string;
}

/** Top-of-page hero. Renders the Reef wordmark + dinner sentence + three
 *  context chips. Locked typography: Instrument Serif italic for the
 *  display headline, Inter for the dinner sentence. */
export function HeroStrip({ className }: HeroStripProps) {
  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-3xl border border-border bg-surface px-8 py-10 md:px-12 md:py-14",
        className
      )}
    >
      {/* Subtle grid backdrop */}
      <div className="absolute inset-0 grid-bg opacity-40 pointer-events-none" />
      <div className="absolute top-0 right-0 h-64 w-64 -translate-y-1/4 translate-x-1/4 rounded-full bg-emerald/10 blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 h-72 w-72 translate-y-1/4 -translate-x-1/4 rounded-full bg-cyan/10 blur-3xl pointer-events-none" />

      <div className="relative">
        <div className="flex items-center gap-2 text-text-3 mono text-xs uppercase tracking-widest">
          <ReefMark />
          <span>reef · v0.1.0</span>
          <span>·</span>
          <span>public safety page</span>
        </div>

        <h1 className="display mt-6 text-5xl md:text-6xl lg:text-7xl leading-[0.95] text-text">
          The signed supply chain
          <br />
          for <em className="text-emerald not-italic font-normal">MCP</em>{" "}
          servers.
        </h1>

        {/* Slack-able category line — Batch D R-D7. Matches the cold-open
         *  closing card so the public page and the recorded video carry the
         *  same sticky line. Stays under 30 words, one beat. */}
        <p className="mt-6 max-w-3xl display text-2xl md:text-3xl text-text-2 leading-snug">
          Signed MCP. Insurable AI. Open source. Blocked the April{" "}
          <span className="text-text">Anthropic RCE</span>. Outputs the audit
          your <span className="text-text">underwriter</span> can price.
        </p>

        <p className="mt-6 max-w-3xl text-base md:text-lg text-text-2 leading-relaxed">
          They built the signed supply chain for MCP servers — blocked the{" "}
          <span className="text-text">April 2026 Anthropic MCP exploit</span>{" "}
          at handshake, also reproduced the{" "}
          <span className="text-text">Microsoft Copilot zero-click</span>, ship
          the only signed AI-BOM your underwriter can score, and contributed the
          4 missing actions back to Lobster Trap upstream.{" "}
          <em className="text-text-3 not-italic">Open source. Edge. Insurable.</em>
        </p>

        <div className="mt-8 flex flex-wrap gap-2">
          <Badge variant="emerald">TechEx 2026</Badge>
          <Badge variant="cyan">Track 1 · Veea + Gemini theme</Badge>
          <Badge variant="amber">v0.1.0 · live</Badge>
        </div>
      </div>
    </section>
  );
}

function ReefMark() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={18}
      height={18}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      className="text-emerald"
      aria-hidden
    >
      <path d="M3 20 Q7 8 12 16 Q17 24 21 12" />
      <circle cx="6" cy="14" r="1" />
      <circle cx="18" cy="14" r="1" />
      <circle cx="12" cy="11" r="1.4" />
    </svg>
  );
}
