"use client";

import { Github } from "lucide-react";
import { REEF_GITHUB_URL } from "@/app/lib/env";
import { Badge } from "@/components/ui/badge";

interface FooterProps {
  deployedAt?: string;
}

export function Footer({ deployedAt }: FooterProps) {
  const ts = deployedAt ?? new Date().toISOString();
  return (
    <footer className="mt-16 border-t border-border-soft pt-8 pb-12 text-xs text-text-3">
      <div className="flex flex-wrap items-center gap-3 justify-between">
        <div className="flex items-center gap-3">
          <a
            href={REEF_GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 hover:text-text transition-colors"
          >
            <Github className="h-3.5 w-3.5" />
            {REEF_GITHUB_URL.replace("https://github.com/", "")}
          </a>
          <Badge variant="outline">MIT licensed</Badge>
          <span>·</span>
          <span>v0.1.0</span>
        </div>
        <div className="mono">last deploy: {ts}</div>
      </div>
      <div className="mt-3 text-text-3/70 max-w-3xl">
        Reef is open-source MIT. Phase 2 commitments (real broker API, real
        TerraFabric SDK, A2A delegation with monotonic scope narrowing, full
        SPIFFE/SPIRE + Rekor) are not built in v1. All disclaimers on this page
        are verbatim from the underwriter agent system prompt — see
        <code className="mono mx-1">reef/control-plane/quote/app/rubrics/</code>.
      </div>
    </footer>
  );
}
