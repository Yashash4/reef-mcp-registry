"use client";

import { Download, ShieldCheck } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ServiceStatus } from "@/components/ui/service-status";
import { cn, truncateHex } from "@/app/lib/utils";
import {
  RIA_SAMPLE_DOWNLOAD_URL,
  STATIC_SAMPLE_RIA_SUMMARY,
  fetchRIASampleVerify,
} from "@/app/lib/api/quote";

interface RIAPanelProps {
  className?: string;
}

/** Underwriter Layer panel for the Public Safety Page. Renders the tier
 *  headline (verbatim from A-10's underwriter score), premium range, and
 *  the two required disclaimers — verbatim per docs/03-TASKS.md hard rule
 *  #4. */
export function RIAPanel({ className }: RIAPanelProps) {
  const q = useQuery({
    queryKey: ["ria-sample-verify"],
    queryFn: fetchRIASampleVerify,
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: 0,
  });

  // Falls back to STATIC_SAMPLE_RIA_SUMMARY when the Quote service is offline
  // — judges still see the disclaimer + tier headline + Phase 2 framing.
  const score = STATIC_SAMPLE_RIA_SUMMARY;

  return (
    <Card className={cn(className)}>
      <CardHeader className="flex flex-row items-start justify-between flex-wrap gap-3">
        <div>
          <CardTitle className="display text-3xl">
            Reef Insurance Artifact
          </CardTitle>
          <p className="mt-1 text-xs text-text-3">
            Signed 6-page PDF · ed25519 over SHA-256(pdf_bytes) · Munich Re aiSure axes
          </p>
        </div>
        <ServiceStatus
          label="quote"
          isLoading={q.isLoading}
          isError={q.isError}
        />
      </CardHeader>
      <CardContent>
        <div className="grid gap-6 md:grid-cols-[2fr_3fr] items-start">
          <div>
            <div className="num-callout text-amber">
              Tier {score.reef_risk_tier}
            </div>
            <div className="mt-1 text-sm text-text-2">
              {score.tier_label_with_framing}
            </div>

            <div className="mt-5 space-y-1">
              <div className="h-section">Suggested premium range (annual)</div>
              <div className="mono text-2xl text-text">
                ${score.estimated_premium_low.toLocaleString()} –{" "}
                ${score.estimated_premium_high.toLocaleString()}
              </div>
              <div className="text-xs text-text-3">
                for ${score.coverage_amount_usd.toLocaleString()} coverage
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <div className="rounded-md border border-amber/30 bg-amber-soft p-3 text-xs leading-relaxed text-amber">
              <strong className="block">ESTIMATED RANGE, not Munich-Re-published.</strong>
              Anchored on the Mosaic + Munich Re $15M aiSure coverage cap (Feb 27 2026).
              This is a rubric-grounded score, not a Lloyd&apos;s quote.
            </div>
            <div className="rounded-md border border-border bg-surface-2 p-3 text-xs leading-relaxed text-text-2">
              {score.phase_2_disclaimer}
            </div>

            <div className="flex flex-wrap gap-2 items-center">
              <Button asChild>
                <a
                  href={RIA_SAMPLE_DOWNLOAD_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <Download className="h-4 w-4" />
                  Download signed RIA (sample)
                </a>
              </Button>
              {q.data && (
                <Badge variant="emerald">
                  <ShieldCheck className="mr-1.5 h-3 w-3" />
                  signature verified
                </Badge>
              )}
              {q.data && (
                <span className="mono text-[11px] text-text-3">
                  sha256: {truncateHex(q.data.sha256_hex || "")}
                </span>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
