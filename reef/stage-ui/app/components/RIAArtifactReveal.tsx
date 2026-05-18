"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import {
  Download,
  FileCheck2,
  FileText,
  ShieldCheck,
  Sigma,
  TrendingUp,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";
import {
  RIA_SAMPLE_DOWNLOAD_URL,
  STATIC_SAMPLE_RIA_SUMMARY,
} from "@/app/lib/api/quote";
import type { RIAScoreSummary } from "@/app/lib/types";

interface RIAArtifactRevealProps {
  /** Live score summary from A-10. Falls back to STATIC_SAMPLE_RIA_SUMMARY
   *  when Quote service is offline. */
  summary?: RIAScoreSummary;
  sampleMode?: boolean;
  /** Pause/resume control for the scene scripts. */
  paused?: boolean;
  className?: string;
}

type SectionId =
  | "executive"
  | "ai-bom"
  | "coverage"
  | "heatmap"
  | "packs"
  | "audit";

interface SectionDef {
  id: SectionId;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
}

const SECTIONS: SectionDef[] = [
  {
    id: "executive",
    title: "Page 1 — Executive summary",
    subtitle: "Reef Risk Tier mapped to Munich Re aiSure axes",
    icon: <TrendingUp className="h-4 w-4 text-amber" />,
  },
  {
    id: "ai-bom",
    title: "Page 2 — AI-BOM tree",
    subtitle: "Agents · Models · MCP servers · Tools · Policy bundle",
    icon: <Sigma className="h-4 w-4 text-cyan" />,
  },
  {
    id: "coverage",
    title: "Page 3 — Coverage matrix",
    subtitle: "OWASP Agentic Top 10 + MITRE ATLAS (honest 3-state)",
    icon: <ShieldCheck className="h-4 w-4 text-emerald" />,
  },
  {
    id: "heatmap",
    title: "Page 4 — 30-day attack heatmap",
    subtitle: "Real audit JSONL + flagged demo seed days",
    icon: <Sigma className="h-4 w-4 text-violet" />,
  },
  {
    id: "packs",
    title: "Page 5 — DAST-A pack catalog",
    subtitle: "MCP-RCE-26.04 + EchoLeak-26.05 + 2 RL-discovered",
    icon: <FileText className="h-4 w-4 text-cyan" />,
  },
  {
    id: "audit",
    title: "Page 6 — Audit attestation",
    subtitle: "Merkle root + ed25519 signature + Phase 2 commitments",
    icon: <FileCheck2 className="h-4 w-4 text-emerald" />,
  },
];

/**
 * The third-act categorical separator. Renders the 6 sections of the RIA
 * PDF as animated panels — judges see the artifact assemble in real time.
 * At the end: a "Download signed PDF" button linking to the live A-10
 * sample endpoint.
 */
export function RIAArtifactReveal({
  summary,
  sampleMode,
  paused = false,
  className,
}: RIAArtifactRevealProps) {
  const [activeIndex, setActiveIndex] = useState(0);
  const score = summary ?? STATIC_SAMPLE_RIA_SUMMARY;

  useEffect(() => {
    if (paused) return;
    const t = setInterval(() => {
      setActiveIndex((i) => Math.min(i + 1, SECTIONS.length - 1));
    }, 1400);
    return () => clearInterval(t);
  }, [paused]);

  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader>
        <CardTitle className="display text-3xl">
          Reef Insurance Artifact (RIA)
        </CardTitle>
        <div className="flex flex-wrap items-center gap-2 mt-2">
          <Badge variant="amber">{score.tier_label_with_framing}</Badge>
          {sampleMode && <Badge variant="outline">sample mode</Badge>}
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-6 lg:grid-cols-[1fr_2fr]">
          {/* Section selector */}
          <ol className="space-y-2">
            {SECTIONS.map((s, i) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setActiveIndex(i)}
                className={cn(
                  "w-full text-left flex items-start gap-3 rounded-lg border p-3 transition-all",
                  i === activeIndex
                    ? "border-amber/30 bg-amber-soft"
                    : i < activeIndex
                    ? "border-border bg-surface-2 opacity-90"
                    : "border-border-soft bg-surface opacity-60"
                )}
              >
                <div className="mt-0.5 flex h-5 w-5 items-center justify-center rounded-full bg-bg">
                  {s.icon}
                </div>
                <div>
                  <div className="text-xs uppercase tracking-widest text-text-3">
                    {s.title}
                  </div>
                  <div className="mt-0.5 text-sm text-text">{s.subtitle}</div>
                </div>
              </button>
            ))}
          </ol>

          {/* Active panel */}
          <div className="rounded-xl border border-border bg-bg p-6 min-h-[360px]">
            <AnimatePresence mode="wait">
              <motion.div
                key={SECTIONS[activeIndex].id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.4 }}
              >
                {renderSection(SECTIONS[activeIndex].id, score)}
              </motion.div>
            </AnimatePresence>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3">
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
          <p className="text-xs text-text-3 max-w-md">
            {score.phase_2_disclaimer}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function renderSection(id: SectionId, score: RIAScoreSummary): React.ReactNode {
  switch (id) {
    case "executive":
      return (
        <div className="space-y-4">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 1 · Executive summary
          </div>
          <div>
            <div className="num-callout text-amber">
              Reef Risk Tier {score.reef_risk_tier}
            </div>
            <div className="mt-2 text-sm text-text-2">
              {score.tier_label_with_framing}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-md border border-border bg-surface-2 p-3">
              <div className="text-[10px] uppercase tracking-widest text-text-3">
                Estimated premium (annual)
              </div>
              <div className="mt-1 mono text-lg text-text">
                ${score.estimated_premium_low.toLocaleString()} –{" "}
                ${score.estimated_premium_high.toLocaleString()}
              </div>
            </div>
            <div className="rounded-md border border-border bg-surface-2 p-3">
              <div className="text-[10px] uppercase tracking-widest text-text-3">
                Coverage
              </div>
              <div className="mt-1 mono text-lg text-text">
                ${score.coverage_amount_usd.toLocaleString()}
              </div>
            </div>
          </div>
          <p className="text-xs leading-relaxed text-text-3">
            <strong className="text-amber">ESTIMATED RANGE, not Munich-Re-published.</strong>{" "}
            Anchored on the Mosaic + Munich Re $15M aiSure coverage cap (Feb 27 2026).
            This is a rubric-grounded score, not a Lloyd&apos;s quote.
          </p>
        </div>
      );
    case "ai-bom":
      return (
        <div className="space-y-4">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 2 · AI Bill of Materials
          </div>
          <ul className="space-y-2 mono text-xs">
            {[
              "├─ agent: copilot-victim · svid: spiffe://reef.test/copilot",
              "│  ├─ model: gemini-3-flash",
              "│  └─ tool: summarize_inbox + fetch_url",
              "├─ mcp_server: com.legit/calendar@1.2.0 (signed by acme-publisher)",
              "├─ mcp_server: com.legit/docs@2.0.1 (signed by acme-publisher)",
              "├─ mcp_server: com.attacker/evil-server@0.5.0 (POISONED — MCP-RCE-26.04)",
              "└─ policy_bundle: v3 · ed25519 by publisher-prod · 49 nodes acked",
            ].map((row, i) => (
              <motion.li
                key={row}
                initial={{ opacity: 0, x: -6 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className="text-text-2"
              >
                {row}
              </motion.li>
            ))}
          </ul>
        </div>
      );
    case "coverage":
      return (
        <div className="space-y-4">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 3 · OWASP Agentic Top 10 coverage (honest 3-state)
          </div>
          <div className="grid grid-cols-5 gap-2">
            {[
              ["ASI01", "full"],
              ["ASI02", "full"],
              ["ASI03", "partial"],
              ["ASI04", "partial"],
              ["ASI05", "full"],
              ["ASI06", "full"],
              ["ASI07", "partial"],
              ["ASI08", "none"],
              ["ASI09", "full"],
              ["ASI10", "full"],
            ].map(([asi, state], i) => (
              <motion.div
                key={asi}
                initial={{ scale: 0.85, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ delay: i * 0.04 }}
                className={cn(
                  "rounded-md border p-2 text-center",
                  state === "full" && "border-emerald/30 bg-emerald-soft text-emerald",
                  state === "partial" && "border-amber/30 bg-amber-soft text-amber",
                  state === "none" && "border-border bg-surface-2 text-text-3"
                )}
              >
                <div className="mono text-xs font-semibold">{asi}</div>
                <div className="mt-1 text-[10px] uppercase tracking-widest">
                  {state}
                </div>
              </motion.div>
            ))}
          </div>
          <p className="text-xs text-text-3">
            Honest gap declaration: ASI08 Resource Hijacking is{" "}
            <span className="text-text-2">not yet covered</span> — see Phase 2
            roadmap for per-identity rate-limit hardening.
          </p>
        </div>
      );
    case "heatmap":
      return (
        <div className="space-y-4">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 4 · 30-day attack heatmap
          </div>
          <div className="grid grid-cols-15 gap-0.5" style={{ gridTemplateColumns: "repeat(15, minmax(0, 1fr))" }}>
            {Array.from({ length: 30 * 4 }).map((_, i) => {
              const intensity = (Math.sin(i * 0.7) + 1) / 2;
              const isDemo = i % 7 === 3;
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.005 }}
                  className="aspect-square rounded-sm"
                  style={{
                    background: isDemo
                      ? `rgba(245,158,11,${0.15 + intensity * 0.45})`
                      : `rgba(16,185,129,${0.12 + intensity * 0.55})`,
                  }}
                  title={isDemo ? "demo seed day" : "real audit day"}
                />
              );
            })}
          </div>
          <p className="text-xs text-text-3">
            Amber cells = clearly-flagged synthetic seed days. Emerald = real
            audit JSONL aggregations (rolling 30-day window).
          </p>
        </div>
      );
    case "packs":
      return (
        <div className="space-y-3">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 5 · DAST-A attack pack catalog
          </div>
          {[
            ["MCP-RCE-26.04", "MCP STDIO Command Execution", "OX Security Apr 16 2026"],
            ["EchoLeak-26.05", "Zero-Click Copilot Markdown Exfil", "CVE-2025-32711"],
            ["MarkdownExfil-26.05", "RL-found markdown image exfil", "DAST-A synthetic"],
            ["ToolChain-Drift-26.04", "Multi-turn ASI-EWMA drift", "DAST-A synthetic"],
          ].map(([id, name, source], i) => (
            <motion.div
              key={id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.08 }}
              className="rounded-md border border-border bg-surface-2 p-3"
            >
              <div className="flex items-center justify-between">
                <span className="mono text-xs text-amber">{id}</span>
                <Badge variant="emerald">blocked by Reef</Badge>
              </div>
              <div className="mt-1 text-sm text-text">{name}</div>
              <div className="text-[10px] uppercase tracking-widest text-text-3 mt-1">
                {source}
              </div>
            </motion.div>
          ))}
        </div>
      );
    case "audit":
      return (
        <div className="space-y-3">
          <div className="text-xs uppercase tracking-widest text-text-3">
            Page 6 · Audit attestation
          </div>
          <div className="rounded-md border border-border bg-surface-2 p-4 mono text-xs">
            <TypewriterBlock
              lines={[
                "Reef Audit Root",
                "  merkle_root: 0xa1b2c3d4e5f6…",
                "  signed_by:   reef-audit-signer · ed25519",
                "  event_count: 14,217",
                "  signed_at:   2026-05-18T07:55:13Z",
                "  verify:      lobstertrap audit verify --event-id <id>",
              ]}
            />
          </div>
          <div className="rounded-md border border-amber/30 bg-amber-soft p-3 text-xs leading-relaxed text-amber">
            Phase 2 commitments (mention-only):
            <ul className="mt-1 ml-4 list-disc text-text-2">
              <li>Real broker API integration (Bold Penguin / CoverGenius / Vouch)</li>
              <li>Real TerraFabric SDK</li>
              <li>A2A delegation with monotonic scope narrowing</li>
              <li>Full SPIFFE/SPIRE + live Rekor anchoring</li>
            </ul>
          </div>
        </div>
      );
  }
}

function TypewriterBlock({ lines }: { lines: string[] }) {
  return (
    <div>
      {lines.map((l, i) => (
        <motion.div
          key={i}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: i * 0.18, duration: 0.3 }}
          className="text-text-2"
        >
          {l}
        </motion.div>
      ))}
    </div>
  );
}
