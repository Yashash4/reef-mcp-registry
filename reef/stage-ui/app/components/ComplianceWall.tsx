"use client";

import { Check, CircleDashed, Minus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/app/lib/utils";

type Coverage = "full" | "partial" | "none";

interface ComplianceItem {
  id: string;
  label: string;
  coverage: Coverage;
  note?: string;
}

interface ComplianceSection {
  title: string;
  items: ComplianceItem[];
}

const SECTIONS: ComplianceSection[] = [
  {
    title: "OWASP Agentic Top 10 (ASI01-10)",
    items: [
      { id: "ASI01", label: "Memory Poisoning", coverage: "full" },
      { id: "ASI02", label: "Tool Misuse", coverage: "full" },
      { id: "ASI03", label: "Cascading Failures", coverage: "partial", note: "EWMA covers; chain isolation Phase 2" },
      { id: "ASI04", label: "Privilege Compromise", coverage: "partial", note: "SVID scopes today; A2A scope-narrow Phase 2" },
      { id: "ASI05", label: "Goal Manipulation", coverage: "full" },
      { id: "ASI06", label: "Tool Misuse (alt)", coverage: "full" },
      { id: "ASI07", label: "Identity Spoofing", coverage: "partial", note: "JWT SVID; full SPIFFE/SPIRE Phase 2" },
      { id: "ASI08", label: "Resource Hijacking", coverage: "none", note: "Phase 2 — rate-limit per-identity only; deeper coverage in Phase 2." },
      { id: "ASI09", label: "Misaligned Behaviors", coverage: "full" },
      { id: "ASI10", label: "Capability Abuse", coverage: "full" },
    ],
  },
  {
    title: "MITRE ATLAS (techniques mapped)",
    items: [
      { id: "AML.T0010", label: "ML Supply Chain Compromise", coverage: "full", note: "Layer 1 — signed MCP registry" },
      { id: "AML.T0040", label: "ML Model Access (via API)", coverage: "partial", note: "DPI on prompts; model-extract Phase 2" },
      { id: "AML.T0050", label: "Command and Scripting Interpreter", coverage: "full", note: "MCP STDIO entrypoint hash" },
      { id: "AML.T0051", label: "LLM Prompt Injection", coverage: "full" },
    ],
  },
  {
    title: "EU AI Act + NIST",
    items: [
      {
        id: "EU-AI Art. 12",
        label: "Logging for high-risk AI systems",
        coverage: "full",
        note: "Merkle tree + signed audit root",
      },
      {
        id: "NIST AI RMF GV-1.4",
        label: "Risk governance accountability",
        coverage: "full",
        note: "RIA artifact + SVID identity binding",
      },
      {
        id: "NIST AI RMF MS-2.5",
        label: "Risk treatment monitoring",
        coverage: "partial",
        note: "Block-rate + heatmap; FP-rate measurement in Phase 2.",
      },
    ],
  },
];

interface ComplianceWallProps {
  className?: string;
}

/** Honest 3-state coverage wall. Matches the RIA page 3 classifier so the
 *  Stage UI never claims more coverage than the PDF does. */
export function ComplianceWall({ className }: ComplianceWallProps) {
  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="display text-2xl">Compliance wall</CardTitle>
        <p className="mt-1 text-xs text-text-3">
          Coverage classifier (full / partial / none) is honest about gaps —
          mirrors the same 3-state from the RIA PDF page 3.
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        {SECTIONS.map((s) => (
          <section key={s.title}>
            <div className="h-section mb-3">{s.title}</div>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {s.items.map((i) => (
                <ComplianceCell key={i.id} item={i} />
              ))}
            </div>
          </section>
        ))}
      </CardContent>
    </Card>
  );
}

function ComplianceCell({ item }: { item: ComplianceItem }) {
  const palette = {
    full: {
      icon: <Check className="h-4 w-4 text-emerald" />,
      cls: "border-emerald/25 bg-emerald-soft",
      tag: "full",
    },
    partial: {
      icon: <CircleDashed className="h-4 w-4 text-amber" />,
      cls: "border-amber/25 bg-amber-soft",
      tag: "partial",
    },
    none: {
      icon: <Minus className="h-4 w-4 text-text-3" />,
      cls: "border-border bg-surface-2",
      tag: "Phase 2",
    },
  }[item.coverage];

  return (
    <div className={cn("rounded-md border p-3 text-sm", palette.cls)}>
      <div className="flex items-start gap-2">
        <div className="mt-0.5">{palette.icon}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="mono text-xs text-text-2">{item.id}</span>
            <span className="text-[10px] uppercase tracking-widest text-text-3">
              {palette.tag}
            </span>
          </div>
          <div className="mt-0.5 text-text">{item.label}</div>
          {item.note && (
            <div className="mt-1 text-xs text-text-3">{item.note}</div>
          )}
        </div>
      </div>
    </div>
  );
}
