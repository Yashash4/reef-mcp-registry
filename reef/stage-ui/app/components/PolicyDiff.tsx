"use client";

import { motion } from "framer-motion";
import { ArrowRight, Equal, Minus, Plus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/app/lib/utils";
import {
  diffRules,
  type PolicyDiffLine,
  type PolicyRule,
} from "@/app/lib/policy-translator";

interface PolicyDiffProps {
  oldRules: PolicyRule[];
  newRules: PolicyRule[];
  bundleHash?: string;
  signerKeyId?: string;
  title?: string;
  className?: string;
}

/** Plain-English policy diff renderer.
 *
 *  Per docs/10-DECISIONS.md D-019: judges should NEVER see raw YAML on the
 *  projector. This component renders +/-/= lines as human-readable
 *  sentences. The translator switch-table lives in
 *  app/lib/policy-translator.ts. */
export function PolicyDiff({
  oldRules,
  newRules,
  bundleHash,
  signerKeyId,
  title = "Signed policy update — plain English",
  className,
}: PolicyDiffProps) {
  const lines = diffRules(oldRules, newRules);
  const added = lines.filter((l) => l.side === "+").length;
  const removed = lines.filter((l) => l.side === "-").length;

  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="display text-2xl">{title}</CardTitle>
        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-text-3">
          {bundleHash && (
            <span className="mono">
              bundle sha256: {bundleHash.slice(0, 16)}…
            </span>
          )}
          {signerKeyId && (
            <span className="mono">signed by: {signerKeyId}</span>
          )}
          <span>·</span>
          <span>
            <span className="text-emerald">+{added}</span> /{" "}
            <span className="text-red">-{removed}</span>
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <ul className="space-y-2">
          {lines.map((line, i) => (
            <DiffLineRow key={i} line={line} index={i} />
          ))}
          {lines.length === 0 && (
            <li className="text-sm text-text-3">
              (no policy delta — both bundles identical)
            </li>
          )}
        </ul>
      </CardContent>
    </Card>
  );
}

function DiffLineRow({ line, index }: { line: PolicyDiffLine; index: number }) {
  const palette: Record<PolicyDiffLine["side"], { icon: React.ReactNode; cls: string }> =
    {
      "+": {
        icon: <Plus className="h-3.5 w-3.5 text-emerald" />,
        cls: "border-emerald/20 bg-emerald-soft",
      },
      "-": {
        icon: <Minus className="h-3.5 w-3.5 text-red" />,
        cls: "border-red/20 bg-red-soft",
      },
      "=": {
        icon: <Equal className="h-3.5 w-3.5 text-text-3" />,
        cls: "border-border bg-surface-2",
      },
    };
  const p = palette[line.side];
  return (
    <motion.li
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.06, duration: 0.3 }}
      className={cn("flex items-start gap-2 rounded-md border p-2.5", p.cls)}
    >
      <span className="mt-0.5 flex h-5 w-5 flex-shrink-0 items-center justify-center">
        {p.icon}
      </span>
      <span className="text-sm leading-snug text-text">{line.text}</span>
    </motion.li>
  );
}

/** Compact diff used inline as a "before → after" example chip. */
export function PolicyDiffInline({
  before,
  after,
}: {
  before: string;
  after: string;
}) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="rounded bg-red-soft px-2 py-0.5 text-red line-through">
        {before}
      </span>
      <ArrowRight className="h-3 w-3 text-text-3" />
      <span className="rounded bg-emerald-soft px-2 py-0.5 text-emerald">
        {after}
      </span>
    </div>
  );
}
