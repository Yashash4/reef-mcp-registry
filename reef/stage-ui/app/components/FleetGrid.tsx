"use client";

import { motion } from "framer-motion";
import { useMemo } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn, formatUnixTime } from "@/app/lib/utils";
import type { AckStatus, NodeRecord } from "@/app/lib/types";

interface FleetGridProps {
  nodes: NodeRecord[];
  /** When set, the most-recently-acked node's apply_unix drives the
   *  stadium wave order. Each cell's animation delay = rank-based offset
   *  so the wave ripples through the grid in last_ack_unix order. */
  rippleEnabled?: boolean;
  /** Visual size — px. Default keeps 7×7 grid roughly 168 px. */
  size?: number;
  className?: string;
}

const STATUS_COLOR: Record<AckStatus, string> = {
  applied: "bg-emerald",
  verify_failed: "bg-red",
  policy_parse_failed: "bg-red",
  kept_old_active: "bg-amber",
  scope_mismatch: "bg-violet",
  unknown: "bg-text-3",
};

const STATUS_LABEL: Record<AckStatus, string> = {
  applied: "applied",
  verify_failed: "verify failed",
  policy_parse_failed: "policy parse failed",
  kept_old_active: "kept old active (fail-safe)",
  scope_mismatch: "out of scope",
  unknown: "unknown / never acked",
};

/**
 * Render the 49-node fleet as a 7×7 grid of dots. Color encodes the
 * last_ack_status. Hover tooltip surfaces full node identity. When
 * `rippleEnabled` is true, a stadium-wave animation ripples through the
 * grid ordered by last_ack_unix.
 *
 * This grid is the GIF moment of the demo arc — when a signed bundle
 * propagates across the 49 nodes, every dot flashes emerald in last_ack
 * order. The wave is driven by REAL data from policy-bus /fleet.
 */
export function FleetGrid({
  nodes,
  rippleEnabled = true,
  size = 240,
  className,
}: FleetGridProps) {
  // Sort once for stable cell positions. We layout by region/site/node
  // so the grid is deterministic regardless of dict-iteration order.
  const sorted = useMemo(() => {
    return [...nodes].sort((a, b) => {
      const keyA = `${a.identity.region_id}/${a.identity.site_id}/${a.identity.node_id}`;
      const keyB = `${b.identity.region_id}/${b.identity.site_id}/${b.identity.node_id}`;
      return keyA.localeCompare(keyB);
    });
  }, [nodes]);

  // Rank each node by last_ack_unix to drive the stadium wave order. Nodes
  // never-acked stay at rank 0 (no animation delay).
  const rankByKey = useMemo(() => {
    const ranked = [...sorted]
      .filter((n) => n.last_ack_unix > 0)
      .sort((a, b) => a.last_ack_unix - b.last_ack_unix);
    const map = new Map<string, number>();
    ranked.forEach((n, i) => {
      map.set(
        `${n.identity.region_id}/${n.identity.site_id}/${n.identity.node_id}`,
        i
      );
    });
    return map;
  }, [sorted]);

  // Pad or trim to exactly 49 cells so the 7×7 grid is always full.
  const padded = useMemo(() => {
    const PLACEHOLDER: NodeRecord = {
      identity: {
        fleet_id: "—",
        region_id: "—",
        site_id: "—",
        node_id: "—",
      },
      last_applied_version: "",
      last_applied_bundle_id: "",
      last_ack_status: "unknown",
      last_ack_detail: "",
      last_ack_unix: 0,
      last_subscribe_unix: 0,
      online: false,
    };
    if (sorted.length >= 49) return sorted.slice(0, 49);
    const fill = Array.from({ length: 49 - sorted.length }, () => PLACEHOLDER);
    return [...sorted, ...fill];
  }, [sorted]);

  return (
    <TooltipProvider delayDuration={120}>
      <div
        className={cn("grid grid-cols-7 gap-1.5 p-1", className)}
        style={{ width: size, height: size }}
      >
        {padded.map((n, i) => {
          const key = `${n.identity.region_id}/${n.identity.site_id}/${n.identity.node_id}/${i}`;
          const rank = rankByKey.get(
            `${n.identity.region_id}/${n.identity.site_id}/${n.identity.node_id}`
          );
          const delay = rippleEnabled && rank !== undefined ? rank * 0.04 : 0;
          const cls = STATUS_COLOR[n.last_ack_status];
          const isReal = n.identity.fleet_id !== "—";

          return (
            <Tooltip key={key}>
              <TooltipTrigger asChild>
                <motion.div
                  initial={{ opacity: 0.3, scale: 0.92 }}
                  animate={{
                    opacity: isReal ? (n.online ? 1 : 0.55) : 0.18,
                    scale: 1,
                  }}
                  transition={{
                    delay,
                    duration: 0.6,
                    type: "spring",
                    stiffness: 220,
                  }}
                  className={cn(
                    "aspect-square rounded-md cursor-pointer transition-shadow",
                    isReal ? cls : "bg-border-soft",
                    n.last_ack_status === "applied" && "hover:shadow-[0_0_18px_-2px_currentColor] text-emerald"
                  )}
                  aria-label={`Node ${n.identity.node_id} — ${STATUS_LABEL[n.last_ack_status]}`}
                />
              </TooltipTrigger>
              <TooltipContent side="top">
                <div className="space-y-0.5 font-mono text-[11px]">
                  <div className="text-text">
                    {n.identity.region_id}/{n.identity.site_id}/{n.identity.node_id}
                  </div>
                  <div className="text-text-3">
                    status: {STATUS_LABEL[n.last_ack_status]}
                  </div>
                  <div className="text-text-3">
                    version: {n.last_applied_version || "—"}
                  </div>
                  <div className="text-text-3">
                    last ack: {formatUnixTime(n.last_ack_unix)}
                  </div>
                  <div className="text-text-3">
                    online: {n.online ? "yes" : "no"}
                  </div>
                </div>
              </TooltipContent>
            </Tooltip>
          );
        })}
      </div>
    </TooltipProvider>
  );
}

/**
 * Deterministic stadium-wave trigger — used by the recorded demo (cold-open
 * scene) when no real bundle is propagating. It synthesises a snapshot
 * where each node's last_ack_unix is staggered by a small offset so the
 * `FleetGrid` ripple animation plays in a clean wave.
 *
 * Driven by `Date.now()` rounded down so consecutive frames stay stable.
 *
 * // DEMO PATH — deterministic stadium-wave trigger for video capture
 */
export function buildDemoFleetSnapshot(
  fleetId: string = "prod-fleet"
): NodeRecord[] {
  const now = Math.floor(Date.now() / 1000);
  const regions = ["us-east", "us-west", "eu-west"];
  const out: NodeRecord[] = [];
  let counter = 0;
  for (let r = 0; r < 3; r++) {
    for (let s = 1; s <= 7; s++) {
      for (let n = 1; n <= 7; n++) {
        counter += 1;
        if (counter > 49) break;
        out.push({
          identity: {
            fleet_id: fleetId,
            region_id: regions[r],
            site_id: `site-${String(s).padStart(2, "0")}`,
            node_id: `node-${String(s).padStart(2, "0")}-${String(n).padStart(
              2,
              "0"
            )}`,
            svid_subject: "",
          },
          // last_ack_unix walks forward by 40ms per node so the ripple
          // order is left-to-right top-to-bottom.
          last_applied_version: "v3",
          last_applied_bundle_id: "demo-bundle-v3",
          last_ack_status: "applied",
          last_ack_detail: "",
          last_ack_unix: now - 5 + counter * 0.04,
          last_subscribe_unix: now,
          online: true,
        });
      }
    }
  }
  return out;
}

/** Compact legend used under the grid on the Public Safety Page. */
export function FleetGridLegend() {
  const items: { color: string; label: string }[] = [
    { color: "bg-emerald", label: "applied" },
    { color: "bg-amber", label: "kept old active (fail-safe)" },
    { color: "bg-red", label: "verify failed / parse failed" },
    { color: "bg-violet", label: "scope mismatch" },
    { color: "bg-text-3", label: "unknown / offline" },
  ];
  return (
    <div className="flex flex-wrap items-center gap-3 text-[11px] text-text-3">
      {items.map((i) => (
        <div key={i.label} className="flex items-center gap-1.5">
          <span className={cn("inline-block h-2 w-2 rounded-sm", i.color)} />
          <span>{i.label}</span>
        </div>
      ))}
    </div>
  );
}
