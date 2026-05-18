"use client";

import { useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ServiceStatus } from "@/components/ui/service-status";
import { Badge } from "@/components/ui/badge";
import { FleetGrid, FleetGridLegend } from "./FleetGrid";
import { useFleet } from "@/app/lib/hooks/use-fleet";
import { useAtlasHealth } from "@/app/lib/hooks/use-atlas-health";
import { usePolicyBusHealth } from "@/app/lib/hooks/use-policy-bus-health";
import { truncateHex, formatUnixTime } from "@/app/lib/utils";

interface FleetStatusPanelProps {
  className?: string;
}

/** Live fleet status — composes FleetGrid + counters from Atlas + bundle
 *  metadata from policy bus. The visual centerpiece of the Public Safety
 *  Page. */
export function FleetStatusPanel({ className }: FleetStatusPanelProps) {
  const fleet = useFleet();
  const atlas = useAtlasHealth();
  const bus = usePolicyBusHealth();

  // Compute fleet-level ack counters from the snapshot
  const ackCounts = useMemo(() => {
    const c = { applied: 0, kept: 0, failed: 0, unknown: 0 };
    for (const n of fleet.nodes) {
      if (n.last_ack_status === "applied") c.applied += 1;
      else if (n.last_ack_status === "kept_old_active") c.kept += 1;
      else if (
        n.last_ack_status === "verify_failed" ||
        n.last_ack_status === "policy_parse_failed" ||
        n.last_ack_status === "scope_mismatch"
      )
        c.failed += 1;
      else c.unknown += 1;
    }
    return c;
  }, [fleet.nodes]);

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-start justify-between flex-wrap gap-3">
        <div>
          <CardTitle className="display text-3xl">Live fleet status</CardTitle>
          <p className="mt-1 text-xs text-text-3">
            7×7 stadium-wave grid · 49 nodes across 3 regions · refresh every 5 s
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <ServiceStatus
            label="policy-bus"
            isLoading={bus.isLoading}
            isError={bus.isError}
          />
          <ServiceStatus
            label="atlas"
            isLoading={atlas.isLoading}
            isError={atlas.isError}
          />
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid gap-8 lg:grid-cols-[auto_1fr] items-start">
          <div className="flex flex-col gap-3 items-center">
            <FleetGrid nodes={fleet.nodes} size={280} />
            <FleetGridLegend />
          </div>

          <div className="grid gap-3 md:grid-cols-2">
            <Stat
              label="MCP servers verified"
              value={atlas.verified}
              tone="emerald"
            />
            <Stat
              label="MCP quarantined / poisoned"
              value={`${atlas.quarantined} / ${atlas.poisoned}`}
              tone="amber"
            />
            <Stat
              label="Nodes applied current bundle"
              value={`${ackCounts.applied} / ${fleet.snapshot?.node_count ?? 49}`}
              tone="emerald"
            />
            <Stat
              label="Nodes kept old active (fail-safe)"
              value={ackCounts.kept}
              tone="amber"
            />
            <Stat
              label="Active subscribers"
              value={bus.health?.active_subscribers ?? "—"}
              tone="cyan"
            />
            <Stat
              label="Total signed bundles"
              value={bus.health?.active_bundles ?? "—"}
              tone="violet"
            />

            <div className="md:col-span-2 rounded-lg border border-border bg-surface-2 p-3">
              <div className="h-section mb-2">Current signed policy</div>
              {bus.currentBundle ? (
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="emerald">
                      v{bus.currentBundle.version}
                    </Badge>
                    <span className="mono text-xs text-text-2">
                      {bus.currentBundle.bundle_id}
                    </span>
                  </div>
                  <div className="mono text-[11px] text-text-3">
                    signer: {bus.currentBundle.signer_key_id}
                    {bus.currentBundle.signer_fingerprint
                      ? ` · ${truncateHex(
                          bus.currentBundle.signer_fingerprint
                        )}`
                      : ""}
                  </div>
                  <div className="mono text-[11px] text-text-3">
                    published: {formatUnixTime(bus.currentBundle.published_at_unix)}
                  </div>
                  {bus.currentBundle.bundle_sha256_hex && (
                    <div className="mono text-[11px] text-text-3">
                      sha256: {truncateHex(bus.currentBundle.bundle_sha256_hex)}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-xs text-text-3">
                  no bundles published yet
                </div>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

interface StatProps {
  label: string;
  value: string | number;
  tone: "emerald" | "amber" | "cyan" | "violet" | "red";
}
function Stat({ label, value, tone }: StatProps) {
  const toneCls = {
    emerald: "text-emerald",
    amber: "text-amber",
    cyan: "text-cyan",
    violet: "text-violet",
    red: "text-red",
  }[tone];
  return (
    <div className="rounded-lg border border-border bg-surface-2 p-3">
      <div className="h-section">{label}</div>
      <div className={`num-callout-sm mt-1 ${toneCls}`}>{value}</div>
    </div>
  );
}
