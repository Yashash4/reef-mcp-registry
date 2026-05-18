"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useReefAuditTail } from "@/app/lib/hooks/use-reef-audit-tail";
import { formatUnixTime } from "@/app/lib/utils";
import { ServiceStatus } from "@/components/ui/service-status";
import { cn } from "@/app/lib/utils";

interface RecentDecisionsFeedProps {
  className?: string;
}

/** Recent-decisions feed sourced from policy-bus /audit/tail.
 *
 *  Each row: timestamp · action · agent_id · reason. Color-coded by kind
 *  so judges scan it visually in <5 seconds. Requires the admin token —
 *  without one the panel renders a "set admin token" hint instead of
 *  crashing. */
export function RecentDecisionsFeed({ className }: RecentDecisionsFeedProps) {
  const { events, isLoading, isError, error } = useReefAuditTail(20);

  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="display text-2xl">Recent decisions</CardTitle>
          <p className="mt-1 text-xs text-text-3">
            Live tail of policy-bus + Atlas audit events · refresh every 3 s
          </p>
        </div>
        <ServiceStatus
          label="audit"
          isLoading={isLoading}
          isError={isError}
        />
      </CardHeader>
      <CardContent>
        {isError && (
          <div className="rounded-md border border-amber/30 bg-amber-soft p-3 text-xs text-amber">
            {error?.message ??
              "Audit tail unavailable. Set NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_TOKEN in .env.local to enable the live feed."}
          </div>
        )}
        {!isError && events.length === 0 && !isLoading && (
          <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-text-3">
            no events in the last window
          </div>
        )}
        {events.length > 0 && (
          <ScrollArea className="h-[360px]">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-widest text-text-3">
                  <th className="pb-2 font-medium">Time</th>
                  <th className="pb-2 font-medium">Action</th>
                  <th className="pb-2 font-medium">Reason</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => {
                  const action = computeAction(e);
                  return (
                    <tr
                      key={e.audit_id}
                      className="border-t border-border-soft align-top hover:bg-surface-2/50"
                    >
                      <td className="py-2 pr-3 mono text-xs text-text-3 whitespace-nowrap">
                        {formatUnixTime(e.ts_unix)}
                      </td>
                      <td className="py-2 pr-3">
                        <Badge variant={action.color}>{action.label}</Badge>
                      </td>
                      <td className="py-2 text-xs text-text-2">
                        <div className="line-clamp-2">{e.reason ?? eventBlurb(e)}</div>
                        {(e.bundle_id || e.signer_key_id) && (
                          <div className="mt-1 mono text-[10px] text-text-3">
                            {e.bundle_id && <span>bundle: {e.bundle_id}</span>}
                            {e.bundle_id && e.signer_key_id && <span> · </span>}
                            {e.signer_key_id && (
                              <span>signer: {e.signer_key_id}</span>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  );
}

interface AuditAction {
  label: string;
  color: "emerald" | "red" | "amber" | "cyan" | "violet" | "default";
}

function computeAction(e: {
  kind: string;
  event?: string;
  decision?: string;
}): AuditAction {
  // Map kind+event/decision into a Stage-UI-friendly action label
  if (e.kind === "publish") {
    if (e.event === "accepted") {
      return { label: "BUNDLE_APPLIED", color: "emerald" };
    }
    if (e.event === "rejected") {
      return { label: "BUNDLE_REJECTED", color: "red" };
    }
  }
  if (e.kind === "verify") {
    if (e.decision === "deny") return { label: "BIND_DENIED", color: "red" };
    if (e.decision === "review")
      return { label: "BIND_REVIEW", color: "amber" };
    if (e.decision === "allow")
      return { label: "BIND_ALLOWED", color: "emerald" };
  }
  if (e.kind === "publisher") {
    return { label: "PUBLISHER_ADDED", color: "cyan" };
  }
  if (e.kind === "ack") {
    return { label: "NODE_ACK", color: "emerald" };
  }
  if (e.kind === "ria") {
    return { label: "RIA_GENERATED", color: "amber" };
  }
  if (e.kind === "egress") {
    return { label: "EXFIL_BLOCKED", color: "red" };
  }
  return { label: (e.kind ?? "EVENT").toUpperCase(), color: "default" };
}

function eventBlurb(e: { kind: string; event?: string }): string {
  if (e.kind && e.event) return `${e.kind} → ${e.event}`;
  return e.kind ?? "(no detail)";
}

// Used by the Public Safety Page to keep horizontal density honest
// without React's no-unused-vars complaining when we drop the prop.
export const _NoOp = cn;
