"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchFleet } from "@/app/lib/api/policy-bus";
import { REEF_FLEET_ID } from "@/app/lib/env";
import type { FleetSnapshot, NodeRecord } from "@/app/lib/types";

export interface UseFleetResult {
  snapshot: FleetSnapshot | undefined;
  nodes: NodeRecord[];
  lastAckedNodeKey: string | null;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
  refetch: () => void;
}

/** Poll policy-bus /fleet every 5 s. Graceful degradation on transport
 *  failure — surfaces `isError` so the caller can render an "offline" badge
 *  instead of crashing the dashboard. */
export function useFleet(fleetId: string = REEF_FLEET_ID): UseFleetResult {
  const q = useQuery({
    queryKey: ["fleet", fleetId],
    queryFn: () => fetchFleet(fleetId),
    refetchInterval: 5_000,
    staleTime: 2_000,
  });

  const nodes = q.data?.nodes ?? [];
  // The "most recently acked" node drives the stadium wave centerpoint.
  const lastAcked = nodes.reduce<NodeRecord | null>((acc, n) => {
    if (n.last_ack_unix <= 0) return acc;
    if (!acc || n.last_ack_unix > acc.last_ack_unix) return n;
    return acc;
  }, null);

  return {
    snapshot: q.data,
    nodes,
    lastAckedNodeKey: lastAcked
      ? `${lastAcked.identity.fleet_id}/${lastAcked.identity.region_id}/${lastAcked.identity.site_id}/${lastAcked.identity.node_id}`
      : null,
    isLoading: q.isLoading,
    isError: q.isError,
    error: (q.error as Error | null) ?? null,
    refetch: () => q.refetch(),
  };
}
