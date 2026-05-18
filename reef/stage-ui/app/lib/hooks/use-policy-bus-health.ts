"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchBundles,
  fetchPolicyBusHealth,
} from "@/app/lib/api/policy-bus";
import type { BundleListItem, PolicyBusHealthz } from "@/app/lib/types";

export interface UsePolicyBusHealthResult {
  health: PolicyBusHealthz | undefined;
  bundles: BundleListItem[];
  currentBundle: BundleListItem | null;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

export function usePolicyBusHealth(): UsePolicyBusHealthResult {
  const healthQ = useQuery({
    queryKey: ["policy-bus-health"],
    queryFn: fetchPolicyBusHealth,
    refetchInterval: 5_000,
    staleTime: 2_000,
  });
  const bundlesQ = useQuery({
    queryKey: ["policy-bus-bundles"],
    queryFn: fetchBundles,
    refetchInterval: 10_000,
    staleTime: 5_000,
  });

  const bundles = bundlesQ.data ?? [];
  // Pick the most recently-published bundle as "current."
  const currentBundle = bundles.reduce<BundleListItem | null>((acc, b) => {
    if (!acc || (b.published_at_unix ?? 0) > (acc.published_at_unix ?? 0)) {
      return b;
    }
    return acc;
  }, null);

  return {
    health: healthQ.data,
    bundles,
    currentBundle,
    isLoading: healthQ.isLoading || bundlesQ.isLoading,
    isError: healthQ.isError || bundlesQ.isError,
    error: ((healthQ.error || bundlesQ.error) as Error | null) ?? null,
  };
}
