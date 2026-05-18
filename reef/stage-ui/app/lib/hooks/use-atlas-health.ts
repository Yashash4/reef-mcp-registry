"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAtlasHealth } from "@/app/lib/api/atlas";
import type { AtlasHealthz } from "@/app/lib/types";

export interface UseAtlasHealthResult {
  health: AtlasHealthz | undefined;
  verified: number;
  quarantined: number;
  poisoned: number;
  publishers: number;
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

export function useAtlasHealth(): UseAtlasHealthResult {
  const q = useQuery({
    queryKey: ["atlas-health"],
    queryFn: fetchAtlasHealth,
    refetchInterval: 30_000,
    staleTime: 10_000,
  });

  return {
    health: q.data,
    verified: q.data?.registry_entries.verified ?? 0,
    quarantined: q.data?.registry_entries.quarantined ?? 0,
    poisoned: q.data?.registry_entries.poisoned ?? 0,
    publishers: q.data?.publishers ?? 0,
    isLoading: q.isLoading,
    isError: q.isError,
    error: (q.error as Error | null) ?? null,
  };
}
