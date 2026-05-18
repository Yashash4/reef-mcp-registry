"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchDastAPacks } from "@/app/lib/api/dast-a";
import { REEF_DEMO_MODE } from "@/app/lib/env";
import { MOCK_DAST_A_PACKS } from "@/app/lib/mocks/fixtures";
import type { AttackPackList } from "@/app/lib/types";

export interface UseDastAPacksResult {
  data: AttackPackList | undefined;
  packs: AttackPackList["packs"];
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

export function useDastAPacks(): UseDastAPacksResult {
  const q = useQuery({
    queryKey: ["dast-a-packs"],
    queryFn: () => fetchDastAPacks(1, 50),
    refetchInterval: 10_000,
    staleTime: 5_000,
    initialData: REEF_DEMO_MODE ? MOCK_DAST_A_PACKS : undefined,
  });

  return {
    data: q.data,
    packs: q.data?.packs ?? [],
    isLoading: q.isLoading,
    isError: q.isError,
    error: (q.error as Error | null) ?? null,
  };
}
