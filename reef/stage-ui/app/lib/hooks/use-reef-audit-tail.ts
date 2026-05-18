"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAuditTail } from "@/app/lib/api/policy-bus";
import type { AuditEvent } from "@/app/lib/types";

export interface UseReefAuditTailResult {
  events: AuditEvent[];
  isLoading: boolean;
  isError: boolean;
  error: Error | null;
}

/** Poll the policy-bus /audit/tail every 3 s. Requires the admin token —
 *  if the token is missing the hook fails fast with a clear error message
 *  so the caller can render an inline "set NEXT_PUBLIC_REEF_POLICY_BUS_ADMIN_TOKEN
 *  in .env.local" hint. */
export function useReefAuditTail(n: number = 20): UseReefAuditTailResult {
  const q = useQuery({
    queryKey: ["audit-tail", n],
    queryFn: () => fetchAuditTail(n),
    refetchInterval: 3_000,
    staleTime: 1_500,
    retry: 0,
  });

  return {
    events: q.data ?? [],
    isLoading: q.isLoading,
    isError: q.isError,
    error: (q.error as Error | null) ?? null,
  };
}
