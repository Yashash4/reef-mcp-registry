"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";

interface ServiceStatusProps {
  label: string;
  isLoading: boolean;
  isError: boolean;
  className?: string;
}

/** Compact inline badge that surfaces upstream service status. Used by
 *  every dashboard panel so a single-service outage degrades that panel
 *  gracefully — no dashboard-wide crash. */
export function ServiceStatus({
  label,
  isLoading,
  isError,
  className,
}: ServiceStatusProps) {
  if (isLoading) {
    return (
      <Badge variant="outline" className={cn("animate-pulse-soft", className)}>
        <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-text-3" />
        {label} loading
      </Badge>
    );
  }
  if (isError) {
    return (
      <Badge variant="red" className={className}>
        <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-red" />
        {label} offline
      </Badge>
    );
  }
  return (
    <Badge variant="emerald" className={className}>
      <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-emerald" />
      {label} live
    </Badge>
  );
}
