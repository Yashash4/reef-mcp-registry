import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Truncate a hex / base64 string to first N chars + ellipsis. */
export function truncateHex(hex: string, head = 12, tail = 6): string {
  if (!hex || hex.length <= head + tail + 1) return hex;
  return `${hex.slice(0, head)}…${hex.slice(-tail)}`;
}

/** Format a unix-seconds timestamp as a HH:MM:SS local-time string. */
export function formatUnixTime(unix: number): string {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return d.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/** Format a unix-seconds timestamp as a relative-time string ("3s ago"). */
export function relativeTime(unix: number, nowMs: number = Date.now()): string {
  if (!unix) return "—";
  const delta = Math.max(0, Math.floor(nowMs / 1000 - unix));
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
  return `${Math.floor(delta / 86400)}d ago`;
}
