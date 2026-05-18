"use client";

import { motion } from "framer-motion";
import { useEffect, useMemo, useState } from "react";
import { cn } from "@/app/lib/utils";

export type SharkState = "idle" | "running" | "novel" | "blocked";

interface SharkProps {
  state?: SharkState;
  attempts?: number;
  blocked?: number;
  novel?: number;
  size?: number;
  className?: string;
}

const STATE_COLOR: Record<SharkState, string> = {
  idle: "text-text-3",
  running: "text-cyan",
  novel: "text-emerald",
  blocked: "text-red",
};

const STATE_GLOW: Record<SharkState, string> = {
  idle: "",
  running: "glow-cyan",
  novel: "glow-emerald",
  blocked: "glow-red",
};

/** DAST-A shark — SVG silhouette circling around a center point. The
 *  state changes color: zinc (idle) → cyan (running) → emerald (novel
 *  attack found) → red (blocked by Reef). Attempts counter ticks each
 *  time `attempts` increases. */
export function Shark({
  state = "idle",
  attempts = 0,
  blocked = 0,
  novel = 0,
  size = 220,
  className,
}: SharkProps) {
  // Brief 800ms "flash" when attempts changes — wraps the SharkSilhouette
  // in a temporary highlight overlay.
  const [flashKey, setFlashKey] = useState(0);
  const prevAttempts = useMemoPrevious(attempts);
  useEffect(() => {
    if (prevAttempts !== undefined && attempts !== prevAttempts) {
      setFlashKey((k) => k + 1);
    }
  }, [attempts, prevAttempts]);

  return (
    <div
      className={cn(
        "relative flex flex-col items-center justify-center rounded-2xl border border-border bg-surface",
        STATE_GLOW[state],
        className
      )}
      style={{ width: size, height: size }}
    >
      <div className="relative h-[140px] w-[140px]">
        {/* Center pulse */}
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="h-4 w-4 rounded-full bg-cyan-soft" />
          <div
            className={cn(
              "absolute h-4 w-4 rounded-full",
              state === "running" ? "animate-ping bg-cyan/40" : ""
            )}
          />
        </div>
        {/* Circling shark */}
        <motion.div
          className="absolute left-1/2 top-1/2 -ml-[14px] -mt-[14px]"
          animate={{ rotate: 360 }}
          transition={{
            duration: 14,
            repeat: Infinity,
            ease: "linear",
          }}
        >
          <SharkSilhouette
            className={cn("h-7 w-7", STATE_COLOR[state])}
            style={{ transform: "translateX(58px)" }}
          />
        </motion.div>
        {/* Attack flash overlay */}
        <motion.div
          key={flashKey}
          initial={{ opacity: 0.8, scale: 0.4 }}
          animate={{ opacity: 0, scale: 2.2 }}
          transition={{ duration: 0.7, ease: "easeOut" }}
          className={cn(
            "absolute inset-0 rounded-full pointer-events-none",
            state === "blocked" ? "bg-red/30" : "bg-cyan/30"
          )}
        />
      </div>

      <div className="mt-4 grid w-full grid-cols-3 gap-2 px-4 text-center font-mono text-[10px] uppercase tracking-widest text-text-3">
        <div>
          <div className="num-callout-sm text-text">{attempts}</div>
          <div>attempts</div>
        </div>
        <div>
          <div className="num-callout-sm text-emerald">{novel}</div>
          <div>novel</div>
        </div>
        <div>
          <div className="num-callout-sm text-red">{blocked}</div>
          <div>blocked</div>
        </div>
      </div>
    </div>
  );
}

function SharkSilhouette({
  className,
  style,
}: {
  className?: string;
  style?: React.CSSProperties;
}) {
  return (
    <svg
      viewBox="0 0 64 32"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      style={style}
      aria-hidden
    >
      {/* Stylized shark — body + dorsal fin + tail */}
      <path d="M2 16 Q14 4 32 6 Q48 7 58 12 L62 10 L58 16 L62 22 L58 20 Q48 25 32 26 Q14 28 2 16 Z" />
      <path d="M30 4 L34 -2 L38 6 Z" transform="translate(0,2)" />
      <circle cx="48" cy="13" r="1.2" fill="#0a0a0a" />
    </svg>
  );
}

/** Tiny utility — track previous value of a prop. */
function useMemoPrevious<T>(value: T): T | undefined {
  const [prev, setPrev] = useState<T | undefined>(undefined);
  useMemo(() => {
    setPrev(value);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return prev;
}
