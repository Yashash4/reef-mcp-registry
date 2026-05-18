"use client";

import { cn } from "@/app/lib/utils";

interface SceneShellProps {
  sceneId: string;
  sceneTitle: string;
  beatLabel?: string;
  beatIndex: number;
  totalBeats: number;
  children: React.ReactNode;
}

/** Wraps a stage scene with a full-bleed dark backdrop + a corner overlay
 *  that surfaces the scene metadata + keybinding cheatsheet. The overlay
 *  is intentionally subdued (text-text-3 on bg) so it doesn't pollute the
 *  OBS capture — judges in the final video see the scene visuals, not the
 *  overlay text. */
export function SceneShell({
  sceneId,
  sceneTitle,
  beatLabel,
  beatIndex,
  totalBeats,
  children,
}: SceneShellProps) {
  return (
    <div className="relative min-h-screen w-full overflow-hidden bg-bg text-text">
      <div className="absolute inset-0 grid-bg opacity-30 pointer-events-none" />
      <div className="relative">{children}</div>

      <div className="pointer-events-none fixed bottom-4 left-4 right-4 z-50 flex items-end justify-between gap-3">
        <div className="rounded-md border border-border-soft bg-bg/70 px-3 py-1.5 mono text-[10px] uppercase tracking-widest text-text-3 backdrop-blur">
          {sceneId} · {sceneTitle}
          {beatLabel && <span className="ml-2 text-text-2">{beatLabel}</span>}
          <span className="ml-2 text-text-3/70">
            beat {beatIndex + 1} / {Math.max(1, totalBeats)}
          </span>
        </div>
        <div className="rounded-md border border-border-soft bg-bg/70 px-3 py-1.5 mono text-[10px] uppercase tracking-widest text-text-3 backdrop-blur">
          <span>space</span> play/pause &nbsp;·&nbsp;
          <span>r</span> reset &nbsp;·&nbsp;
          <span>→</span> next &nbsp;·&nbsp;
          <span>←</span> prev
        </div>
      </div>
    </div>
  );
}

export function SceneCenter({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-h-screen w-full flex-col items-center justify-center px-8 py-12",
        className
      )}
    >
      {children}
    </div>
  );
}
