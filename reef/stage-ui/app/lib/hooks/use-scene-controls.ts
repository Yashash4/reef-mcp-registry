"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

export interface SceneControlsState {
  beatIndex: number;
  totalBeats: number;
  paused: boolean;
  startTimeMs: number;
}

export interface SceneControlsApi extends SceneControlsState {
  next: () => void;
  prev: () => void;
  reset: () => void;
  togglePause: () => void;
}

/** Keyboard-controlled scene runner for stage/OBS captures.
 *
 * Bindings (documented on every scene's footer per A-11 task §4):
 *   space    play / pause
 *   r        reset to first beat
 *   →        next beat
 *   ←        previous beat
 *
 * `totalBeats` is the total step count for the scene. Auto-advance fires
 * every `autoAdvanceMs` while not paused (default 1500 ms). */
export function useSceneControls(
  totalBeats: number,
  autoAdvanceMs: number = 1500
): SceneControlsApi {
  const [beatIndex, setBeatIndex] = useState(0);
  const [paused, setPaused] = useState(false);
  const [startTimeMs, setStartTimeMs] = useState(() => Date.now());

  const next = useCallback(
    () =>
      setBeatIndex((i) => (totalBeats > 0 ? Math.min(i + 1, totalBeats - 1) : 0)),
    [totalBeats]
  );
  const prev = useCallback(() => setBeatIndex((i) => Math.max(i - 1, 0)), []);
  const reset = useCallback(() => {
    setBeatIndex(0);
    setStartTimeMs(Date.now());
  }, []);
  const togglePause = useCallback(() => setPaused((p) => !p), []);

  // Auto-advance
  useEffect(() => {
    if (paused) return;
    if (totalBeats <= 0) return;
    const t = setInterval(() => {
      setBeatIndex((i) => Math.min(i + 1, totalBeats - 1));
    }, autoAdvanceMs);
    return () => clearInterval(t);
  }, [paused, autoAdvanceMs, totalBeats]);

  // Keybindings
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Skip when focused inside a textarea / input
      const tgt = e.target as HTMLElement;
      if (tgt && (tgt.tagName === "TEXTAREA" || tgt.tagName === "INPUT")) return;

      if (e.code === "Space") {
        e.preventDefault();
        togglePause();
      } else if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        reset();
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        next();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        prev();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [next, prev, reset, togglePause]);

  return useMemo(
    () => ({
      beatIndex,
      totalBeats,
      paused,
      startTimeMs,
      next,
      prev,
      reset,
      togglePause,
    }),
    [beatIndex, totalBeats, paused, startTimeMs, next, prev, reset, togglePause]
  );
}
