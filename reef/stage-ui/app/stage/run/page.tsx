"use client";

import { useEffect, useState } from "react";
import { Shark, type SharkState } from "@/app/components/Shark";
import { AttackTrace } from "@/app/components/AttackTrace";
import { AttackPackCatalog } from "@/app/components/AttackPackCatalog";
import { SceneShell, SceneCenter } from "@/app/stage/_shell/SceneShell";
import { useSceneControls } from "@/app/lib/hooks/use-scene-controls";

const SHARK_BEATS: { state: SharkState; attempts: number; blocked: number; novel: number; label: string }[] = [
  { state: "idle", attempts: 0, blocked: 0, novel: 0, label: "idle" },
  { state: "running", attempts: 8, blocked: 6, novel: 1, label: "exploring" },
  { state: "novel", attempts: 21, blocked: 18, novel: 3, label: "novel attack found" },
  { state: "blocked", attempts: 42, blocked: 38, novel: 4, label: "all-blocked sweep" },
  { state: "blocked", attempts: 72, blocked: 65, novel: 6, label: "live attack/defense scoreboard" },
];

/** /stage/run — Shark + live attack/defense scoreboard. The DAST-A
 *  RL adversary attacks the sandbox; Reef blocks; novel attacks become
 *  pending review-queue drafts. */
export default function RunScene() {
  const ctl = useSceneControls(SHARK_BEATS.length, 3_500);
  const beat = SHARK_BEATS[ctl.beatIndex] ?? SHARK_BEATS[0];

  // Animate attempts counter smoothly across each beat instead of a
  // hard jump — gives the OBS capture a clean ticker effect.
  const [ticker, setTicker] = useState({
    attempts: 0,
    blocked: 0,
    novel: 0,
  });
  useEffect(() => {
    const start = ticker;
    const target = beat;
    const steps = 24;
    let i = 0;
    const t = setInterval(() => {
      i += 1;
      const f = Math.min(1, i / steps);
      setTicker({
        attempts: Math.round(start.attempts + (target.attempts - start.attempts) * f),
        blocked: Math.round(start.blocked + (target.blocked - start.blocked) * f),
        novel: Math.round(start.novel + (target.novel - start.novel) * f),
      });
      if (i >= steps) clearInterval(t);
    }, 50);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ctl.beatIndex]);

  return (
    <SceneShell
      sceneId="run"
      sceneTitle="Layer 3 · DAST-A shark + scoreboard"
      beatLabel={beat.label}
      beatIndex={ctl.beatIndex}
      totalBeats={SHARK_BEATS.length}
    >
      <SceneCenter className="gap-8">
        <div className="text-center">
          <div className="text-text-3 mono text-xs uppercase tracking-widest mb-2">
            Reef · Run pillar
          </div>
          <h1 className="display text-5xl text-text">
            DAST-A patrols the fleet.
          </h1>
        </div>

        <div className="grid gap-8 lg:grid-cols-[auto_1fr] items-center w-full max-w-6xl">
          <div className="flex flex-col items-center gap-4">
            <Shark
              state={beat.state}
              attempts={ticker.attempts}
              blocked={ticker.blocked}
              novel={ticker.novel}
              size={300}
            />
          </div>

          <AttackTrace sessionId={`scene-run-${ctl.beatIndex}`} />
        </div>

        <AttackPackCatalog compact className="w-full max-w-6xl" />
      </SceneCenter>
    </SceneShell>
  );
}
