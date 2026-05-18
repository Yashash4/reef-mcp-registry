"use client";

import { RIAArtifactReveal } from "@/app/components/RIAArtifactReveal";
import { ComplianceWall } from "@/app/components/ComplianceWall";
import { SceneShell, SceneCenter } from "@/app/stage/_shell/SceneShell";
import { useSceneControls } from "@/app/lib/hooks/use-scene-controls";

/** /stage/score — RIAArtifactReveal full-screen + ComplianceWall on demand.
 *  The third-act categorical separator. */
export default function ScoreScene() {
  const ctl = useSceneControls(2, 10_000);
  return (
    <SceneShell
      sceneId="score"
      sceneTitle="Layer 4 · Underwriter — RIA reveal + compliance wall"
      beatLabel={["RIA build", "compliance wall"][ctl.beatIndex]}
      beatIndex={ctl.beatIndex}
      totalBeats={2}
    >
      <SceneCenter className="gap-8">
        <div className="text-center">
          <div className="text-text-3 mono text-xs uppercase tracking-widest mb-2">
            Reef · Score pillar
          </div>
          <h1 className="display text-6xl text-text">
            The artifact the underwriter <em>can</em> price.
          </h1>
        </div>
        <div className="w-full max-w-6xl">
          {ctl.beatIndex === 0 && <RIAArtifactReveal paused={false} />}
          {ctl.beatIndex >= 1 && <ComplianceWall />}
        </div>
      </SceneCenter>
    </SceneShell>
  );
}
