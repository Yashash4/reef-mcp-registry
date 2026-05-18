"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import {
  FleetGrid,
  buildDemoFleetSnapshot,
} from "@/app/components/FleetGrid";
import { MCPRegistryBeat } from "@/app/components/MCPRegistryBeat";
import { Shark } from "@/app/components/Shark";
import { AttackPackCatalog } from "@/app/components/AttackPackCatalog";
import { RIAArtifactReveal } from "@/app/components/RIAArtifactReveal";
import { SceneShell } from "@/app/stage/_shell/SceneShell";
import { useSceneControls } from "@/app/lib/hooks/use-scene-controls";
import { REEF_VICTIM_URL } from "@/app/lib/env";

// 8 beats matching A-11 task §4 cold-open arc:
//   0:00-0:10 title
//   0:10-0:30 MCPRegistryBeat
//   0:30-0:50 FleetGrid stadium wave
//   0:50-1:05 EchoLeak iframe mini-demo
//   1:05-1:15 Shark + attack pack scroll
//   1:15-1:50 RIAArtifactReveal
//   1:50-2:00 closing card
const BEATS = [
  { id: 0, label: "0:00 · title", durationMs: 10_000 },
  { id: 1, label: "0:10 · MCP block beat", durationMs: 20_000 },
  { id: 2, label: "0:30 · stadium wave", durationMs: 20_000 },
  { id: 3, label: "0:50 · EchoLeak mini-demo", durationMs: 15_000 },
  { id: 4, label: "1:05 · DAST-A shark", durationMs: 10_000 },
  { id: 5, label: "1:15 · RIA artifact reveal", durationMs: 35_000 },
  { id: 6, label: "1:50 · closing card", durationMs: 10_000 },
];

export default function ColdOpenScene() {
  const ctl = useSceneControls(BEATS.length, 1500);

  // Custom auto-advance using per-beat durations (override the default)
  const [advanceTrigger, setAdvanceTrigger] = useState(0);
  useEffect(() => {
    if (ctl.paused) return;
    const t = setTimeout(() => {
      setAdvanceTrigger((x) => x + 1);
      ctl.next();
    }, BEATS[ctl.beatIndex]?.durationMs ?? 10_000);
    return () => clearTimeout(t);
  }, [ctl, advanceTrigger]);

  // Synthesised fleet for the stadium wave beat. // DEMO PATH — see
  // FleetGrid::buildDemoFleetSnapshot. Refresh every 200 ms so the wave
  // replays on each new mount.
  const [demoSnapshot, setDemoSnapshot] = useState(buildDemoFleetSnapshot());
  useEffect(() => {
    if (ctl.beatIndex !== 2) return;
    const t = setInterval(
      () => setDemoSnapshot(buildDemoFleetSnapshot()),
      2_500
    );
    return () => clearInterval(t);
  }, [ctl.beatIndex]);

  const beat = BEATS[ctl.beatIndex] ?? BEATS[0];

  return (
    <SceneShell
      sceneId="cold-open"
      sceneTitle="2-minute cold-open arc"
      beatLabel={beat.label}
      beatIndex={ctl.beatIndex}
      totalBeats={BEATS.length}
    >
      <AnimatePresence mode="wait">
        {beat.id === 0 && (
          <SceneBeat key="title">
            <TypewriterTitle />
          </SceneBeat>
        )}
        {beat.id === 1 && (
          <SceneBeat key="mcp-beat">
            <div className="w-full max-w-3xl">
              <MCPRegistryBeat autoPlay />
            </div>
          </SceneBeat>
        )}
        {beat.id === 2 && (
          <SceneBeat key="fleet-wave">
            <div className="flex flex-col items-center gap-6">
              <div className="display text-3xl text-text-2">
                49 nodes converge on the new signed policy
              </div>
              <FleetGrid nodes={demoSnapshot} size={420} rippleEnabled />
              <div className="mono text-xs text-text-3">
                bundle v3 · ed25519 by publisher-prod · &lt; 4 s propagation
              </div>
            </div>
          </SceneBeat>
        )}
        {beat.id === 3 && (
          <SceneBeat key="echoleak">
            <div className="flex flex-col items-center gap-4 w-full max-w-5xl">
              <div className="display text-3xl text-text-2">
                EchoLeak attempt at the victim Copilot
              </div>
              <iframe
                src={`${REEF_VICTIM_URL}?demo=true`}
                className="w-full h-[60vh] rounded-xl border border-border bg-bg"
                title="Reef victim — EchoLeak demo path"
                sandbox="allow-scripts allow-forms allow-same-origin"
              />
            </div>
          </SceneBeat>
        )}
        {beat.id === 4 && (
          <SceneBeat key="shark">
            <div className="flex flex-col items-center gap-8">
              <Shark state="blocked" attempts={42} blocked={42} novel={6} size={300} />
              <AttackPackCatalog compact className="w-full max-w-5xl" />
            </div>
          </SceneBeat>
        )}
        {beat.id === 5 && (
          <SceneBeat key="ria">
            <div className="w-full max-w-6xl">
              <RIAArtifactReveal />
            </div>
          </SceneBeat>
        )}
        {beat.id === 6 && (
          <SceneBeat key="closing">
            <ClosingCard />
          </SceneBeat>
        )}
      </AnimatePresence>
    </SceneShell>
  );
}

function SceneBeat({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.6 }}
      className="flex min-h-screen w-full flex-col items-center justify-center px-8 py-12"
    >
      {children}
    </motion.div>
  );
}

function TypewriterTitle() {
  const words = ["April", "2026.", "An", "MCP", "STDIO", "RCE", "—", "7,000+", "servers."];
  return (
    <div className="display text-text text-center">
      <div className="text-text-3 text-xs uppercase tracking-widest mb-6 mono">
        REEF · TechEx 2026
      </div>
      <div className="text-5xl md:text-7xl leading-tight">
        {words.map((w, i) => (
          <motion.span
            key={`${w}-${i}`}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.4, duration: 0.4 }}
            className="inline-block mr-4"
          >
            {w}
          </motion.span>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: words.length * 0.4 + 0.3 }}
        className="mt-10 text-text-2 text-2xl"
      >
        Reef ships the signed supply chain.
      </motion.div>
    </div>
  );
}

function ClosingCard() {
  return (
    <div className="text-center max-w-3xl">
      <div className="display text-6xl md:text-7xl leading-none text-text">
        Reef.
      </div>
      <div className="mt-4 display text-3xl text-text-2">
        Signed MCP. Insurable AI.
      </div>
      <div className="mt-8 mono text-sm text-text-3">
        github.com/Yashash4/reef-mcp-registry · MIT · TechEx 2026
      </div>
    </div>
  );
}
