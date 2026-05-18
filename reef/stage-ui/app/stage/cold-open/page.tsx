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

// 8 beats matching Batch D R-D4 cold-open arc (POV-3 #1: open on red
// BIND_DENIED cold-cut, NOT 10s of silent typewriter):
//   0:00-0:03 BIND_DENIED cold-cut (movement first, no narration)
//   0:03-0:10 title card (typewriter reveals AFTER the punch lands)
//   0:10-0:30 MCPRegistryBeat (the one-big-punch GIF moment)
//   0:30-0:50 FleetGrid stadium wave (with counter ticking down)
//   0:50-1:05 EchoLeak iframe mini-demo
//   1:05-1:15 Shark + attack pack scroll
//   1:15-1:50 RIAArtifactReveal
//   1:50-2:00 closing card (slack-able 25-word category line)
const BEATS = [
  { id: 0, label: "0:00 · BIND_DENIED cold-cut", durationMs: 3_000 },
  { id: 1, label: "0:03 · title", durationMs: 7_000 },
  { id: 2, label: "0:10 · MCP block beat", durationMs: 20_000 },
  { id: 3, label: "0:30 · stadium wave", durationMs: 20_000 },
  { id: 4, label: "0:50 · EchoLeak mini-demo", durationMs: 15_000 },
  { id: 5, label: "1:05 · DAST-A shark", durationMs: 10_000 },
  { id: 6, label: "1:15 · RIA artifact reveal", durationMs: 35_000 },
  { id: 7, label: "1:50 · closing card", durationMs: 10_000 },
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
  // FleetGrid::buildDemoFleetSnapshot. Refresh every 2.5s so the wave
  // replays on each new mount. Stadium wave beat is now index 3 (Batch D
  // R-D4 inserted the BIND_DENIED cold-cut at index 0).
  const [demoSnapshot, setDemoSnapshot] = useState(buildDemoFleetSnapshot());
  useEffect(() => {
    if (ctl.beatIndex !== 3) return;
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
          <SceneBeat key="bind-denied-cold-cut">
            <BindDeniedColdCut />
          </SceneBeat>
        )}
        {beat.id === 1 && (
          <SceneBeat key="title">
            <TypewriterTitle />
          </SceneBeat>
        )}
        {beat.id === 2 && (
          <SceneBeat key="mcp-beat">
            <div className="w-full max-w-6xl">
              <MCPRegistryBeat autoPlay />
            </div>
          </SceneBeat>
        )}
        {beat.id === 3 && (
          <SceneBeat key="fleet-wave">
            <div className="flex flex-col items-center gap-6">
              <div className="display text-3xl text-text-2">
                49 nodes converge on the new signed policy
              </div>
              <FleetGrid
                nodes={demoSnapshot}
                size={420}
                rippleEnabled
                showCountdown
              />
              <div className="mono text-xs text-text-3">
                bundle v4 · ed25519 by publisher-prod · &lt; 4 s propagation
              </div>
            </div>
          </SceneBeat>
        )}
        {beat.id === 4 && (
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
        {beat.id === 5 && (
          <SceneBeat key="shark">
            <div className="flex flex-col items-center gap-8">
              <Shark state="blocked" attempts={42} blocked={42} novel={6} size={300} />
              <AttackPackCatalog compact className="w-full max-w-5xl" />
            </div>
          </SceneBeat>
        )}
        {beat.id === 6 && (
          <SceneBeat key="ria">
            <div className="w-full max-w-6xl">
              <RIAArtifactReveal />
            </div>
          </SceneBeat>
        )}
        {beat.id === 7 && (
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

/**
 * Beat 0 — red BIND_DENIED cold-cut (Batch D R-D4 / POV-3 #1 +12% win-prob).
 *
 * Opens the cold-open arc on movement, NOT 10s of silent typewriter title.
 * Giant red BIND DENIED glyph + MCP-RCE-26.04 code below + named villain
 * badge. 3 seconds, no narration — the punch lands first, words follow at
 * beat 1.
 *
 * Mirrors the cover image (samples/cover-image.png) opening frame so the
 * static cover and the recorded video become continuous (POV-3 §7).
 */
function BindDeniedColdCut() {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.96 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="relative flex flex-col items-center justify-center text-center"
    >
      <div className="pointer-events-none absolute inset-0 -z-10 bg-red-soft blur-3xl" />
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: [0, 1, 1, 0.92, 1] }}
        transition={{ duration: 0.8, times: [0, 0.15, 0.4, 0.7, 1] }}
        className="display text-red text-[120px] md:text-[200px] leading-none tracking-tightest"
        style={{ textShadow: "0 0 60px rgba(239, 68, 68, 0.55)" }}
      >
        BIND DENIED
      </motion.div>
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25, duration: 0.4 }}
        className="mono mt-4 text-3xl md:text-5xl text-text"
      >
        MCP-RCE-26.04
      </motion.div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6, duration: 0.4 }}
        className="mt-6 flex items-center gap-3"
      >
        <span className="rounded-full border border-violet/40 bg-violet-soft px-3 py-1 mono text-xs text-violet">
          Anthropic MCP STDIO
        </span>
        <span className="text-text-3 text-xs uppercase tracking-widest mono">
          OX Security · April 16 2026
        </span>
      </motion.div>
    </motion.div>
  );
}

function TypewriterTitle() {
  // Title typewriter reveals AFTER the BIND_DENIED punch (beat 0). Now
  // 7s instead of 10s — see BEATS[1].durationMs.
  const words = [
    "April",
    "2026.",
    "Anthropic",
    "MCP",
    "STDIO",
    "RCE.",
    "7,000+",
    "servers.",
    "150M+",
    "downloads.",
  ];
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
            transition={{ delay: i * 0.28, duration: 0.3 }}
            className="inline-block mr-4"
          >
            {w}
          </motion.span>
        ))}
      </div>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: words.length * 0.28 + 0.2 }}
        className="mt-10 text-text-2 text-2xl"
      >
        Reef ships the signed supply chain.
      </motion.div>
    </div>
  );
}

/**
 * Closing card — final still frame of the cold-open scene (Batch D R-D7).
 *
 * Slack-able 25-word category line that ENDS the video on a card a judge
 * can screenshot and paste into Slack without losing context. Refined
 * from POV-3 suggestion ("Someone shipped npm-Sigstore-but-for-MCP-
 * servers — blocked the April Anthropic RCE and outputs an insurance-
 * grade PDF your broker can price") into a one-beat 23-word version that
 * preserves the verbatim grounding hooks (Anthropic RCE, signed MCP,
 * insurable AI, underwriter).
 */
function ClosingCard() {
  return (
    <div className="text-center max-w-4xl">
      <div className="display text-6xl md:text-7xl leading-none text-text">
        Reef.
      </div>
      <div className="mt-6 display text-2xl md:text-3xl leading-snug text-text-2">
        Signed MCP. Insurable AI. Open source.
        <br />
        Blocked the April Anthropic RCE. Outputs the audit your underwriter can price.
      </div>
      <div className="mt-10 mono text-sm text-text-3">
        github.com/Yashash4/reef-mcp-registry · MIT · TechEx 2026
      </div>
    </div>
  );
}
