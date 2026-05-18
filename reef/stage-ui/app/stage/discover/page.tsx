"use client";

import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { FleetGrid, FleetGridLegend } from "@/app/components/FleetGrid";
import { Badge } from "@/components/ui/badge";
import { SceneShell } from "@/app/stage/_shell/SceneShell";
import { useFleet } from "@/app/lib/hooks/use-fleet";
import { useAtlasHealth } from "@/app/lib/hooks/use-atlas-health";
import { useSceneControls } from "@/app/lib/hooks/use-scene-controls";
import { fetchAtlasEntries } from "@/app/lib/api/atlas";
import { ServiceStatus } from "@/components/ui/service-status";

/** /stage/discover — full-screen FleetGrid + AI-BOM panel for OBS capture.
 *  Reads from live policy-bus /fleet and Atlas /registry/entries. */
export default function DiscoverScene() {
  const fleet = useFleet();
  const atlas = useAtlasHealth();
  const entriesQ = useQuery({
    queryKey: ["atlas-entries"],
    queryFn: fetchAtlasEntries,
    refetchInterval: 15_000,
    staleTime: 8_000,
    retry: 0,
  });

  const ctl = useSceneControls(3, 4_000);

  // 3 beats: counters → grid → AI-BOM tree
  return (
    <SceneShell
      sceneId="discover"
      sceneTitle="Layer 1 · MCP signature registry discovery"
      beatLabel={["counters", "fleet grid", "AI-BOM"][ctl.beatIndex]}
      beatIndex={ctl.beatIndex}
      totalBeats={3}
    >
      <div className="min-h-screen grid lg:grid-cols-[1fr_1fr] gap-6 px-10 py-10">
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-text-3 mono text-xs uppercase tracking-widest mb-2">
                Reef · Discover pillar
              </div>
              <h1 className="display text-5xl text-text">Signed MCP registry</h1>
            </div>
            <div className="flex flex-col gap-1 items-end">
              <ServiceStatus
                label="atlas"
                isLoading={atlas.isLoading}
                isError={atlas.isError}
              />
              <ServiceStatus
                label="policy-bus"
                isLoading={fleet.isLoading}
                isError={fleet.isError}
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 mt-4">
            <BigStat
              label="verified"
              value={atlas.verified}
              tone="emerald"
              show={ctl.beatIndex >= 0}
            />
            <BigStat
              label="quarantined"
              value={atlas.quarantined}
              tone="amber"
              show={ctl.beatIndex >= 0}
            />
            <BigStat
              label="poisoned"
              value={atlas.poisoned}
              tone="red"
              show={ctl.beatIndex >= 0}
            />
          </div>

          {ctl.beatIndex >= 1 && (
            <div className="flex flex-col items-center gap-3 mt-4">
              <FleetGrid nodes={fleet.nodes} size={380} />
              <FleetGridLegend />
            </div>
          )}
        </div>

        {ctl.beatIndex >= 2 && (
          <motion.div
            initial={{ opacity: 0, x: 12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.5 }}
            className="rounded-xl border border-border bg-surface p-6 overflow-hidden"
          >
            <div className="h-section mb-3">AI Bill of Materials · live</div>
            <div className="mono text-xs space-y-1 max-h-[80vh] overflow-y-auto">
              {(entriesQ.data?.entries ?? []).slice(0, 36).map((e) => (
                <div
                  key={e.registry_id}
                  className="flex items-center gap-2 py-1 border-b border-border-soft"
                >
                  <Badge
                    variant={
                      e.status === "verified"
                        ? "emerald"
                        : e.status === "quarantined"
                        ? "amber"
                        : "red"
                    }
                  >
                    {e.status}
                  </Badge>
                  <span className="text-text">{e.manifest.mcpName}</span>
                  <span className="text-text-3">@{e.manifest.version}</span>
                  <span className="text-text-3 ml-auto">
                    sdk: {e.manifest.sdk_version}
                  </span>
                </div>
              ))}
              {(entriesQ.data?.entries ?? []).length === 0 && (
                <div className="text-text-3 italic">
                  Atlas offline — Stage UI can still render fleet, but the AI-BOM
                  panel needs Atlas /registry/entries.
                </div>
              )}
            </div>
          </motion.div>
        )}
      </div>
    </SceneShell>
  );
}

function BigStat({
  label,
  value,
  tone,
  show,
}: {
  label: string;
  value: number;
  tone: "emerald" | "amber" | "red";
  show: boolean;
}) {
  const toneCls = {
    emerald: "text-emerald",
    amber: "text-amber",
    red: "text-red",
  }[tone];
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: show ? 1 : 0, y: show ? 0 : 8 }}
      transition={{ duration: 0.4 }}
      className="rounded-xl border border-border bg-surface p-5"
    >
      <div className="h-section">{label}</div>
      <div className={`num-callout mt-2 ${toneCls}`}>{value}</div>
    </motion.div>
  );
}
