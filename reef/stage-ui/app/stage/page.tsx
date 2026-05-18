import Link from "next/link";
import { ArrowRight } from "lucide-react";

const SCENES = [
  {
    href: "/stage/cold-open",
    title: "cold-open",
    subtitle: "2-minute headline arc · title → MCP block → wave → EchoLeak → shark → RIA → close",
  },
  {
    href: "/stage/discover",
    title: "discover",
    subtitle: "FleetGrid + AI-BOM panel · Atlas /registry/entries live",
  },
  {
    href: "/stage/build",
    title: "build",
    subtitle: "PolicyDiff (plain English) + Gemini Pro × Flash duo",
  },
  {
    href: "/stage/run",
    title: "run",
    subtitle: "DAST-A shark + live attack/defense scoreboard + pack catalog",
  },
  {
    href: "/stage/score",
    title: "score",
    subtitle: "RIAArtifactReveal + Compliance wall (3-state coverage)",
  },
];

/** /stage — directory of the 5 OBS-capturable scenes. Not linked from the
 *  Public Safety Page; reachable only by direct URL during a rehearsal. */
export default function StageIndex() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <div className="text-text-3 mono text-xs uppercase tracking-widest mb-3">
        REEF · stage scenes
      </div>
      <h1 className="display text-5xl text-text mb-8">
        OBS capture scenes
      </h1>
      <p className="text-text-2 mb-10">
        Each scene auto-advances on a fixed cadence. Use space/r/←/→ to control.
        Open each in a 1080p browser window and capture via OBS. These pages
        are intentionally not linked from the main Public Safety Page — they
        are dedicated full-screen visuals for video.
      </p>

      <div className="space-y-3">
        {SCENES.map((s) => (
          <Link
            key={s.href}
            href={s.href}
            className="group flex items-center justify-between rounded-2xl border border-border bg-surface px-6 py-5 hover:border-emerald/40 transition-colors"
          >
            <div>
              <div className="display text-2xl text-text group-hover:text-emerald transition-colors">
                /stage/{s.title}
              </div>
              <div className="text-sm text-text-3 mt-1">{s.subtitle}</div>
            </div>
            <ArrowRight className="h-5 w-5 text-text-3 group-hover:text-emerald group-hover:translate-x-1 transition-all" />
          </Link>
        ))}
      </div>
    </main>
  );
}
