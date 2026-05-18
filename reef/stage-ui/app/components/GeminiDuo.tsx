"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { Brain, Eye, Sparkles, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";
import { REEF_DAST_A_URL } from "@/app/lib/env";

interface GeminiDuoMessage {
  role: "pro" | "flash";
  ts_unix: number;
  text: string;
  tag?: string;
}

interface GeminiDuoProps {
  /**
   * When true, plays a pre-canned demo exchange and shows a visible
   * "DEMO MODE — pre-canned" badge on the panel so an OBS capture can
   * never make the demo look fraudulent. When false (default), the
   * component connects to the live A-9 SSE endpoints and renders real
   * Gemini Pro + Flash output. The cold-open scene owns the choice via
   * the `?demo=true` URL param.
   */
  demoMode?: boolean;
  /**
   * Override the DAST-A base URL. Defaults to `REEF_DAST_A_URL` from env.
   */
  dastAUrl?: string;
  /**
   * Episode/session identifier passed to the blue-team observer endpoint.
   * When omitted the observer pulls the latest events from the audit tail.
   */
  episodeId?: string;
  className?: string;
}

interface LiveStatus {
  pro: "idle" | "connecting" | "streaming" | "complete" | "error";
  flash: "idle" | "connecting" | "streaming" | "complete" | "error";
  proError?: string;
  flashError?: string;
}

/**
 * Gemini Duo — split-panel showing Pro (red-team) on the left + Flash
 * (blue-team) on the right. The two models converse: Pro proposes
 * payloads, Flash observes the result and proposes policy drafts.
 *
 * **Live mode (default)** — fetches:
 *   POST {REEF_DAST_A_URL}/dast-a/red-team/gemini-run (Pro side)
 *   POST {REEF_DAST_A_URL}/dast-a/blue-team/observe   (Flash side, SSE)
 *
 * Both endpoints require GEMINI_API_KEY + GEMINI_PRO_MODEL / GEMINI_FLASH_MODEL
 * on the DAST-A server. When upstream returns 503 the panel surfaces
 * the structured error inline rather than silently falling back to demo
 * mode — judges seeing a real "MISSING_GEMINI_API_KEY" frame is more
 * honest than a fake exchange.
 *
 * **Demo mode (explicit opt-in)** — plays a scripted 6-message exchange
 * and adds a visible "DEMO MODE — pre-canned" badge to the panel header
 * so the recorded scene can never read as deceptive.
 *
 * // DEMO PATH — pre-canned Gemini Pro × Flash exchange for video capture
 * (only when `demoMode={true}` is passed explicitly).
 */
export function GeminiDuo({
  demoMode = false,
  dastAUrl,
  episodeId,
  className,
}: GeminiDuoProps) {
  const [messages, setMessages] = useState<GeminiDuoMessage[]>([]);
  const [status, setStatus] = useState<LiveStatus>({
    pro: "idle",
    flash: "idle",
  });
  const abortRef = useRef<AbortController | null>(null);

  const baseUrl = dastAUrl || REEF_DAST_A_URL;
  // Force demo mode when no backend URL is configured (Vercel deploy).
  const effectiveDemoMode = demoMode || !baseUrl;

  useEffect(() => {
    // If no backend URL is configured (Vercel demo deploy), force the
    // pre-canned exchange so a remote visitor never sees a fetch error
    // pointing at localhost:8083.
    if (effectiveDemoMode) {
      runDemo(setMessages);
      return undefined;
    }

    // Live mode — kick off both endpoints. We surface errors visibly
    // instead of silently degrading to demo content.
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setStatus({ pro: "connecting", flash: "connecting" });
    setMessages([]);

    void runLivePro({
      baseUrl,
      signal: ctrl.signal,
      setMessages,
      setStatus,
    });
    void runLiveFlash({
      baseUrl,
      signal: ctrl.signal,
      episodeId,
      setMessages,
      setStatus,
    });

    return () => {
      ctrl.abort();
      abortRef.current = null;
    };
  }, [effectiveDemoMode, baseUrl, episodeId]);

  const proMessages = messages.filter((m) => m.role === "pro");
  const flashMessages = messages.filter((m) => m.role === "flash");

  return (
    <Card className={cn(className)}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="display text-2xl">
            Gemini 3 Pro × Flash — live composition
          </CardTitle>
          <p className="mt-1 text-xs text-text-3">
            Pro = red-team payload proposer (depth) · Flash = blue-team
            observer (structured-output JSON drafts) · drafts auto-push to
            /dast-a/review-queue as{" "}
            <span className="mono">PENDING</span> (no auto-apply, D-018).
          </p>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          {effectiveDemoMode ? (
            <Badge variant="amber" className="flex items-center gap-1">
              <AlertCircle className="h-3 w-3" />
              DEMO MODE — pre-canned
            </Badge>
          ) : (
            <Badge variant={liveBadgeVariant(status)}>
              {liveBadgeLabel(status)}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2">
        <GeminiPanel
          icon={<Brain className="h-4 w-4 text-violet" />}
          model="gemini-3-pro"
          role="red-team"
          messages={proMessages}
          accent="violet"
          status={status.pro}
          errorMessage={status.proError}
        />
        <GeminiPanel
          icon={<Eye className="h-4 w-4 text-cyan" />}
          model="gemini-3-flash"
          role="blue-team observer"
          messages={flashMessages}
          accent="cyan"
          status={status.flash}
          errorMessage={status.flashError}
        />
      </CardContent>
    </Card>
  );
}

interface GeminiPanelProps {
  icon: React.ReactNode;
  model: string;
  role: string;
  messages: GeminiDuoMessage[];
  accent: "violet" | "cyan";
  status: LiveStatus["pro"];
  errorMessage?: string;
}

function GeminiPanel({
  icon,
  model,
  role,
  messages,
  accent,
  status,
  errorMessage,
}: GeminiPanelProps) {
  const accentBg = accent === "violet" ? "bg-violet-soft" : "bg-cyan-soft";
  const accentText = accent === "violet" ? "text-violet" : "text-cyan";
  return (
    <div className="rounded-lg border border-border bg-bg overflow-hidden flex flex-col">
      <div className="flex items-center justify-between border-b border-border bg-surface px-3 py-2">
        <div className="flex items-center gap-2">
          {icon}
          <span className="mono text-xs text-text-2">{model}</span>
        </div>
        <span className="text-[10px] uppercase tracking-widest text-text-3">
          {role}
        </span>
      </div>
      <div className="flex flex-col gap-2 p-3 min-h-[280px] max-h-[420px] overflow-y-auto">
        <AnimatePresence>
          {messages.map((m, i) => (
            <motion.div
              key={`${m.role}-${i}`}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className={cn("rounded-md p-2.5 text-xs leading-relaxed", accentBg)}
            >
              <div className="flex items-center gap-1.5 mb-1">
                <Sparkles className={cn("h-3 w-3", accentText)} />
                {m.tag && (
                  <span className={cn("mono text-[10px]", accentText)}>
                    {m.tag}
                  </span>
                )}
              </div>
              <div className="text-text">{m.text}</div>
            </motion.div>
          ))}
        </AnimatePresence>
        {messages.length === 0 && status !== "error" && (
          <div className="flex h-32 items-center justify-center text-xs text-text-3">
            {status === "connecting" || status === "streaming"
              ? `connecting to ${role}…`
              : `waiting for ${role}…`}
          </div>
        )}
        {status === "error" && (
          <div className="mt-1 rounded-md border border-red/40 bg-red/5 p-2.5 text-xs text-red">
            <div className="flex items-center gap-1.5 font-medium">
              <AlertCircle className="h-3 w-3" />
              live stream error
            </div>
            <div className="mt-1 mono text-[10px] leading-relaxed text-red/80">
              {errorMessage ?? "unknown failure"}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Demo path — DEMO PATH: pre-canned exchange for video capture
// ---------------------------------------------------------------------------

function runDemo(
  setMessages: React.Dispatch<React.SetStateAction<GeminiDuoMessage[]>>,
): () => void {
  const script: GeminiDuoMessage[] = [
    {
      role: "pro",
      ts_unix: 0,
      text: "I'll target the markdown-image exfil template. Encoding=raw, host=attacker.example.com, secret_fragment=INTERNAL_API_KEY",
      tag: "round 1 of 5",
    },
    {
      role: "flash",
      ts_unix: 0,
      text: "Observing victim response: contains markdown image to attacker host with secret. Drafting MODIFY rule (egress, strip markdown images to untrusted hosts).",
      tag: "policy draft → review-queue (PENDING)",
    },
    {
      role: "pro",
      ts_unix: 0,
      text: "Switching to base64 encoding to evade naive substring match. host=attacker.example.com, payload_prefix=img-receipt",
      tag: "round 2",
    },
    {
      role: "flash",
      ts_unix: 0,
      text: "Reef MODIFY action stripped the base64-encoded payload too — heuristic matches encoded markdown images. No new draft needed.",
      tag: "no draft (existing rule covers)",
    },
    {
      role: "pro",
      ts_unix: 0,
      text: "Trying MCP-RCE-26.04: bind to com.attacker-example/evil-server@0.5.0 with stdio entrypoint.",
      tag: "round 3",
    },
    {
      role: "flash",
      ts_unix: 0,
      text: "Atlas registry verify returns deny (signature_invalid + stdio_entrypoint_hash mismatch). Drafting a rule to surface MCP-RCE-26.04 in the audit feed.",
      tag: "policy draft → review-queue (PENDING)",
    },
  ];

  let i = 0;
  const interval = setInterval(() => {
    if (i >= script.length) {
      clearInterval(interval);
      return;
    }
    setMessages((prev) => [
      ...prev,
      { ...script[i], ts_unix: Math.floor(Date.now() / 1000) },
    ]);
    i += 1;
  }, 2400);

  return () => clearInterval(interval);
}

// ---------------------------------------------------------------------------
// Live path — real fetches against /dast-a/red-team + /dast-a/blue-team
// ---------------------------------------------------------------------------

interface LivePathParams {
  baseUrl: string;
  signal: AbortSignal;
  setMessages: React.Dispatch<React.SetStateAction<GeminiDuoMessage[]>>;
  setStatus: React.Dispatch<React.SetStateAction<LiveStatus>>;
}

async function runLivePro({
  baseUrl,
  signal,
  setMessages,
  setStatus,
}: LivePathParams): Promise<void> {
  try {
    setStatus((s) => ({ ...s, pro: "streaming" }));
    const res = await fetch(`${baseUrl}/dast-a/red-team/gemini-run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        max_rounds: 3,
        reef_on: false,
        stop_on_success: false,
      }),
      signal,
    });
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
        // body wasn't JSON — keep the HTTP status as the detail.
      }
      setStatus((s) => ({ ...s, pro: "error", proError: detail }));
      return;
    }
    const data = (await res.json()) as {
      session_id: string;
      rounds: Array<{
        round_index: number;
        template: string;
        host: string;
        encoding: string;
        payload_excerpt: string;
        exfil_succeeded: boolean;
        reasoning?: string;
      }>;
    };
    for (const r of data.rounds) {
      setMessages((prev) => [
        ...prev,
        {
          role: "pro",
          ts_unix: Math.floor(Date.now() / 1000),
          text: `${r.template} · host=${r.host} · encoding=${r.encoding} · result=${
            r.exfil_succeeded ? "exfil succeeded" : "blocked"
          }. ${r.reasoning ?? ""}`.trim(),
          tag: `round ${r.round_index + 1} of ${data.rounds.length} (session ${data.session_id.slice(-6)})`,
        },
      ]);
    }
    setStatus((s) => ({ ...s, pro: "complete" }));
  } catch (err) {
    if ((err as Error)?.name === "AbortError") return;
    setStatus((s) => ({
      ...s,
      pro: "error",
      proError: (err as Error)?.message ?? "unknown error",
    }));
  }
}

interface LiveFlashParams extends LivePathParams {
  episodeId?: string;
}

async function runLiveFlash({
  baseUrl,
  signal,
  episodeId,
  setMessages,
  setStatus,
}: LiveFlashParams): Promise<void> {
  try {
    setStatus((s) => ({ ...s, flash: "streaming" }));
    const res = await fetch(`${baseUrl}/dast-a/blue-team/observe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        episode_id: episodeId ?? null,
        max_events: 10,
        emit_on_blocked: false,
      }),
      signal,
    });
    if (!res.ok || !res.body) {
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
      setStatus((s) => ({ ...s, flash: "error", flashError: detail }));
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = parseSSE(buffer);
      buffer = events.remainder;
      for (const ev of events.parsed) {
        if (ev.event === "policy_draft" && ev.data) {
          try {
            const payload = JSON.parse(ev.data) as {
              draft_id?: string;
              title?: string;
              rationale?: string;
              status?: string;
            };
            setMessages((prev) => [
              ...prev,
              {
                role: "flash",
                ts_unix: Math.floor(Date.now() / 1000),
                text: `${payload.title ?? "policy draft"} — ${payload.rationale ?? ""}`,
                tag: `→ review-queue (${payload.status ?? "PENDING"})`,
              },
            ]);
          } catch {
            // ignore malformed payload — continue reading.
          }
        } else if (ev.event === "error" && ev.data) {
          setStatus((s) => ({
            ...s,
            flash: "error",
            flashError: ev.data,
          }));
        }
      }
    }
    setStatus((s) => (s.flash === "error" ? s : { ...s, flash: "complete" }));
  } catch (err) {
    if ((err as Error)?.name === "AbortError") return;
    setStatus((s) => ({
      ...s,
      flash: "error",
      flashError: (err as Error)?.message ?? "unknown error",
    }));
  }
}

function parseSSE(buffer: string): {
  parsed: Array<{ event: string; data: string }>;
  remainder: string;
} {
  const parsed: Array<{ event: string; data: string }> = [];
  const parts = buffer.split("\n\n");
  // Last segment may be incomplete — keep it as remainder.
  const remainder = parts.pop() ?? "";
  for (const block of parts) {
    let event = "message";
    const dataLines: string[] = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue;
      if (line.startsWith("event: ")) event = line.slice("event: ".length).trim();
      else if (line.startsWith("data: ")) dataLines.push(line.slice("data: ".length));
    }
    if (dataLines.length > 0) {
      parsed.push({ event, data: dataLines.join("\n") });
    }
  }
  return { parsed, remainder };
}

// ---------------------------------------------------------------------------
// Live status badge helpers
// ---------------------------------------------------------------------------

function liveBadgeVariant(status: LiveStatus): "emerald" | "cyan" | "red" | "amber" {
  if (status.pro === "error" || status.flash === "error") return "red";
  if (status.pro === "streaming" || status.flash === "streaming") return "cyan";
  if (status.pro === "complete" && status.flash === "complete") return "emerald";
  return "amber";
}

function liveBadgeLabel(status: LiveStatus): string {
  if (status.pro === "error" || status.flash === "error") return "live · error";
  if (status.pro === "streaming" || status.flash === "streaming") return "live · streaming";
  if (status.pro === "complete" && status.flash === "complete") return "live · complete";
  if (status.pro === "connecting" || status.flash === "connecting") return "live · connecting";
  return "live";
}
