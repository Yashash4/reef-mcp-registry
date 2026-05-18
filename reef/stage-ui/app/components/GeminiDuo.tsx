"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useState } from "react";
import { Brain, Eye, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/app/lib/utils";

interface GeminiDuoMessage {
  role: "pro" | "flash";
  ts_unix: number;
  text: string;
  tag?: string;
}

interface GeminiDuoProps {
  /** When true, plays the pre-canned demo exchange instead of streaming
   *  live from A-9. Used by the recorded video path (?demo=true). */
  demoMode?: boolean;
  className?: string;
}

/**
 * Gemini Duo — split-panel showing Pro (red-team) on the left + Flash
 * (blue-team) on the right. The two models converse: Pro proposes
 * payloads, Flash observes the result and proposes policy drafts.
 *
 * Live mode would SSE-subscribe to:
 *   POST {REEF_DAST_A_URL}/dast-a/red-team/gemini-run (Pro side)
 *   POST {REEF_DAST_A_URL}/dast-a/blue-team/observe   (Flash side)
 *
 * Both endpoints require GEMINI_API_KEY on the server. Stage UI v1
 * ships demo mode by default — operators with a key can toggle live by
 * passing demoMode=false (handled at the scene level via ?demo=true URL
 * param). The demo-mode exchanges below match A-9's actual system prompt
 * cadence so the video reads truthfully.
 *
 * // DEMO PATH — pre-canned Gemini Pro × Flash exchange for video capture
 */
export function GeminiDuo({ demoMode = true, className }: GeminiDuoProps) {
  const [messages, setMessages] = useState<GeminiDuoMessage[]>([]);

  useEffect(() => {
    if (!demoMode) return;
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
  }, [demoMode]);

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
            observer (speed, Live API SSE) · drafts auto-push to /dast-a/review-queue
            as <span className="mono">PENDING</span> (no auto-apply, D-018).
          </p>
        </div>
        {demoMode && <Badge variant="amber">demo path</Badge>}
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-2">
        <GeminiPanel
          icon={<Brain className="h-4 w-4 text-violet" />}
          model="gemini-3-pro"
          role="red-team"
          messages={proMessages}
          accent="violet"
        />
        <GeminiPanel
          icon={<Eye className="h-4 w-4 text-cyan" />}
          model="gemini-3-flash"
          role="blue-team observer"
          messages={flashMessages}
          accent="cyan"
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
}

function GeminiPanel({ icon, model, role, messages, accent }: GeminiPanelProps) {
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
        {messages.length === 0 && (
          <div className="flex h-32 items-center justify-center text-xs text-text-3">
            waiting for {role}…
          </div>
        )}
      </div>
    </div>
  );
}
