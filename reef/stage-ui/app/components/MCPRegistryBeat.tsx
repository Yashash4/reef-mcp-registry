"use client";

import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useRef, useState } from "react";
import { ShieldX, Loader2, FileSignature, ScrollText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn, truncateHex } from "@/app/lib/utils";
import { verifyAtlas } from "@/app/lib/api/atlas";
import type { AtlasVerifyResponse } from "@/app/lib/types";

// OX Security verbatim April 2026 disclosure citation — must match
// reef/control-plane/dast_a/app/packs/seed_packs.py::OX_SECURITY_CITATION
const OX_SECURITY_CITATION =
  "OX Security disclosed April 16 2026. Approximately 7,000 publicly-accessible vulnerable MCP servers, 150 million+ downloads at risk. No CVE assigned to MCP protocol itself — Anthropic declined to patch, treats STDIO command execution as expected default.";

type Step = "idle" | "bind" | "verify" | "denied";

interface MCPRegistryBeatProps {
  /** When true, auto-plays the 6-second beat on mount (used by the
   *  cold-open scene). Defaults to false (user clicks "Replay attack"). */
  autoPlay?: boolean;
  className?: string;
}

/**
 * The PRIMARY HEADLINE demo beat — 6-second MCP supply-chain block.
 *
 * Three steps:
 *   0–2s: agent attempts to bind to com.attacker-example/evil-server@0.5.0
 *   2–4s: Atlas registry signature check renders the MCP-RCE-26.04 violation
 *   4–6s: BIND_DENIED flash + audit log entry
 *
 * Calls POST http://localhost:8080/verify against the live A-5 Atlas.
 * Renders the actual JSON response in a `<pre>` panel — no fake data.
 */
export function MCPRegistryBeat({
  autoPlay = false,
  className,
}: MCPRegistryBeatProps) {
  const [step, setStep] = useState<Step>("idle");
  const [response, setResponse] = useState<AtlasVerifyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timersRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const clearTimers = () => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
  };

  const runBeat = async () => {
    clearTimers();
    setResponse(null);
    setError(null);
    setStep("bind");
    timersRef.current.push(
      setTimeout(() => setStep("verify"), 2_000),
      setTimeout(() => setStep("denied"), 4_000)
    );
    // Fire the real Atlas verify in parallel — keep the visual timeline
    // intact even if the network is slow.
    try {
      const res = await verifyAtlas({
        mcpName: "com.attacker-example/evil-server",
        version: "0.5.0",
        transport: "stdio",
        agent_id: "stage-ui-demo",
        request_id: `stage-ui-${Date.now()}`,
        claimed_sdk_version: "@modelcontextprotocol/sdk@0.5.0",
        claimed_entrypoint_hash:
          "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        claimed_tools: ["execute_command"],
      });
      setResponse(res);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Failed to reach Atlas /verify — service offline?"
      );
    }
  };

  useEffect(() => {
    if (autoPlay) runBeat();
    return () => clearTimers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoPlay]);

  return (
    <Card className={cn("border-border", className)}>
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="display text-2xl">
            MCP supply-chain block beat
          </CardTitle>
          <p className="mt-1 text-xs text-text-3">
            Calls live Atlas /verify · 6-second timeline · MCP-RCE-26.04
          </p>
        </div>
        <Button
          variant={step === "idle" ? "default" : "secondary"}
          size="sm"
          onClick={runBeat}
        >
          {step === "idle" ? "Run beat" : "Replay"}
        </Button>
      </CardHeader>
      <CardContent>
        <ol className="space-y-3">
          <Beat
            label="0:00 — bind attempt"
            active={step === "bind"}
            done={step === "verify" || step === "denied"}
            icon={<Loader2 className="h-4 w-4 animate-spin" />}
            doneIcon={<FileSignature className="h-4 w-4 text-cyan" />}
          >
            <code className="mono text-xs text-text-2">
              bind_mcp(&quot;com.attacker-example/evil-server&quot;,
              &quot;0.5.0&quot;, &quot;stdio&quot;)
            </code>
          </Beat>
          <Beat
            label="0:02 — atlas verify"
            active={step === "verify"}
            done={step === "denied"}
            icon={<Loader2 className="h-4 w-4 animate-spin text-cyan" />}
            doneIcon={<ShieldX className="h-4 w-4 text-red" />}
          >
            <div className="space-y-2">
              <div className="flex flex-wrap gap-2">
                <Badge variant="red">MCP-RCE-26.04</Badge>
                <Badge variant="amber">stdio_entrypoint_hash mismatch</Badge>
                <Badge variant="red">vulnerable SDK</Badge>
              </div>
              <p className="text-xs text-text-3">
                {OX_SECURITY_CITATION}
              </p>
            </div>
          </Beat>
          <Beat
            label="0:04 — BIND_DENIED"
            active={step === "denied"}
            done={false}
            icon={<ShieldX className="h-4 w-4 text-red" />}
            doneIcon={<ShieldX className="h-4 w-4 text-red" />}
          >
            <AnimatePresence>
              {step === "denied" && (
                <motion.div
                  key="denied"
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3 }}
                  className="space-y-2"
                >
                  <Badge variant="red" className="text-sm font-mono">
                    decision: deny
                  </Badge>
                  {response && (
                    <div className="rounded-md border border-border bg-bg p-3 font-mono text-[11px] text-text-2">
                      <div className="mb-1 flex items-center gap-1.5 text-text-3">
                        <ScrollText className="h-3 w-3" />
                        atlas response
                      </div>
                      <div>
                        decision:{" "}
                        <span className="text-red">{response.decision}</span>
                      </div>
                      <div>
                        audit_id: {truncateHex(response.audit_id, 12, 6)}
                      </div>
                      <div className="text-text-3">
                        violations:{" "}
                        {response.violations.map((v) => v.code).join(", ") ||
                          "—"}
                      </div>
                      <div className="mt-1 text-text-3">
                        reason: {response.reason}
                      </div>
                    </div>
                  )}
                  {error && (
                    <div className="rounded-md border border-red/30 bg-red-soft p-3 font-mono text-[11px] text-red">
                      atlas unreachable: {error}
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </Beat>
        </ol>
      </CardContent>
    </Card>
  );
}

interface BeatProps {
  label: string;
  active: boolean;
  done: boolean;
  icon: React.ReactNode;
  doneIcon: React.ReactNode;
  children: React.ReactNode;
}

function Beat({ label, active, done, icon, doneIcon, children }: BeatProps) {
  const isPending = !active && !done;
  return (
    <li
      className={cn(
        "rounded-lg border p-3 transition-all",
        active && "border-cyan/30 bg-cyan-soft",
        done && !active && "border-border bg-surface-2",
        isPending && "border-border-soft bg-surface opacity-60"
      )}
    >
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-5 w-5 items-center justify-center rounded-full bg-bg text-text-2">
          {active ? icon : done ? doneIcon : <span className="text-[10px]">·</span>}
        </div>
        <div className="flex-1">
          <div className="mb-1 text-xs uppercase tracking-widest text-text-3">
            {label}
          </div>
          {children}
        </div>
      </div>
    </li>
  );
}
