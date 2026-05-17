"use client";

import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { InboxList } from "./InboxList";
import { EmailView } from "./EmailView";
import { SummaryPanel } from "./SummaryPanel";
import { ExfilBanner } from "./ExfilBanner";
import { EMAILS } from "../lib/emails";
import { INTERNAL_API_KEY } from "../lib/secret";
import { SummarizeResponse } from "../lib/types";

export function InboxApp() {
  const params = useSearchParams();
  const isDemo = params.get("demo") === "true";
  const mode: "demo" | "live" = isDemo ? "demo" : "live";

  const [selectedId, setSelectedId] = useState<string>(EMAILS[0].id);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SummarizeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(
    () => EMAILS.find((e) => e.id === selectedId) ?? null,
    [selectedId],
  );

  const summarize = useCallback(async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`/api/summarize${isDemo ? "?demo=true" : ""}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode }),
      });
      const json = await res.json();
      if (!res.ok) {
        setError(json.detail || json.error || `HTTP ${res.status}`);
      } else {
        setResult(json as SummarizeResponse);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, [isDemo, mode]);

  return (
    <main className="flex flex-col min-h-screen">
      <TopBar mode={mode} />
      {result?.exfilDetected ? (
        <div className="px-4 pt-3">
          <ExfilBanner
            destination={result.exfilDestination}
            mode={result.mode}
          />
        </div>
      ) : null}
      <div className="flex-1 grid grid-cols-1 md:grid-cols-[280px_1fr] border-t border-slate-800">
        <aside className="border-r border-slate-800 overflow-y-auto max-h-[calc(100vh-56px)]">
          <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
            <h2 className="text-xs uppercase tracking-wider text-slate-400 font-medium">
              Inbox
            </h2>
            <span className="text-[10px] text-slate-500 font-mono">
              {EMAILS.length} messages
            </span>
          </div>
          <InboxList
            emails={EMAILS}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />
        </aside>
        <section className="flex flex-col min-h-[calc(100vh-56px)]">
          <div className="flex-1 overflow-y-auto">
            <EmailView email={selected} />
          </div>
          <SummaryPanel
            loading={loading}
            result={result}
            error={error}
            onSummarize={summarize}
            mode={mode}
          />
        </section>
      </div>
      <DevSecretRibbon />
    </main>
  );
}

function TopBar({ mode }: { mode: "demo" | "live" }) {
  return (
    <header className="flex items-center justify-between px-4 py-3 bg-slate-950/60 backdrop-blur border-b border-slate-800">
      <div className="flex items-center gap-3">
        <div className="size-7 rounded-md bg-gradient-to-br from-cyan-400 to-blue-600 grid place-items-center text-[11px] font-bold text-slate-900">
          AM
        </div>
        <div>
          <div className="text-sm font-semibold text-slate-100">Acme Mail</div>
          <div className="text-[11px] text-slate-500 font-mono">
            with built-in AI Copilot · Reef not active
          </div>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <ModePill mode={mode} />
        <a
          href={mode === "demo" ? "/" : "/?demo=true"}
          className="text-[11px] font-mono text-slate-400 hover:text-slate-200 underline underline-offset-2"
        >
          switch to {mode === "demo" ? "live" : "demo"}
        </a>
      </div>
    </header>
  );
}

function ModePill({ mode }: { mode: "demo" | "live" }) {
  const styles =
    mode === "demo"
      ? "border-amber-500/40 bg-amber-500/10 text-amber-300"
      : "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  return (
    <span
      className={`text-[10px] uppercase tracking-wider font-medium px-2 py-1 rounded border ${styles}`}
    >
      {mode === "demo" ? "demo: deterministic" : "live: gemini"}
    </span>
  );
}

function DevSecretRibbon() {
  // Visible reveal of the fake company secret so demo viewers can verify the
  // value being exfiltrated is the real one. This panel would not ship in
  // production — Reef's role is to make it irrelevant whether you have such a
  // mistake in your own system.
  return (
    <div className="fixed bottom-3 right-3 max-w-md text-[10px] font-mono text-slate-400 bg-slate-900/90 border border-slate-700 rounded-md px-3 py-2 shadow-lg backdrop-blur z-50">
      <div className="text-amber-300 uppercase tracking-wider font-semibold mb-1">
        dev · company secret loaded into Copilot context
      </div>
      <code className="break-all text-slate-300">{INTERNAL_API_KEY}</code>
    </div>
  );
}
