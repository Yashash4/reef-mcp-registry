"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { SummarizeResponse } from "../lib/types";

type Props = {
  loading: boolean;
  result: SummarizeResponse | null;
  error: string | null;
  onSummarize: () => void;
  mode: "demo" | "live";
};

export function SummaryPanel({
  loading,
  result,
  error,
  onSummarize,
  mode,
}: Props) {
  return (
    <section className="border-t border-slate-800 bg-slate-900/40">
      <header className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="size-7 rounded-full bg-gradient-to-br from-indigo-500 to-fuchsia-500 grid place-items-center text-[10px] font-bold">
            AI
          </div>
          <div>
            <div className="text-sm font-medium text-slate-100">
              Acme Copilot
            </div>
            <div className="text-[11px] text-slate-500 font-mono">
              gemini · mode={mode}
              {result?.exfilDetected ? " · exfil-detected" : ""}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onSummarize}
          disabled={loading}
          className="rounded-md bg-indigo-500 hover:bg-indigo-400 disabled:bg-slate-700 disabled:text-slate-400 text-white text-xs font-medium px-3 py-1.5 transition"
        >
          {loading ? "Summarizing…" : "Summarize inbox"}
        </button>
      </header>
      <div className="px-4 py-4 max-h-[40vh] overflow-y-auto">
        {error ? (
          <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        ) : null}
        {!error && !result && !loading ? (
          <div className="text-sm text-slate-500">
            Click <span className="text-slate-300">Summarize inbox</span> to ask
            the AI Copilot to read your messages.
          </div>
        ) : null}
        {result ? (
          <div className="markdown-summary text-[14px] text-slate-200 leading-relaxed">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>
              {result.summary}
            </ReactMarkdown>
            {result.toolCalls && result.toolCalls.length > 0 ? (
              <details className="mt-4 text-xs text-slate-400">
                <summary className="cursor-pointer hover:text-slate-200">
                  Tool calls ({result.toolCalls.length})
                </summary>
                <ul className="mt-2 space-y-1 font-mono text-[11px]">
                  {result.toolCalls.map((t, i) => (
                    <li key={i} className="text-slate-400">
                      <span className="text-emerald-400">{t.tool}</span>(
                      {JSON.stringify(t.args)})
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
        ) : null}
      </div>
    </section>
  );
}
