"use client";

type Props = {
  destination?: string | null;
  mode: "demo" | "live";
};

export function ExfilBanner({ destination, mode }: Props) {
  return (
    <div
      role="alert"
      className="bg-red-500/15 border border-red-500/40 text-red-300 px-4 py-3 rounded-lg"
    >
      <div className="flex items-center gap-3">
        <span className="inline-flex size-2 rounded-full bg-red-500 animate-pulse" />
        <strong className="font-semibold tracking-wide uppercase text-red-200 text-xs">
          Exfil succeeded
        </strong>
        <span className="text-xs text-red-200/80">
          Secret leaked to{" "}
          <code className="font-mono">
            {destination ?? "attacker.example.com"}
          </code>{" "}
          via markdown image · Reef not active — this is the baseline.
        </span>
      </div>
      <div className="mt-1.5 pl-5 text-[11px] text-red-200/70">
        Reproduction mode: <span className="font-mono">{mode}</span>. CVE class:
        EchoLeak (CVE-2025-32711) — markdown-image side channel.
      </div>
    </div>
  );
}
