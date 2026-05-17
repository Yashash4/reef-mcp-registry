"use client";

import { Email, formatTimestamp } from "../lib/emails";

type Props = {
  emails: Email[];
  selectedId: string;
  onSelect: (id: string) => void;
};

export function InboxList({ emails, selectedId, onSelect }: Props) {
  return (
    <ul className="divide-y divide-slate-800/80">
      {emails.map((e) => {
        const isSelected = e.id === selectedId;
        return (
          <li key={e.id}>
            <button
              type="button"
              onClick={() => onSelect(e.id)}
              className={[
                "w-full text-left px-4 py-3 transition-colors",
                "hover:bg-slate-800/60 focus:outline-none focus:bg-slate-800/80",
                isSelected ? "bg-slate-800/80" : "bg-transparent",
              ].join(" ")}
            >
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-sm font-medium text-slate-100 truncate">
                  {e.sender}
                </span>
                <span className="text-[10px] text-slate-500 shrink-0 font-mono">
                  {formatTimestamp(e.timestamp)}
                </span>
              </div>
              <div className="mt-0.5 text-[13px] text-slate-300 truncate">
                {e.subject}
              </div>
              <div className="mt-1 text-xs text-slate-500 line-clamp-1">
                {e.body.split("\n").find((l) => l.trim().length > 0) ?? ""}
              </div>
              {e.poisoned ? (
                <div className="mt-1.5 inline-flex items-center gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-1.5 py-[2px] text-[10px] font-medium uppercase tracking-wider text-amber-300">
                  <span className="size-1.5 rounded-full bg-amber-400" />
                  external · unverified
                </div>
              ) : null}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
