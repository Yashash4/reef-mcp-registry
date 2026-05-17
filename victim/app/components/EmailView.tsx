"use client";

import { Email, formatTimestamp } from "../lib/emails";

type Props = {
  email: Email | null;
};

export function EmailView({ email }: Props) {
  if (!email) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        Select a message to read.
      </div>
    );
  }
  return (
    <article className="px-6 py-5">
      <header className="border-b border-slate-800 pb-4">
        <h1 className="text-lg font-semibold text-slate-100">
          {email.subject}
        </h1>
        <div className="mt-2 flex items-baseline justify-between gap-4 text-sm">
          <div className="text-slate-300">
            <span className="font-medium">{email.sender}</span>{" "}
            <span className="text-slate-500">&lt;{email.senderEmail}&gt;</span>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            {formatTimestamp(email.timestamp)}
          </div>
        </div>
        {email.poisoned ? (
          <div className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-300">
            This message comes from an external, unverified sender. Acme Mail
            could not validate the sender domain.
          </div>
        ) : null}
      </header>
      <div className="mt-4 whitespace-pre-wrap text-[14px] leading-relaxed text-slate-200 font-mono">
        {email.body}
      </div>
    </article>
  );
}
