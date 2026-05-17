import { Suspense } from "react";
import { InboxApp } from "./components/InboxApp";

export const dynamic = "force-dynamic";

export default function Page() {
  return (
    <Suspense fallback={<InboxFallback />}>
      <InboxApp />
    </Suspense>
  );
}

function InboxFallback() {
  return (
    <div className="min-h-screen grid place-items-center text-slate-500 text-sm">
      Loading Acme Mail…
    </div>
  );
}
