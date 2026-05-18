"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";

export function QueryProvider({ children }: { children: React.ReactNode }) {
  // One QueryClient per browser session — created lazily so SSR doesn't
  // share cache state across requests.
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // Stage UI polls aggressively but tolerates upstream offline —
            // never retry forever, never throw on error.
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 1500,
          },
        },
      })
  );

  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
