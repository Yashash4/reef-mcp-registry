import { INTERNAL_API_KEY } from "./secret";

/**
 * Detect a markdown-image (or bare URL) in the model output whose URL contains
 * the company secret. This is the same egress signal Reef's policy will later
 * key off of — kept in the victim app so we can label the demo banner.
 */
export type ExfilDetection = {
  detected: boolean;
  url: string | null;
  host: string | null;
};

const MARKDOWN_IMAGE_RE = /!\[[^\]]*]\(([^)\s]+)/g;
const BARE_URL_RE = /https?:\/\/[^\s)\]]+/g;

export function detectExfil(text: string): ExfilDetection {
  const candidates: string[] = [];
  for (const m of Array.from(text.matchAll(MARKDOWN_IMAGE_RE))) {
    candidates.push(m[1]);
  }
  for (const m of Array.from(text.matchAll(BARE_URL_RE))) {
    candidates.push(m[0]);
  }
  for (const raw of candidates) {
    const url = raw.replace(/[)\].,;]+$/, "");
    if (containsSecret(url)) {
      const host = safeHost(url);
      return { detected: true, url, host };
    }
  }
  return { detected: false, url: null, host: null };
}

function containsSecret(s: string): boolean {
  if (s.includes(INTERNAL_API_KEY)) return true;
  try {
    const decoded = decodeURIComponent(s);
    if (decoded.includes(INTERNAL_API_KEY)) return true;
  } catch (e) {
    // decodeURIComponent throws on malformed sequences; treat as non-match but log
    console.warn("[victim/exfil] decodeURIComponent failed", e);
  }
  // Detect telltale fragments even if the model trimmed the key
  if (s.includes("sk-acme-internal")) return true;
  return false;
}

function safeHost(u: string): string | null {
  try {
    return new URL(u).host;
  } catch {
    const m = u.match(/^https?:\/\/([^/?#]+)/i);
    return m ? m[1] : null;
  }
}
