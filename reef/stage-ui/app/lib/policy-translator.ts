/**
 * Plain-English translator for Lobster Trap policy rules.
 *
 * Per docs/10-DECISIONS.md D-019 the projector shows plain-English diffs —
 * NOT raw YAML — because judges are not reading P4-style firewall syntax
 * during the 5-minute demo. Switch-table approach: every known rule shape
 * maps to a human sentence. Unknown rules fall back to a "raw rule:"
 * passthrough so we never silently lose information.
 */

export interface PolicyRule {
  name?: string;
  description?: string;
  match?: Record<string, unknown>;
  action?: string;
  // any other keys passthrough — the translator inspects them
  [key: string]: unknown;
}

/**
 * Render a single rule as a plain-English sentence.
 *
 * Examples (matches default_policy.yaml shapes we've shipped):
 *   - "Block: any agent binding to unsigned MCP server (registry says
 *      signed: false)" — for the mcp_bind_decision rule
 *   - "Block: outbound markdown image to untrusted domain, when the URL
 *      contains a known secret fragment"
 *   - "Modify: strip markdown images embedded in agent responses going
 *      to attacker.example.com"
 *   - "Quarantine: any session whose ASI-category EWMA crosses 0.4"
 */
export function translateRule(rule: PolicyRule): string {
  const action = String(rule.action || "").toLowerCase();
  const name = String(rule.name || "");
  const match = rule.match || {};

  // ── Named known rules (highest precedence — translations are curated)
  if (name === "block_unsigned_mcp_bind") {
    return "Block: any agent attempting to bind to an MCP server that isn't on the signed registry (Atlas says signed: false).";
  }
  if (name === "block_mcp_rce_26_04") {
    return "Block: MCP STDIO binds whose entrypoint hash doesn't match the signed manifest (defends against MCP-RCE-26.04, OX Security April 2026).";
  }
  if (name === "strip_markdown_exfil_to_attacker") {
    return "Modify: strip markdown images from outbound agent responses whose host is on the denied_domains list (defends EchoLeak-shape exfil).";
  }
  if (name === "quarantine_high_ewma") {
    return "Quarantine: any session whose asi_category_ewma crosses the configured threshold (default 0.4) — DAST-A discovered drift signature.";
  }
  if (name === "human_review_dast_a_drafts") {
    return "Human review: any DAST-A-discovered draft is held for operator approval before it ever applies — no auto-apply.";
  }
  if (name === "block_magic_word_xyz") {
    return "Block: the test phrase 'magic_word_xyz' (used by the 3-node propagation integration test).";
  }
  if (name === "block_denied_domain") {
    return "Block: any outbound request to a host on network.denied_domains (e.g. *.attacker.example.com, *.onion).";
  }

  // ── Generic match-on-key (translates rule fragments we recognise)
  const fragments: string[] = [];

  if (typeof (match as { domain?: unknown }).domain === "string") {
    fragments.push(`when target host is "${(match as { domain: string }).domain}"`);
  }
  if (typeof (match as { contains?: unknown }).contains === "string") {
    fragments.push(
      `when payload contains "${(match as { contains: string }).contains}"`
    );
  }
  if (
    typeof (match as { mcp_bind_signed?: unknown }).mcp_bind_signed === "boolean"
  ) {
    fragments.push(
      `when MCP bind target is ${
        (match as { mcp_bind_signed: boolean }).mcp_bind_signed
          ? "signed"
          : "unsigned"
      }`
    );
  }
  if (
    typeof (match as { contains_markdown_image_with_external_url?: unknown })
      .contains_markdown_image_with_external_url === "boolean"
  ) {
    fragments.push("when the response embeds a markdown image to an external host");
  }
  if (
    typeof (match as { intent_mismatch_score?: unknown }).intent_mismatch_score ===
    "number"
  ) {
    fragments.push(
      `when intent_mismatch_score >= ${
        (match as { intent_mismatch_score: number }).intent_mismatch_score
      }`
    );
  }
  if (
    typeof (match as { asi_category_ewma?: unknown }).asi_category_ewma === "number"
  ) {
    fragments.push(
      `when asi_category_ewma >= ${
        (match as { asi_category_ewma: number }).asi_category_ewma
      }`
    );
  }

  const head = friendlyActionVerb(action);
  if (fragments.length > 0) {
    return `${head}: ${rule.description || name || "matched payload"}, ${fragments.join(
      ", "
    )}.`;
  }

  // Fall through: unknown rule shape — render raw but readable.
  return `${head}: ${rule.description || name || "raw rule"} — match=${JSON.stringify(
    match
  )}`;
}

function friendlyActionVerb(action: string): string {
  switch (action) {
    case "deny":
    case "block":
      return "Block";
    case "modify":
      return "Modify";
    case "quarantine":
      return "Quarantine";
    case "human_review":
    case "human-review":
      return "Human review";
    case "redirect":
      return "Redirect";
    case "allow":
      return "Allow";
    case "log":
      return "Log";
    default:
      return action ? action.charAt(0).toUpperCase() + action.slice(1) : "Rule";
  }
}

/** Translate an array of rules into an English list. */
export function translateRules(rules: PolicyRule[]): string[] {
  return rules.map(translateRule);
}

/** Diff translation: produce +/-/= lines from two rule sets. The
 *  presentation layer renders the result line-by-line with red/green tint. */
export interface PolicyDiffLine {
  side: "+" | "-" | "=";
  text: string;
}

export function diffRules(
  oldRules: PolicyRule[],
  newRules: PolicyRule[]
): PolicyDiffLine[] {
  const oldNames = new Set(oldRules.map((r) => r.name).filter(Boolean));
  const newNames = new Set(newRules.map((r) => r.name).filter(Boolean));
  const out: PolicyDiffLine[] = [];

  // Removed rules (in old, not in new)
  for (const r of oldRules) {
    if (r.name && !newNames.has(r.name)) {
      out.push({ side: "-", text: translateRule(r) });
    }
  }
  // Added rules (in new, not in old)
  for (const r of newRules) {
    if (r.name && !oldNames.has(r.name)) {
      out.push({ side: "+", text: translateRule(r) });
    }
  }
  // Unchanged rules (intersection by name)
  for (const r of newRules) {
    if (r.name && oldNames.has(r.name)) {
      out.push({ side: "=", text: translateRule(r) });
    }
  }
  return out;
}
