/**
 * TypeScript shapes mirroring upstream service responses. These match
 * (verbatim) the pydantic models in:
 *   - reef/control-plane/policy_bus/app/models/fleet.py
 *   - reef/control-plane/atlas/app/api/health.py
 *   - reef/control-plane/dast_a/app/packs/schema.py
 *   - reef/control-plane/quote/app/api/generate.py
 *
 * When upstream model changes, update these — keep one source of truth.
 */

// ─── Policy Bus / Fleet ───────────────────────────────────────────────

export type AckStatus =
  | "applied"
  | "verify_failed"
  | "policy_parse_failed"
  | "kept_old_active"
  | "scope_mismatch"
  | "unknown";

export interface NodeIdentity {
  fleet_id: string;
  region_id: string;
  site_id: string;
  node_id: string;
  svid_subject?: string;
}

export interface NodeRecord {
  identity: NodeIdentity;
  last_applied_version: string;
  last_applied_bundle_id: string;
  last_ack_status: AckStatus;
  last_ack_detail: string;
  last_ack_unix: number;
  last_subscribe_unix: number;
  online: boolean;
}

export interface FleetSnapshot {
  fleet_id: string;
  region_count: number;
  site_count: number;
  node_count: number;
  nodes: NodeRecord[];
}

export interface PolicyBusHealthz {
  status: string;
  active_subscribers: number;
  active_bundles: number;
  fleet_node_count: number;
}

export interface BundleListItem {
  bundle_id: string;
  version: string;
  scope: {
    fleet_id: string;
    region_id: string;
    site_id: string;
    node_id: string;
  };
  signer_key_id: string;
  signer_fingerprint?: string;
  published_at_unix: number;
  expires_at_unix?: number;
  bundle_sha256_hex?: string;
}

export interface AuditEvent {
  audit_id: string;
  ts_unix: number;
  kind: string;
  event?: string;
  decision?: string;
  reason?: string;
  bundle_id?: string;
  version?: string;
  signer_key_id?: string;
  fleet_recipient_count?: number;
  [key: string]: unknown;
}

// ─── Atlas (MCP signature registry) ───────────────────────────────────

export interface AtlasHealthz {
  status: string;
  registry_entries: {
    verified: number;
    quarantined: number;
    poisoned: number;
  };
  total_entries: number;
  publishers: number;
}

export interface AtlasManifest {
  mcpName: string;
  version: string;
  sdk_version: string;
  transport: "stdio" | "http" | "sse" | "websocket";
  capabilities: string[];
  tools: string[];
  stdio_entrypoint_hash?: string;
  publisher_id: string;
  notes?: string;
}

export interface AtlasEntry {
  registry_id: string;
  manifest: AtlasManifest;
  signature_hex: string;
  status: "verified" | "quarantined" | "poisoned";
  publisher_id: string;
  poisoned_reason?: string;
  quarantined_reason?: string;
  registered_at_unix: number;
}

export interface AtlasPublisher {
  publisher_id: string;
  fingerprint: string;
  revoked: boolean;
  public_key_hex?: string;
}

export interface AtlasEntriesList {
  entries: AtlasEntry[];
  publishers: AtlasPublisher[];
}

export interface AtlasVerifyResponse {
  decision: "allow" | "review" | "deny";
  reason: string;
  registry_id: string | null;
  matched_capabilities: string[];
  violations: { code: string; detail: string }[];
  audit_id: string;
}

// ─── DAST-A (attack pack catalog) ─────────────────────────────────────

export type OwaspAsiTag =
  | "ASI01"
  | "ASI02"
  | "ASI03"
  | "ASI04"
  | "ASI05"
  | "ASI06"
  | "ASI07"
  | "ASI08"
  | "ASI09"
  | "ASI10";

export type MitreAtlasTag = string; // "AML.T0010" etc.

export interface AttackPack {
  pack_id: string;
  name: string;
  source: string;
  discovered_by: string;
  cve_mapping?: string | null;
  owasp_asi: OwaspAsiTag[];
  mitre_atlas: MitreAtlasTag[];
  trigger_template: string;
  victim_signal: string;
  reef_policy_signal: string;
  discovered_at: string;
  exemplar_request_id?: string;
  successful_episodes: number;
  blocked_by_reef: boolean;
  ox_security_citation?: string | null;
  evidence?: {
    payload_excerpt?: string;
    blocked_by_reef?: boolean;
  };
}

export interface AttackPackList {
  packs: AttackPack[];
  total: number;
  page: number;
  page_size: number;
}

export interface PolicyDraft {
  draft_id: string;
  status: "pending" | "approved" | "rejected";
  episode_request_id?: string;
  rule_yaml: string;
  english_explanation?: string;
  created_at_unix: number;
  updated_at_unix?: number;
  source: string;
  signature?: string;
}

// ─── Quote / RIA ──────────────────────────────────────────────────────

export interface RIAScoreSummary {
  reef_risk_tier: string;
  tier_label_with_framing: string;
  estimated_premium_low: number;
  estimated_premium_high: number;
  coverage_amount_usd: number;
  phase_2_disclaimer: string;
}

export interface RIAGenerateResponse {
  ria_id: string;
  download_url: string;
  verify_url: string;
  score_summary: RIAScoreSummary;
  sha256: string;
  signature_hex_short: string;
  signature_b64_short: string;
  signer_key_id: string;
  sample_mode: boolean;
}

export interface RIAVerifyResponse {
  ria_id: string;
  verified: boolean;
  sha256_hex: string;
  signer_key_id: string;
  signature_b64_short?: string;
  signed_at_unix?: number;
  detail?: string;
}
