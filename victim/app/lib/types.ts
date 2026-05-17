export type ToolCallRecord = {
  tool: string;
  args: Record<string, unknown>;
  result?: string;
};

export type SummarizeResponse = {
  summary: string;
  mode: "demo" | "live";
  /** True when an outbound markdown image / URL containing the secret was emitted. */
  exfilDetected: boolean;
  /** Host portion of the exfil URL if exfil was detected. */
  exfilDestination: string | null;
  /** Full leaked URL (for the demo's red banner / audit). */
  exfilUrl: string | null;
  /** Internal tool calls made by the agent. */
  toolCalls: ToolCallRecord[];
};

export type SummarizeError = {
  error: string;
  detail?: string;
};
