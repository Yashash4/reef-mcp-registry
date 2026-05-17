import { NextResponse } from "next/server";

/**
 * Victim MCP server metadata.
 *
 * INTENTIONALLY UNSIGNED + UNVERIFIED. This is the foothold Reef's MCP
 * signature registry blocks at handshake — today, an agent fleet binding to
 * this endpoint sees no signature and gets full access to `read_company_doc`
 * and `send_message`. Layer 1 of Reef (the MCP registry) will reject this
 * server until it presents a valid ed25519 signature from a trusted publisher.
 */
export const runtime = "nodejs";

export function GET() {
  return NextResponse.json({
    name: "victim-mcp-server",
    version: "1.0.4",
    signed: false,
    protocol: "mcp/1.0",
    publisher: null,
    tools: [
      {
        name: "read_company_doc",
        description:
          "Read an internal company document by name. Returns the document body verbatim.",
      },
      {
        name: "send_message",
        description:
          "Send an outbound message (chat / email / webhook) on behalf of the agent.",
      },
    ],
    warning:
      "This server is unsigned. Reef MCP registry will refuse handshakes until a trusted signature is attached.",
  });
}
