import { NextRequest, NextResponse } from "next/server";
import { INTERNAL_DOC } from "../../../../lib/secret";

/**
 * MCP tool invocation endpoint. Accepts { tool, args } and dispatches to the
 * minimal tool surface exposed by the victim. NO signature check, NO scope
 * verification — the whole point is that Reef's MCP registry sidecar must do
 * that work at the binding layer before any call reaches here.
 */
export const runtime = "nodejs";

type CallBody = {
  tool?: string;
  args?: Record<string, unknown>;
};

export async function POST(req: NextRequest) {
  let body: CallBody;
  try {
    body = (await req.json()) as CallBody;
  } catch (err) {
    return NextResponse.json(
      {
        ok: false,
        error: "invalid_json",
        detail: err instanceof Error ? err.message : String(err),
      },
      { status: 400 },
    );
  }

  const tool = body.tool ?? "";
  const args = body.args ?? {};

  if (tool === "read_company_doc") {
    const name = String(args.name ?? "");
    const doc = INTERNAL_DOC[name];
    if (!doc) {
      return NextResponse.json(
        {
          ok: false,
          error: "doc_not_found",
          available: Object.keys(INTERNAL_DOC),
        },
        { status: 404 },
      );
    }
    console.log(
      `[victim/mcp] read_company_doc(${name}) — unsigned MCP call served`,
    );
    return NextResponse.json({ ok: true, tool, name, body: doc });
  }

  if (tool === "send_message") {
    const to = String(args.to ?? "");
    const messageBody = String(args.body ?? "");
    if (!to || !messageBody) {
      return NextResponse.json(
        { ok: false, error: "missing_args", required: ["to", "body"] },
        { status: 400 },
      );
    }
    console.log(
      `[victim/mcp] send_message — to=${to} body=${JSON.stringify(messageBody).slice(0, 240)}`,
    );
    return NextResponse.json({
      ok: true,
      tool,
      delivered: true,
      to,
      bytes: messageBody.length,
    });
  }

  return NextResponse.json(
    { ok: false, error: "unknown_tool", tool },
    { status: 404 },
  );
}
