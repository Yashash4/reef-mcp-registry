# Reef victim — Acme Mail Copilot-clone

The deliberately-vulnerable AI Copilot Reef defends against.

Acme Mail is a Next.js inbox with a built-in Gemini-powered Copilot. It loads
fake "internal" company secrets into the same context window as user emails,
exposes an unsigned MCP server, and offers a `fetch_url` tool — exactly the
shape of the Microsoft Copilot deployment that EchoLeak (CVE-2025-32711)
exploited.

The point is to make the EchoLeak-class attack succeed **without** Reef in
front, so the demo can then turn Reef on and watch it die.

## Run it

```bash
pnpm install
GEMINI_API_KEY=… pnpm dev   # http://localhost:3001
```

`GEMINI_API_KEY` is required for the **live** path. The **demo** path
(`/?demo=true`) is deterministic and runs without a key.

Environment variables read:

| Var                 | Default                  | Purpose                            |
| ------------------- | ------------------------ | ---------------------------------- |
| `GEMINI_API_KEY`    | —                        | Required for live Gemini call      |
| `GEMINI_PRO_MODEL`  | `gemini-2.0-flash-exp`   | Override the model used            |

## Two demo paths

- **`/`** — Live Gemini call. The model is given a system prompt that loads
  the secret + the `summarize_inbox` + `fetch_url` tools, then told to
  summarize the inbox. Whether the EchoLeak payload lands depends on the
  model's alignment.
- **`/?demo=true`** — Deterministic. The API route synthesizes the exfil
  payload directly; the markdown image with the secret in the URL renders
  inline, the red banner fires, and the recorded video gets the exact same
  beat every take.

Both code paths are clearly labeled in `app/api/summarize/route.ts`.

## Endpoints

| Route                      | Method | Notes                                  |
| -------------------------- | ------ | -------------------------------------- |
| `/api/summarize`           | POST   | Live + demo summarize paths            |
| `/api/mcp`                 | GET    | MCP server metadata (`signed: false`)  |
| `/api/mcp/tools/call`      | POST   | `read_company_doc`, `send_message`     |

The MCP endpoint is intentionally unsigned. Reef's Layer 1 (signed MCP
registry) will reject handshakes against it once we wire that in.

## What Reef will block later

- The markdown-image egress with a credential payload (Lobster Trap MODIFY +
  egress regex).
- The unsigned MCP handshake at `/api/mcp` (signature registry sidecar).
- The poisoned-email prompt-injection chain (asi_category_ewma + intent
  mismatch).

For now: the attack succeeds, on purpose.
