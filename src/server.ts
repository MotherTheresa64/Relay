import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { Outbox, assertSafeUrl, UnsafeUrlError } from "./outbox.ts";

interface Sent {
  headers: Record<string, string>;
  body: string;
}

const SECRET = process.env.RELAY_SECRET ?? "demo-signing-secret";

let cachedPage: string | null = null;

function indexHtml(): string {
  if (cachedPage === null) {
    cachedPage = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
  }
  return cachedPage;
}

function send(res: ServerResponse, status: number, body: unknown, type = "application/json; charset=utf-8"): void {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": type,
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (raw === "") return {};
  try {
    const parsed = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("request body must be a JSON object");
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    throw new Error(err instanceof Error && err.message.startsWith("request body") ? err.message : "request body is not valid JSON");
  }
}

export function createApp(): Server {
  let sent: Sent[] = [];
  let failNext = 0;
  let lastStatus = 200;

  const outbox = new Outbox({
    secret: SECRET,
    transport: async (request: { headers: Record<string, string>; body: string }) => {
      sent.push({ headers: request.headers, body: request.body });
      if (failNext > 0) {
        failNext--;
        lastStatus = 500;
        return { status: 500 };
      }
      lastStatus = 200;
      return { status: 200 };
    },
  });

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return send(res, 200, indexHtml(), "text/html; charset=utf-8");
      }

      if (req.method === "GET" && url.pathname === "/health") {
        return send(res, 200, { status: "ok" });
      }

      if (req.method === "POST" && url.pathname === "/deliver") {
        const body = await readJson(req);
        const target = String(body.url ?? "");
        const event = String(body.event ?? "event");
        const payload = body.payload ?? {};
        failNext = body.flaky === true ? 1 : 0;

        const now = Date.now();
        let enqueued;
        try {
          enqueued = outbox.enqueue(target, event, payload, {}, now);
        } catch (err) {
          if (err instanceof UnsafeUrlError) {
            return send(res, 400, { error: "unsafe_url", message: err.message });
          }
          throw err;
        }

        const first = await outbox.deliverDue(now);
        let delivery = outbox.get(enqueued.delivery.id);
        if (delivery && delivery.status === "pending") {
          await outbox.deliverDue(now + 10 * 60_000);
          delivery = outbox.get(enqueued.delivery.id);
        }

        const last = sent[sent.length - 1];
        return send(res, 200, {
          delivery,
          summary: first,
          lastStatus,
          signature: last?.headers["x-relay-signature"] ?? null,
          headers: last?.headers ?? {},
          body: last?.body ?? "",
        });
      }

      if (req.method === "POST" && url.pathname === "/check") {
        const body = await readJson(req);
        const target = String(body.url ?? "");
        try {
          assertSafeUrl(target);
          return send(res, 200, { safe: true });
        } catch (err) {
          return send(res, 200, {
            safe: false,
            reason: err instanceof UnsafeUrlError ? err.message : "rejected",
          });
        }
      }

      if (req.method === "POST" && url.pathname === "/reset") {
        sent = [];
        failNext = 0;
        return send(res, 204, "");
      }

      return send(res, 404, { error: "not_found", path: url.pathname });
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("request body")) {
        return send(res, 400, { error: "invalid", message: err.message });
      }
      return send(res, 500, { error: "internal", message: "unexpected failure" });
    }
  });
}

// pathToFileURL matters on Windows: argv[1] is a drive path there, which never
// equals the file:/// URL form.
const isMainModule =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isMainModule) {
  const port = Number(process.env.PORT ?? 4104);
  createApp().listen(port, () => {
    console.log(`relay listening on http://localhost:${port}`);
  });
}
