import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsafeUrlError";
  }
}

export interface BackoffPolicy {
  baseMs: number;
  factor: number;
  maxMs: number;
}

export const DEFAULT_BACKOFF: BackoffPolicy = { baseMs: 1_000, factor: 2, maxMs: 300_000 };

export function retryDelay(attempts: number, policy: BackoffPolicy = DEFAULT_BACKOFF): number {
  if (attempts <= 0) return 0;
  return Math.min(Math.round(policy.baseMs * Math.pow(policy.factor, attempts - 1)), policy.maxMs);
}

const PRIVATE_V4: [RegExp, string][] = [
  [/^0\./, "0.0.0.0/8"],
  [/^10\./, "10.0.0.0/8"],
  [/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, "100.64.0.0/10 (carrier NAT)"],
  [/^127\./, "loopback"],
  [/^169\.254\./, "link-local (cloud metadata lives here)"],
  [/^172\.(1[6-9]|2\d|3[01])\./, "172.16.0.0/12"],
  [/^192\.168\./, "192.168.0.0/16"],
];

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "instance-data",
  "169.254.169.254",
]);

/**
 * Refuses destinations that would let a user-supplied webhook URL reach the host's own
 * network. This is the difference between "deliver a webhook" and "a free SSRF gadget".
 */
export function assertSafeUrl(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError(`not a valid URL: ${raw}`);
  }

  if (url.protocol !== "https:") {
    throw new UnsafeUrlError(`webhook URLs must use https, received ${url.protocol}`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new UnsafeUrlError("credentials in the URL are not allowed");
  }

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_HOSTNAMES.has(host) || host.endsWith(".local") || host.endsWith(".localhost")) {
    throw new UnsafeUrlError(`blocked hostname: ${host}`);
  }
  if (host === "::1" || host === "::" || /^f[cd][0-9a-f]{2}:/.test(host) || /^fe[89ab][0-9a-f]:/.test(host)) {
    throw new UnsafeUrlError(`blocked IPv6 range: ${host}`);
  }
  for (const [pattern, label] of PRIVATE_V4) {
    if (pattern.test(host)) throw new UnsafeUrlError(`blocked private address range (${label}): ${host}`);
  }
  return url;
}

export function signPayload(secret: string, timestamp: number, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function verifySignature(
  secret: string,
  timestamp: number,
  body: string,
  signature: string,
  opts: { toleranceMs?: number; now?: number } = {},
): boolean {
  const tolerance = opts.toleranceMs ?? 300_000;
  const now = opts.now ?? Date.now();
  if (Math.abs(now - timestamp) > tolerance) return false;

  const expected = Buffer.from(signPayload(secret, timestamp, body), "utf8");
  const received = Buffer.from(signature, "utf8");
  if (expected.length !== received.length) return false;
  return timingSafeEqual(expected, received);
}

export interface SignedRequest {
  url: string;
  body: string;
  headers: Record<string, string>;
}

export interface TransportResult {
  status: number;
}

export type Transport = (request: SignedRequest) => Promise<TransportResult>;

export type DeliveryStatus = "pending" | "delivered" | "failed";

export interface Delivery {
  id: string;
  url: string;
  event: string;
  body: string;
  attempts: number;
  status: DeliveryStatus;
  nextAttemptAt: number;
  lastStatus: number | null;
  lastError: string | null;
  idempotencyKey: string | null;
  createdAt: number;
}

export interface OutboxOptions {
  secret: string;
  transport: Transport;
  maxAttempts?: number;
  backoff?: BackoffPolicy;
}

export interface EnqueueOptions {
  idempotencyKey?: string;
}

export class Outbox {
  private secret: string;
  private transport: Transport;
  private maxAttempts: number;
  private backoff: BackoffPolicy;
  private records = new Map<string, Delivery>();

  constructor(opts: OutboxOptions) {
    if (!opts.secret || opts.secret.length < 8) {
      throw new ValidationError("secret must be at least 8 characters");
    }
    this.secret = opts.secret;
    this.transport = opts.transport;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.backoff = opts.backoff ?? DEFAULT_BACKOFF;
  }

  enqueue(
    url: string,
    event: string,
    payload: unknown,
    opts: EnqueueOptions = {},
    now = Date.now(),
  ): { delivery: Delivery; deduped: boolean } {
    assertSafeUrl(url);
    if (typeof event !== "string" || event.trim() === "") {
      throw new ValidationError("event must be a non-empty string");
    }
    const key = opts.idempotencyKey ?? null;
    if (key !== null) {
      for (const existing of this.records.values()) {
        if (existing.idempotencyKey === key) return { delivery: { ...existing }, deduped: true };
      }
    }

    const body = JSON.stringify(payload ?? null);
    const delivery: Delivery = {
      id: randomUUID(),
      url,
      event,
      body,
      attempts: 0,
      status: "pending",
      nextAttemptAt: now,
      lastStatus: null,
      lastError: null,
      idempotencyKey: key,
      createdAt: now,
    };
    this.records.set(delivery.id, delivery);
    return { delivery: { ...delivery }, deduped: false };
  }

  /**
   * Attempts every delivery that is due. A 2xx marks it delivered; anything else schedules a
   * retry with bounded exponential backoff, and after `maxAttempts` the delivery is failed
   * rather than retried forever.
   */
  async deliverDue(now = Date.now()): Promise<{ delivered: number; retried: number; failed: number }> {
    const due = [...this.records.values()].filter(
      (d) => d.status === "pending" && d.nextAttemptAt <= now,
    );

    let delivered = 0;
    let retried = 0;
    let failed = 0;

    for (const record of due) {
      const timestamp = now;
      const signature = signPayload(this.secret, timestamp, record.body);
      record.attempts += 1;

      try {
        const result = await this.transport({
          url: record.url,
          body: record.body,
          headers: {
            "content-type": "application/json",
            "x-relay-event": record.event,
            "x-relay-delivery": record.id,
            "x-relay-attempt": String(record.attempts),
            "x-relay-signature": `t=${timestamp},v1=${signature}`,
          },
        });
        record.lastStatus = result.status;

        if (result.status >= 200 && result.status < 300) {
          record.status = "delivered";
          record.lastError = null;
          delivered++;
          continue;
        }
        record.lastError = `receiver returned ${result.status}`;
      } catch (err) {
        record.lastStatus = null;
        record.lastError = err instanceof Error ? err.message : String(err);
      }

      if (record.attempts >= this.maxAttempts) {
        record.status = "failed";
        failed++;
      } else {
        record.nextAttemptAt = now + retryDelay(record.attempts, this.backoff);
        retried++;
      }
    }

    return { delivered, retried, failed };
  }

  get(id: string): Delivery | null {
    const record = this.records.get(id);
    return record ? { ...record } : null;
  }

  byStatus(status: DeliveryStatus): Delivery[] {
    return [...this.records.values()].filter((d) => d.status === status).map((d) => ({ ...d }));
  }
}
