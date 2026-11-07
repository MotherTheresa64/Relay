import test from "node:test";
import assert from "node:assert/strict";
import {
  Outbox,
  UnsafeUrlError,
  ValidationError,
  assertSafeUrl,
  retryDelay,
  signPayload,
  verifySignature,
  type SignedRequest,
} from "../src/outbox.ts";

const T0 = 1_700_000_000_000;
const SECRET = "whsec_test_secret_value";

function recorder(responses: (number | Error)[]) {
  const calls: SignedRequest[] = [];
  let i = 0;
  return {
    calls,
    transport: async (req: SignedRequest) => {
      calls.push(req);
      const next = responses[Math.min(i, responses.length - 1)];
      i++;
      if (next instanceof Error) throw next;
      return { status: next };
    },
  };
}

test("public https endpoints are accepted", () => {
  for (const url of [
    "https://api.example.com/hooks",
    "https://hooks.example.com:8443/path?x=1",
    "https://8.8.8.8/hook",
  ]) {
    assert.equal(assertSafeUrl(url).hostname.length > 0, true, url);
  }
});

test("internal addresses are refused", () => {
  const blocked = [
    "https://127.0.0.1/hook",
    "https://localhost/hook",
    "https://10.0.0.5/hook",
    "https://192.168.1.1/hook",
    "https://172.16.4.2/hook",
    "https://169.254.169.254/latest/meta-data",
    "https://100.64.0.1/hook",
    "https://0.0.0.0/hook",
    "https://[::1]/hook",
    "https://[fd00::1]/hook",
    "https://service.local/hook",
    "https://metadata.google.internal/hook",
  ];
  for (const url of blocked) {
    assert.throws(() => assertSafeUrl(url), UnsafeUrlError, `should block ${url}`);
  }
});

test("plain http and credential-bearing URLs are refused", () => {
  assert.throws(() => assertSafeUrl("http://example.com/hook"), UnsafeUrlError);
  assert.throws(() => assertSafeUrl("https://user:pass@example.com/hook"), UnsafeUrlError);
  assert.throws(() => assertSafeUrl("ftp://example.com/hook"), UnsafeUrlError);
  assert.throws(() => assertSafeUrl("not a url"), UnsafeUrlError);
});

test("signatures verify and tampering is detected", () => {
  const body = JSON.stringify({ id: 1 });
  const sig = signPayload(SECRET, T0, body);

  assert.equal(verifySignature(SECRET, T0, body, sig, { now: T0 }), true);
  assert.equal(verifySignature(SECRET, T0, `${body} `, sig, { now: T0 }), false, "body changed");
  assert.equal(verifySignature("other-secret", T0, body, sig, { now: T0 }), false, "wrong secret");
  assert.equal(verifySignature(SECRET, T0 + 1, body, sig, { now: T0 + 1 }), false, "timestamp changed");
});

test("stale signatures are rejected to stop replay", () => {
  const body = "{}";
  const sig = signPayload(SECRET, T0, body);
  assert.equal(verifySignature(SECRET, T0, body, sig, { now: T0 + 60_000 }), true, "inside tolerance");
  assert.equal(verifySignature(SECRET, T0, body, sig, { now: T0 + 400_000 }), false, "outside tolerance");
  assert.equal(verifySignature(SECRET, T0, body, sig, { now: T0 - 400_000 }), false, "future-dated");
});

test("a successful delivery is signed, identified and marked delivered", async () => {
  const rec = recorder([200]);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport });
  const { delivery } = outbox.enqueue("https://example.com/hook", "invoice.paid", { id: 7 }, {}, T0);

  const result = await outbox.deliverDue(T0);
  assert.deepEqual(result, { delivered: 1, retried: 0, failed: 0 });

  const call = rec.calls[0];
  assert.equal(call.headers["x-delivery"] ?? call.headers["x-relay-delivery"], delivery.id);
  assert.equal(call.headers["x-relay-event"], "invoice.paid");
  assert.equal(call.headers["x-relay-attempt"], "1");
  assert.deepEqual(JSON.parse(call.body), { id: 7 });

  const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(call.headers["x-relay-signature"]);
  assert.ok(match, "signature header has the documented shape");
  assert.equal(verifySignature(SECRET, Number(match![1]), call.body, match![2], { now: T0 }), true);

  assert.equal(outbox.get(delivery.id)!.status, "delivered");
  assert.equal(outbox.get(delivery.id)!.lastStatus, 200);
});

test("a failure schedules a retry with backoff instead of dropping the webhook", async () => {
  const rec = recorder([500, 200]);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport, maxAttempts: 5 });
  const { delivery } = outbox.enqueue("https://example.com/hook", "e", {}, {}, T0);

  await outbox.deliverDue(T0);
  const afterFirst = outbox.get(delivery.id)!;
  assert.equal(afterFirst.status, "pending");
  assert.equal(afterFirst.attempts, 1);
  assert.equal(afterFirst.nextAttemptAt, T0 + retryDelay(1));
  assert.equal(afterFirst.lastError, "receiver returned 500");

  assert.deepEqual(await outbox.deliverDue(T0 + 1), { delivered: 0, retried: 0, failed: 0 }, "not due yet");

  const result = await outbox.deliverDue(afterFirst.nextAttemptAt);
  assert.deepEqual(result, { delivered: 1, retried: 0, failed: 0 });
  assert.equal(outbox.get(delivery.id)!.attempts, 2);
  assert.equal(outbox.get(delivery.id)!.lastError, null, "success clears the previous error");
});

test("a transport exception is treated as a failure, not a crash", async () => {
  const rec = recorder([new Error("ECONNREFUSED"), 200]);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport });
  const { delivery } = outbox.enqueue("https://example.com/hook", "e", {}, {}, T0);

  await outbox.deliverDue(T0);
  assert.equal(outbox.get(delivery.id)!.lastError, "ECONNREFUSED");
  assert.equal(outbox.get(delivery.id)!.lastStatus, null);

  const retryAt = outbox.get(delivery.id)!.nextAttemptAt;
  await outbox.deliverDue(retryAt);
  assert.equal(outbox.get(delivery.id)!.status, "delivered");
});

test("attempts are bounded and the delivery ends failed", async () => {
  const rec = recorder([503]);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport, maxAttempts: 3 });
  const { delivery } = outbox.enqueue("https://example.com/hook", "e", {}, {}, T0);

  let now = T0;
  for (let i = 0; i < 3; i++) {
    await outbox.deliverDue(now);
    now = outbox.get(delivery.id)!.nextAttemptAt || now + 1_000_000;
  }

  const final = outbox.get(delivery.id)!;
  assert.equal(final.status, "failed");
  assert.equal(final.attempts, 3);
  assert.equal(rec.calls.length, 3, "no attempt beyond the budget");
  assert.deepEqual(await outbox.deliverDue(now + 10_000_000), { delivered: 0, retried: 0, failed: 0 });
});

test("retry delays grow and are capped", () => {
  const policy = { baseMs: 500, factor: 2, maxMs: 4_000 };
  assert.equal(retryDelay(0, policy), 0);
  assert.equal(retryDelay(1, policy), 500);
  assert.equal(retryDelay(3, policy), 2_000);
  assert.equal(retryDelay(10, policy), 4_000);
});

test("an idempotency key stops a duplicated event being delivered twice", async () => {
  const rec = recorder([200]);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport });
  const first = outbox.enqueue("https://example.com/hook", "order.created", { id: 1 }, { idempotencyKey: "order-1" }, T0);
  const second = outbox.enqueue("https://example.com/hook", "order.created", { id: 1 }, { idempotencyKey: "order-1" }, T0 + 5);

  assert.equal(first.deduped, false);
  assert.equal(second.deduped, true);
  assert.equal(second.delivery.id, first.delivery.id);

  await outbox.deliverDue(T0);
  assert.equal(rec.calls.length, 1);
  assert.equal(outbox.byStatus("delivered").length, 1);
});

test("enqueue validates its inputs", () => {
  const rec = recorder([200]);
  assert.throws(() => new Outbox({ secret: "short", transport: rec.transport }), ValidationError);
  const outbox = new Outbox({ secret: SECRET, transport: rec.transport });
  assert.throws(() => outbox.enqueue("https://127.0.0.1/x", "e", {}), UnsafeUrlError);
  assert.throws(() => outbox.enqueue("https://example.com/x", "", {}), ValidationError);
  assert.equal(outbox.byStatus("pending").length, 0, "a rejected enqueue leaves no delivery behind");
});
