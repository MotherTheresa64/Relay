import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createApp } from "../src/server.ts";

async function withServer(fn: (url: string) => Promise<void>): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

const post = (url: string, path: string, body: unknown) =>
  fetch(`${url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

test("the page is served", async () => {
  await withServer(async (url) => {
    const res = await fetch(`${url}/`);
    assert.equal(res.status, 200);
    assert.match(await res.text(), /Relay/);
  });
});

test("a delivery is signed and succeeds", async () => {
  await withServer(async (url) => {
    const res = await post(url, "/deliver", {
      url: "https://example.com/hooks/orders",
      event: "order.created",
      payload: { id: 42 },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.delivery.status, "delivered");
    assert.equal(body.delivery.attempts, 1);
    assert.match(body.signature, /^t=\d+,v1=[0-9a-f]{64}$/);
    assert.match(body.body, /"id":42/);
  });
});

test("a failing endpoint is retried and then delivered", async () => {
  await withServer(async (url) => {
    const res = await post(url, "/deliver", {
      url: "https://example.com/flaky",
      event: "order.created",
      payload: { id: 7 },
      flaky: true,
    });
    const body = await res.json();
    assert.equal(body.delivery.status, "delivered");
    assert.equal(body.delivery.attempts, 2);
  });
});

test("the SSRF guard blocks metadata and loopback addresses", async () => {
  await withServer(async (url) => {
    const metadata = await (await post(url, "/check", { url: "http://169.254.169.254/latest/meta-data" })).json();
    assert.equal(metadata.safe, false);

    const loopback = await (await post(url, "/check", { url: "http://localhost:8080/admin" })).json();
    assert.equal(loopback.safe, false);

    const fine = await (await post(url, "/check", { url: "https://example.com/hook" })).json();
    assert.equal(fine.safe, true);
  });
});

test("an unsafe target is refused end to end", async () => {
  await withServer(async (url) => {
    const res = await post(url, "/deliver", { url: "http://127.0.0.1:9000/internal", event: "x", payload: {} });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "unsafe_url");
  });
});
