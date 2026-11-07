# Relay

A webhook outbox: signed deliveries, an SSRF guard on the destination, bounded exponential
retries, and a terminal failed state instead of infinite redelivery.

Zero dependencies.

## Run it

```bash
node --test
```

```ts
import { Outbox } from "./src/outbox.ts";

const outbox = new Outbox({
  secret: process.env.WEBHOOK_SECRET!,
  transport: async ({ url, body, headers }) => {
    const res = await fetch(url, { method: "POST", body, headers });
    return { status: res.status };
  },
});

outbox.enqueue("https://example.com/hook", "invoice.paid", { id: 42 });
await outbox.deliverDue();
```

## The hard part: a webhook URL is attacker-controlled input

If a user can type the destination URL, they can point it at `http://169.254.169.254` and ask
the server to fetch internal cloud metadata, or at `127.0.0.1:6379` to poke a local daemon.
That is server-side request forgery, and it is the reason webhook features get written up as
vulnerabilities.

`assertSafeUrl` refuses before any request is made:

- non-`https` schemes (so credentials in headers cannot be stripped in transit),
- URLs with embedded `user:pass`,
- `localhost`, `*.local`, `*.localhost`, `metadata.google.internal`,
- every private and special IPv4 range — `10/8`, `172.16/12`, `192.168/16`, `127/8`,
  `169.254/16`, `100.64/10`, `0/8`,
- IPv6 loopback, unspecified, unique-local (`fc00::/7`) and link-local (`fe80::/10`).

It validates literal addresses only. Name-based DNS rebinding is a separate problem that
needs resolution-time checks and connection pinning; this module deliberately does not claim
to solve it, and says so here instead of leaving a false sense of safety.

## Signing

Each attempt sends `X-Relay-Signature: t=<unix-ms>,v1=<hex>`, where the digest is
`HMAC-SHA256(secret, "<t>.<body>")`. Receivers must:

1. Recompute the HMAC over the raw body,
2. compare in constant time (`timingSafeEqual`),
3. reject timestamps outside a tolerance window — that is what stops a captured request
   from being replayed tomorrow.

Including the timestamp inside the signed string is what makes step 3 meaningful. Signing the
body alone lets an attacker reuse an old signature indefinitely.

## Delivery model

```
pending ──2xx──▶ delivered
   │
   └──non-2xx / exception──▶ pending (backoff) ──attempts exhausted──▶ failed
```

| Field | Meaning |
| --- | --- |
| `attempts` | Incremented per attempt, including ones that threw. |
| `nextAttemptAt` | `now + retryDelay(attempts)`, capped at `maxMs`. |
| `lastStatus` / `lastError` | What the receiver said, or why the call threw. |
| `idempotencyKey` | Optional; a repeat enqueue returns the original delivery. |

## Design decisions

**Delivery is injected, not hard-coded.** `transport` is a function, so the retry logic is
testable without a network, and the same outbox can drive `fetch`, an undici pool, or a queue
in production.

**A thrown transport error is a failed attempt, not an exception.** One unreachable receiver
must not abort the whole batch of due deliveries.

**Success clears `lastError`.** A delivery that failed twice and then succeeded should not look
half-broken in an operator's dashboard.

**Retries are capped per delivery, not globally.** `maxAttempts` is a property of the outbox,
and each delivery tracks its own count, so one poison endpoint cannot consume the budget of
healthy ones.

## Tests

Acceptance of public endpoints, rejection across every private range and scheme, signature
verification and tamper detection, replay-tolerance windows, successful delivery with headers
and body assertions, retry scheduling with backoff, transport exceptions, attempt exhaustion
into `failed`, backoff capping, idempotent enqueue, and input validation.
