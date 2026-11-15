# WebSocket `Origin` Allowlist Transition (`#450`)

## Current Production Posture (`ebe2b19`)

Since upstream issue `#450` (commits `70a82ba` and `231d652`), all four TotalDrop server implementations unconditionally refuse WebSocket upgrades that carry an HTTP `Origin` header **before** any per-client rate-limit counter is incremented:

1. **Cloudflare Rendezvous Worker** (`server/rendezvous-worker/src/index.ts`):
   ```ts
   if (!isUpgrade(request)) return new Response("WebSocket only\n", { status: 426 });
   // A web page's WebSocket always carries Origin; the apps and the
   // command line never send it (#450). Refusing it keeps a page from
   // spending its visitors' per-client limits.
   if (request.headers.has("Origin")) {
     return new Response("browsers are not served\n", { status: 403 });
   }
   ```
2. **Cloudflare Relay Worker** (`server/relay-worker/src/index.ts`):
   ```ts
   if (upgrade && request.headers.has("Origin")) {
     return new Response("browsers are not served\n", { status: 403 });
   }
   ```
3. **Self-Hosted Rust Rendezvous & Relay Servers** (`server/totaldrop-rendezvous/src/lib.rs` and `server/totaldrop-relay/src/lib.rs`):
   Both inspect the HTTP upgrade request callback and answer `403 Forbidden` whenever `headers().contains_key("origin")` is true, prior to touching per-IPv4 / per-IPv6-`/64` token buckets.

### Why `#450` Exists
Browsers attach the immutable page `Origin` header to every `new WebSocket(...)` handshake, whereas native TotalDrop clients (Android, Linux, CLI, and deploy probes) omit `Origin`. While no browser client was deployed, rejecting every request with `Origin` prevented any third-party webpage (`https://evil.example`) from silently opening WebSockets from a visitor's browser and exhausting that visitor's 60-slot per-client allocation/mailbox budget on `rendezvous.totaldrop.app`.

---

## Transition When Enabling the Web Receiver (`10-web-wasm`)

When the `10-web-wasm` Web Receiver is deployed at `https://totaldrop.app/r`, browsers visiting `https://totaldrop.app` will send:

```http
GET /v0/mailbox/7 HTTP/1.1
Host: rendezvous.totaldrop.app
Upgrade: websocket
Origin: https://totaldrop.app
```

To admit the official first-party Web Receiver while preserving every protection of `#450` against third-party origins, both Workers (and optionally self-hosted Rust servers configured for web access) transition from a **presence check** (`request.headers.has("Origin")`) to an **exact-match allowlist check** evaluated **before** `clientOf(CF-Connecting-IP)` rate-limit accounting.

### 1. `rendezvous-worker` Transition (`server/rendezvous-worker/src/index.ts`)

```ts
const WEB_RECEIVER_ORIGIN = "https://totaldrop.app";

function isAllowedOrigin(request: Request, webEnabled: boolean): boolean {
  const origin = request.headers.get("Origin");
  // Native apps and the CLI never send `Origin`.
  if (origin === null) return true;
  // When the Web Receiver is enabled, admit ONLY exact `https://totaldrop.app`
  // on `/v0/mailbox/<n>` (browser receivers never need `/v0/allocate` until
  // web-send is enabled).
  return webEnabled && origin === WEB_RECEIVER_ORIGIN;
}
```

And inside `fetch(request, env)` **before** `const client = clientOf(...)`:

```ts
if (!isUpgrade(request)) return new Response("WebSocket only\n", { status: 426 });

const origin = request.headers.get("Origin");
if (origin !== null) {
  const allowWebMailbox =
    env.ALLOW_WEB_RECEIVER === "true" &&
    origin === "https://totaldrop.app" &&
    /^\/v0\/mailbox\/([1-9][0-9]{0,9})$/.test(url.pathname);
  if (!allowWebMailbox) {
    return new Response("origin not allowed\n", { status: 403 });
  }
}
```

Key properties of this transition:
- **Zero impact when disabled**: With `ALLOW_WEB_RECEIVER` unset (default), behavior is byte-for-byte identical to `#450` (`403` for every `Origin`).
- **Least-privilege endpoint scoping**: A browser receiver only claims an existing mailbox (`/v0/mailbox/<n>`); `/v0/allocate` remains closed to browser `Origin`s so even an XSS bug on `totaldrop.app` cannot allocate nameplates from a visitor's IP budget.
- **Pre-limiter rejection preserved (`231d652`)**: Any request from `https://attacker.example`, `http://totaldrop.app` (cleartext), `https://sub.totaldrop.app`, or `Origin: null` (sandboxed `iframe` / `data:` URL, where the literal string `"null"` is sent!) is rejected with `403` **before** `Directory.lookup` or `limit.ts` counts the client's IP.

### 2. `relay-worker` Transition (`server/relay-worker/src/index.ts`)

```ts
const origin = request.headers.get("Origin");
if (upgrade && origin !== null) {
  if (!(env.ALLOW_WEB_RECEIVER === "true" && origin === "https://totaldrop.app")) {
    return new Response("origin not allowed\n", { status: 403 });
  }
}
```

Note that on `relay-worker`, `Pair` Durable Objects additionally require a valid Ed25519 signature over a fresh server challenge matching one of the two single-use endpoint keys in `/v0/relay/<keyA>-<keyB>`. Restricting `Origin` to `"https://totaldrop.app"` prevents arbitrary websites from probing `/v0/relay/...` sockets from visitors' browsers.

---

## Companion Browser Hardening on `https://totaldrop.app/r`

Because `https://totaldrop.app` becomes a trusted `Origin` once `ALLOW_WEB_RECEIVER=true` is enabled, the static `/r` page must enforce strict browser isolation headers so untrusted script execution cannot piggyback on that origin:

1. **Content Security Policy (`CSP`)**:
   ```http
   Content-Security-Policy:
     default-src 'none';
     script-src 'self' 'wasm-unsafe-eval';
     connect-src 'self' wss://rendezvous.totaldrop.app wss://relay.totaldrop.app;
     style-src 'self';
     img-src 'self' data:;
     font-src 'self';
     base-uri 'none';
     form-action 'none';
     frame-ancestors 'none'
   ```
2. **Subresource Integrity (`SRI`)**:
   Both `target-wasm32-simd128/build.sh` and `target-wasm32-baseline/build.sh` emit SHA-384 integrity digests (`sha384-…`) verified by `fetch(..., { integrity })` in `web-ui/receiver.js`.
3. **Fragment Confidentiality & Referrer Suppression**:
   `Referrer-Policy: no-referrer` + immediate `history.replaceState` scrubbing in `consumeLocationFragment()` ensures the `#<code>` fragment never leaks via HTTP headers, browser extensions inspecting navigation history, or screen sharing.
4. **Threat-Model Boundary Reminder (`docs/threat-model.md`)**:
   `Origin` is an **anti-cross-site-abuse** control enforced by browsers, **not** client authentication: non-browser programs can always omit or forge `Origin`, which is why per-IP `/64` rate limits (`limit.ts`), CPace password-authenticated key exchange, hybrid `Noise + ML-KEM-768` session keys, and 4-word SAS verification remain the cryptographic root of trust.
