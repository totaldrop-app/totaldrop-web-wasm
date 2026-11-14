// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Comprehensive Node 24 test suite for the zero-framework TotalDrop Web Receiver
// (`fs-writer.js`, `transport.js`, `receiver.js`, `index.html`, and `styles.css`).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  VerifiedFileSink,
  assertSafeBrowserPath,
  supportsFileSystemAccess,
} from "../fs-writer.js";
import {
  DEFAULT_ENDPOINTS,
  TotalDropWebReceiver,
  bootstrapBrowserUi,
  consumeLocationFragment,
  loadVerifiedWasmReceiver,
  supportsWasmSimd128,
} from "../receiver.js";
import {
  MAX_MAILBOX_FRAME_BYTES,
  MAX_RELAY_FRAME_BYTES,
  RELAY_TAG_CONTROL,
  RelayStreamTransport,
  RendezvousMailboxClient,
  computeBackoffDelayMs,
  decodeRelayFrame,
  encodeChunkFrame,
  encodeControlFrame,
  validateRelayPairName,
  validateWebSocketOrigin,
} from "../transport.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WEB_UI_DIR = resolve(__dirname, "..");

/**
 * Minimal valid 8-byte empty WebAssembly module (`\0asm` version 1).
 */
const EMPTY_WASM_MODULE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
]);

/**
 * In-memory mock `FileSystemWritableFileStream` modeling Chromium's `.crswap`
 * temporary swap buffer: bytes enter `swapChunks` on `write()`, promote to
 * `committedBytes` ONLY on `close()`, and are wiped to zero on `abort()`.
 */
class MockSwapWritableStream {
  swapChunks = [];
  committedBytes = null;
  aborted = false;
  abortReason = undefined;
  closed = false;

  async write(chunk) {
    if (this.closed || this.aborted) {
      throw new Error("Stream already finalized");
    }
    this.swapChunks.push(chunk.slice());
  }

  async close() {
    if (this.closed || this.aborted) {
      throw new Error("Stream already finalized");
    }
    this.closed = true;
    const total = this.swapChunks.reduce((sum, c) => sum + c.byteLength, 0);
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const part of this.swapChunks) {
      merged.set(part, offset);
      offset += part.byteLength;
    }
    this.committedBytes = merged;
    this.swapChunks = [];
  }

  async abort(reason) {
    this.aborted = true;
    this.abortReason = reason;
    this.swapChunks = [];
    this.committedBytes = null;
  }
}

/**
 * Deterministic in-memory mock `WebSocket` supporting DOM `addEventListener`,
 * binary `ArrayBuffer` delivery, outbound frame capture, and close tracking.
 */
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances = [];

  static reset() {
    MockWebSocket.instances = [];
  }

  url;
  binaryType = "blob";
  readyState = MockWebSocket.CONNECTING;
  sentFrames = [];
  closeCode = null;
  closeReason = "";
  #listeners = new Map();

  constructor(url) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  addEventListener(type, listener) {
    const list = this.#listeners.get(type) ?? [];
    list.push(listener);
    this.#listeners.set(type, list);
  }

  send(data) {
    if (this.readyState !== MockWebSocket.OPEN) {
      throw new Error("MockWebSocket is not open");
    }
    this.sentFrames.push(data instanceof Uint8Array ? data.slice() : data);
  }

  close(code = 1000, reason = "") {
    if (this.readyState >= MockWebSocket.CLOSING) return;
    this.readyState = MockWebSocket.CLOSED;
    this.closeCode = code;
    this.closeReason = reason;
    this.#emit("close", { code, reason });
  }

  serverOpen() {
    this.readyState = MockWebSocket.OPEN;
    this.#emit("open", {});
  }

  serverSendBinary(bytes) {
    const buf = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    );
    this.#emit("message", { data: buf });
  }

  serverSendText(text) {
    this.#emit("message", { data: text });
  }

  serverDrop(code = 1006, reason = "abnormal closure") {
    if (this.readyState === MockWebSocket.CLOSED) return;
    this.readyState = MockWebSocket.CLOSED;
    this.closeCode = code;
    this.closeReason = reason;
    this.#emit("close", { code, reason });
  }

  #emit(type, event) {
    const list = this.#listeners.get(type) ?? [];
    for (const fn of list) {
      fn(event);
    }
  }
}

/**
 * Create a mock browser `window` exposing `isSecureContext`,
 * `showSaveFilePicker`, and `showDirectoryPicker` backed by `MockSwapWritableStream`.
 */
function createMockBrowserWindow() {
  const singleFileStreams = [];
  const directoryTree = new Map();

  function createDirHandle(prefixSegments) {
    return {
      async getDirectoryHandle(name, options) {
        assert.equal(options?.create, true);
        const nextPath = [...prefixSegments, name].join("/");
        if (!directoryTree.has(`dir:${nextPath}`)) {
          directoryTree.set(`dir:${nextPath}`, true);
        }
        return createDirHandle([...prefixSegments, name]);
      },
      async getFileHandle(name, options) {
        assert.equal(options?.create, true);
        const filePath = [...prefixSegments, name].join("/");
        return {
          async createWritable(writableOpts) {
            assert.equal(writableOpts?.keepExistingData, false);
            const stream = new MockSwapWritableStream();
            directoryTree.set(`file:${filePath}`, stream);
            return stream;
          },
        };
      },
    };
  }

  const win = {
    isSecureContext: true,
    WebSocket: MockWebSocket,
    async showSaveFilePicker(options) {
      const stream = new MockSwapWritableStream();
      singleFileStreams.push({ suggestedName: options.suggestedName, stream });
      return {
        async createWritable(writableOpts) {
          assert.equal(writableOpts?.keepExistingData, false);
          return stream;
        },
      };
    },
    async showDirectoryPicker(options) {
      assert.equal(options?.mode, "readwrite");
      return createDirHandle([]);
    },
  };

  return { win, singleFileStreams, directoryTree };
}

test("1. supportsWasmSimd128 detects fixed-width 128-bit SIMD on Node 24", () => {
  assert.equal(supportsWasmSimd128(), true);
  assert.equal(DEFAULT_ENDPOINTS.rendezvousOrigin, "wss://rendezvous.totaldrop.app");
  assert.equal(DEFAULT_ENDPOINTS.relayOrigin, "wss://relay.totaldrop.app");
});

test("2. consumeLocationFragment scrubs URL bar via history.replaceState and rejects >1024-byte fragments", () => {
  const replacedCalls = [];
  const mockWin = {
    location: {
      pathname: "/r",
      search: "?v=1",
      hash: "#7-abandon-ability",
    },
    history: {
      replaceState(state, unused, url) {
        replacedCalls.push({ state, unused, url });
      },
    },
  };

  const extracted = consumeLocationFragment(mockWin);
  assert.equal(extracted, "#7-abandon-ability");
  assert.deepEqual(replacedCalls, [{ state: null, unused: "", url: "/r?v=1" }]);

  // Preserves location bar when scrubLocationBar is false:
  const preserved = consumeLocationFragment(mockWin, { scrubLocationBar: false });
  assert.equal(preserved, "#7-abandon-ability");
  assert.equal(replacedCalls.length, 1);

  // Empty or bare '#' fragments return null:
  assert.equal(consumeLocationFragment({ location: { hash: "" } }), null);
  assert.equal(consumeLocationFragment({ location: { hash: "#" } }), null);

  // Over-limit fragment (> 1024 characters) is rejected unread without calling replaceState:
  const oversizedWin = {
    location: {
      pathname: "/r",
      search: "",
      hash: "#" + "x".repeat(1024),
    },
    history: {
      replaceState() {
        assert.fail("replaceState must not run on rejected oversized fragments");
      },
    },
  };
  assert.equal(oversizedWin.location.hash.length, 1025);
  assert.equal(consumeLocationFragment(oversizedWin), null);
});

test("3. loadVerifiedWasmReceiver enforces SHA-384 SRI integrity and instantiates WASM", async () => {
  const validSri = "sha384-" + "A".repeat(64);

  await assert.rejects(
    () =>
      loadVerifiedWasmReceiver({
        simd128: { url: "/wasm/simd.wasm", integrity: "sha256-wrong" },
        baseline: { url: "/wasm/base.wasm", integrity: validSri },
      }),
    /Missing URL or SHA-384 SRI integrity/,
  );

  let observedInit = null;
  const loaded = await loadVerifiedWasmReceiver({
    simd128: { url: "/wasm/totaldrop-simd128.wasm", integrity: validSri },
    baseline: { url: "/wasm/totaldrop-baseline.wasm", integrity: validSri },
    async fetchImpl(url, init) {
      observedInit = { url, init };
      return {
        ok: true,
        status: 200,
        async arrayBuffer() {
          return EMPTY_WASM_MODULE.buffer.slice(0);
        },
      };
    },
  });

  assert.equal(loaded.variant, "simd128");
  assert.ok(loaded.instance instanceof WebAssembly.Instance);
  assert.equal(observedInit.url, "/wasm/totaldrop-simd128.wasm");
  assert.equal(observedInit.init.integrity, validSri);
  assert.equal(observedInit.init.credentials, "omit");
  assert.equal(observedInit.init.mode, "same-origin");
});

test("4. assertSafeBrowserPath normalizes NFD to NFC and rejects traversal or invalid depth", () => {
  // NFD 'e' + combining acute (\u0301) normalizes to NFC '\u00e9'
  const normalized = assertSafeBrowserPath(["docs", "cafe\u0301-notes.txt"]);
  assert.deepEqual(normalized, ["docs", "caf\u00e9-notes.txt"]);

  assert.throws(() => assertSafeBrowserPath([]), /Unsafe manifest path depth/);
  assert.throws(
    () => assertSafeBrowserPath(Array.from({ length: 65 }, (_, i) => `d${i}`)),
    /Unsafe manifest path depth/,
  );
  assert.throws(() => assertSafeBrowserPath([".."]), /Dot or empty segment/);
  assert.throws(() => assertSafeBrowserPath(["safe", "..", "etc"]), /Dot or empty segment/);
  assert.throws(() => assertSafeBrowserPath(["."]), /Dot or empty segment/);
  assert.throws(() => assertSafeBrowserPath([""]), /Dot or empty segment/);
});

test("5. assertSafeBrowserPath rejects Windows reserved names, bidi overrides, control chars, and trailing dot/space", () => {
  // Windows device names (case-insensitive, with or without extension)
  for (const reserved of ["CON.txt", "nul", "prn.pdf", "COM1.log", "lpt9.dat"]) {
    assert.throws(
      () => assertSafeBrowserPath([reserved]),
      /Reserved device name/,
      `Expected ${reserved} to be rejected`,
    );
  }

  // Bidirectional Trojan-Source / extension-spoofing overrides
  assert.throws(
    () => assertSafeBrowserPath(["report\u202Efdp.exe"]),
    /Forbidden or bidirectional control character/,
  );
  assert.throws(
    () => assertSafeBrowserPath(["\u2066isolated.txt"]),
    /Forbidden or bidirectional control character/,
  );

  // Forbidden separators & ASCII/C1 control bytes
  assert.throws(() => assertSafeBrowserPath(["sub/file.txt"]), /Forbidden/);
  assert.throws(() => assertSafeBrowserPath(["sub\\file.txt"]), /Forbidden/);
  assert.throws(() => assertSafeBrowserPath(["bad:stream"]), /Forbidden/);
  assert.throws(() => assertSafeBrowserPath(["line\nbreak.txt"]), /Control character/);
  assert.throws(() => assertSafeBrowserPath(["del\x7fchar.txt"]), /Control character/);

  // Trailing dot and trailing space
  assert.throws(() => assertSafeBrowserPath(["report."]), /Trailing dot or space/);
  assert.throws(() => assertSafeBrowserPath(["report "]), /Trailing dot or space/);
});

test("6. VerifiedFileSink streams multi-chunk plaintext and commits only when verified", async () => {
  const swap = new MockSwapWritableStream();
  const sink = new VerifiedFileSink(swap, 10);

  await sink.writeVerifiedChunk(new Uint8Array([1, 2, 3, 4]));
  await sink.writeVerifiedChunk(new Uint8Array([5, 6, 7, 8, 9, 10]));

  // Swap file is still uncommitted prior to commit(true):
  assert.equal(sink.bytesWritten, 10);
  assert.equal(swap.committedBytes, null);
  assert.equal(swap.aborted, false);

  await sink.commit(true);
  assert.equal(swap.closed, true);
  assert.deepEqual(
    swap.committedBytes,
    new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
  );
});

test("7. VerifiedFileSink aborts immediately when manifest byte size is exceeded or commit(false) is called", async () => {
  // Case A: Exceeding declared manifest size aborts swap buffer
  const overflowSwap = new MockSwapWritableStream();
  const overflowSink = new VerifiedFileSink(overflowSwap, 5);
  await overflowSink.writeVerifiedChunk(new Uint8Array([10, 20, 30]));
  await assert.rejects(
    () => overflowSink.writeVerifiedChunk(new Uint8Array([40, 50, 60])),
    /Plaintext stream exceeded declared manifest size/,
  );
  assert.equal(overflowSwap.aborted, true);
  assert.equal(overflowSwap.committedBytes, null);

  // Case B: commit(false) aborts swap buffer even if byte count matched
  const unverifiedSwap = new MockSwapWritableStream();
  const unverifiedSink = new VerifiedFileSink(unverifiedSwap, 3);
  await unverifiedSink.writeVerifiedChunk(new Uint8Array([7, 8, 9]));
  await assert.rejects(
    () => unverifiedSink.commit(false),
    /Refusing to commit unverified or incomplete file/,
  );
  assert.equal(unverifiedSwap.aborted, true);
  assert.equal(unverifiedSwap.committedBytes, null);

  // Case C: Truncated stream (fewer bytes than expected) refuses commit(true)
  const truncatedSwap = new MockSwapWritableStream();
  const truncatedSink = new VerifiedFileSink(truncatedSwap, 8);
  await truncatedSink.writeVerifiedChunk(new Uint8Array([1, 2, 3]));
  await assert.rejects(
    () => truncatedSink.commit(true),
    /Refusing to commit unverified or incomplete file/,
  );
  assert.equal(truncatedSwap.aborted, true);
  assert.equal(truncatedSwap.committedBytes, null);
});

test("8. encodeControlFrame, encodeChunkFrame, and decodeRelayFrame round-trip deterministically", () => {
  const controlPayload = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
  const encodedControl = encodeControlFrame(controlPayload);
  assert.equal(encodedControl[0], RELAY_TAG_CONTROL);
  const decodedControl = decodeRelayFrame(encodedControl.buffer);
  assert.equal(decodedControl.kind, "control");
  assert.deepEqual(decodedControl.payload, controlPayload);

  const ciphertext = new Uint8Array([1, 3, 5, 7, 9, 11]);
  const encodedChunk = encodeChunkFrame(42, 1025n, ciphertext);
  assert.equal(encodedChunk.byteLength, 13 + ciphertext.byteLength);
  const decodedChunk = decodeRelayFrame(encodedChunk);
  assert.equal(decodedChunk.kind, "chunk");
  assert.equal(decodedChunk.entryIndex, 42);
  assert.equal(decodedChunk.chunkIndex, 1025);
  assert.deepEqual(decodedChunk.ciphertext, ciphertext);

  // Reject unknown tags, truncated chunk headers, and oversized frames
  assert.throws(() => decodeRelayFrame(new Uint8Array([0x99, 0x01])), /Unknown relay frame tag/);
  assert.throws(() => decodeRelayFrame(new Uint8Array(13).fill(0x02)), /truncated/);
  assert.throws(
    () => decodeRelayFrame(new Uint8Array(MAX_RELAY_FRAME_BYTES + 1)),
    /exceeds limit/,
  );
});

test("9. validateWebSocketOrigin enforces wss:// on public hosts and allows loopback ws://", () => {
  assert.equal(
    validateWebSocketOrigin("wss://rendezvous.totaldrop.app"),
    "wss://rendezvous.totaldrop.app",
  );
  assert.equal(
    validateWebSocketOrigin("wss://relay.totaldrop.app/"),
    "wss://relay.totaldrop.app",
  );
  assert.equal(validateWebSocketOrigin("ws://127.0.0.1:8787"), "ws://127.0.0.1:8787");
  assert.equal(validateWebSocketOrigin("ws://[::1]:8788"), "ws://[::1]:8788");
  assert.equal(validateWebSocketOrigin("ws://localhost:9000"), "ws://localhost:9000");

  // Reject insecure ws:// on public hosts or spoofed loopback prefixes
  assert.throws(
    () => validateWebSocketOrigin("ws://rendezvous.totaldrop.app"),
    /Insecure ws:\/\/ WebSocket origin rejected/,
  );
  assert.throws(
    () => validateWebSocketOrigin("ws://127.0.0.1.evil.example:8787"),
    /Insecure ws:\/\/ WebSocket origin rejected/,
  );
  assert.throws(
    () => validateWebSocketOrigin("https://rendezvous.totaldrop.app"),
    /Unsupported WebSocket scheme/,
  );
  assert.throws(
    () => validateWebSocketOrigin("wss://rendezvous.totaldrop.app/v0/mailbox"),
    /must not include a path/,
  );
});

test("10. validateRelayPairName enforces 64-hex symmetric pair names", () => {
  const pair64 = "0f".repeat(32);
  assert.equal(validateRelayPairName(pair64), pair64);

  const canonicalTwo = `${"01".repeat(32)}-${"ab".repeat(32)}`;
  assert.equal(validateRelayPairName(canonicalTwo), canonicalTwo);

  // Reject uppercase, wrong length, non-hex, traversal, and unsorted pairs
  assert.throws(() => validateRelayPairName("0F".repeat(32)), /Invalid relay pair name/);
  assert.throws(() => validateRelayPairName("a".repeat(63)), /Invalid relay pair name/);
  assert.throws(() => validateRelayPairName("a".repeat(65)), /Invalid relay pair name/);
  assert.throws(() => validateRelayPairName("g".repeat(64)), /Invalid relay pair name/);
  assert.throws(() => validateRelayPairName("../" + "a".repeat(61)), /Invalid relay pair name/);
  assert.throws(
    () => validateRelayPairName(`${"ab".repeat(32)}-${"01".repeat(32)}`),
    /Invalid relay pair name/,
  );
});

test("11. RendezvousMailboxClient enforces 64 KiB frame limit, FIFO ordering, deterministic backoff, and session lock", async () => {
  MockWebSocket.reset();
  assert.equal(
    computeBackoffDelayMs(0, { baseDelayMs: 200, maxDelayMs: 5000, jitterCapMs: 100 }),
    computeBackoffDelayMs(0, { baseDelayMs: 200, maxDelayMs: 5000, jitterCapMs: 100 }),
  );
  assert.ok(
    computeBackoffDelayMs(1, { baseDelayMs: 200, maxDelayMs: 5000, jitterCapMs: 50 }) >
      computeBackoffDelayMs(0, { baseDelayMs: 200, maxDelayMs: 5000, jitterCapMs: 50 }),
  );

  const scheduledCallbacks = [];
  const arrivalOrder = [];
  const errors = [];

  const client = new RendezvousMailboxClient({
    rendezvousOrigin: "ws://127.0.0.1:9100",
    nameplate: 19,
    WebSocketImpl: MockWebSocket,
    maxReconnectAttempts: 2,
    scheduleTimer(fn, delayMs) {
      scheduledCallbacks.push({ fn, delayMs });
      return scheduledCallbacks.length;
    },
    cancelTimer() {},
    async onFrame(frame) {
      if (frame[0] === 1) {
        await new Promise((r) => setImmediate(r));
      }
      arrivalOrder.push(frame[0]);
    },
    onError(err) {
      errors.push(err);
    },
  });

  const ws1 = client.connect();
  assert.equal(ws1.url, "ws://127.0.0.1:9100/v0/mailbox/19");
  assert.equal(ws1.binaryType, "arraybuffer");
  ws1.serverOpen();

  // FIFO serial processing even when frame 1 awaits asynchronously
  ws1.serverSendBinary(new Uint8Array([1]));
  ws1.serverSendBinary(new Uint8Array([2]));
  await client.whenIdle();
  assert.deepEqual(arrivalOrder, [1, 2]);

  // Transient drop before session lock schedules deterministic backoff reconnect
  ws1.serverDrop(1006, "network drop");
  assert.equal(client.reconnectAttempts, 1);
  assert.equal(scheduledCallbacks.length, 1);
  scheduledCallbacks[0].fn();
  assert.equal(MockWebSocket.instances.length, 2);

  // Locking session prevents further reconnects on drop
  const ws2 = MockWebSocket.instances[1];
  ws2.serverOpen();
  client.lockSession();
  assert.equal(client.sessionLocked, true);
  ws2.serverDrop(1006, "dropped after lock");
  assert.equal(scheduledCallbacks.length, 1);

  // Oversized frame (> 64 KiB) on a fresh client is rejected with close code 1009
  const guardClient = new RendezvousMailboxClient({
    rendezvousOrigin: "ws://localhost:9100",
    nameplate: 7,
    WebSocketImpl: MockWebSocket,
    onError(err) {
      errors.push(err);
    },
  });
  const ws3 = guardClient.connect();
  ws3.serverOpen();
  ws3.serverSendBinary(new Uint8Array(MAX_MAILBOX_FRAME_BYTES + 1));
  assert.equal(ws3.closeCode, 1009);
  assert.equal(errors.length, 1);

  // Clean close uses (1000, "done")
  const cleanClient = new RendezvousMailboxClient({
    rendezvousOrigin: "ws://[::1]:9100",
    nameplate: 3,
    WebSocketImpl: MockWebSocket,
  });
  const ws4 = cleanClient.connect();
  ws4.serverOpen();
  cleanClient.close();
  assert.equal(ws4.closeCode, 1000);
  assert.equal(ws4.closeReason, "done");
});

test("12. RelayStreamTransport rejects oversized frames (> 1 MiB + 4096 B) immediately", () => {
  MockWebSocket.reset();
  const observedErrors = [];
  const pairName = "ab".repeat(32);

  const relay = new RelayStreamTransport({
    relayOrigin: "ws://127.0.0.1:9200",
    pairName,
    WebSocketImpl: MockWebSocket,
    onError(err) {
      observedErrors.push(err);
    },
  });

  const ws = relay.connect();
  assert.equal(ws.url, `ws://127.0.0.1:9200/v0/relay/${pairName}`);
  assert.equal(ws.binaryType, "arraybuffer");
  ws.serverOpen();

  ws.serverSendBinary(new Uint8Array(MAX_RELAY_FRAME_BYTES + 1));
  assert.equal(ws.closeCode, 1009);
  assert.equal(observedErrors.length, 1);
  assert.match(observedErrors[0].message, /exceeds limit/);
});

test("13. TotalDropWebReceiver negotiates RTL/LTR locales and bootstrapBrowserUi surfaces fallback notice", () => {
  const receiver = new TotalDropWebReceiver({
    wasmBridge: {
      parseShareInput: () => ({ nameplate: 1, displayEnglish: "1-abandon-ability" }),
      negotiateLocale: (langs) =>
        langs[0]?.startsWith("ar")
          ? { tag: "ar", dir: "rtl" }
          : { tag: "en", dir: "ltr" },
      verifyEntryChunk: () => {
        throw new Error("unused");
      },
    },
  });

  const doc = { documentElement: { lang: "en", dir: "ltr" } };
  const negotiatedRtl = receiver.applyDocumentLocale(doc, { languages: ["ar-EG", "en"] });
  assert.deepEqual(negotiatedRtl, { tag: "ar", dir: "rtl" });
  assert.equal(doc.documentElement.lang, "ar");
  assert.equal(doc.documentElement.dir, "rtl");

  // Unsupported browser (no showSaveFilePicker) triggers fallback notice + URL scrub
  const unsupportedNotice = { hidden: true };
  const codeInput = { value: "", disabled: false };
  const connectButton = { disabled: false };
  const statusLine = { textContent: "", hidden: true };
  let scrubbedTo = null;

  const unsupportedWin = {
    isSecureContext: true,
    location: {
      pathname: "/r",
      search: "",
      hash: "#12-harbor-rocket",
    },
    history: {
      replaceState(_s, _u, url) {
        scrubbedTo = url;
      },
    },
    document: {
      getElementById(id) {
        const map = {
          "unsupported-browser-notice": unsupportedNotice,
          "transfer-code-input": codeInput,
          "connect-button": connectButton,
          "connection-status": statusLine,
        };
        return map[id] ?? null;
      },
    },
  };

  assert.equal(supportsFileSystemAccess(unsupportedWin), false);
  bootstrapBrowserUi(unsupportedWin);
  assert.equal(scrubbedTo, "/r");
  assert.equal(codeInput.value, "12-harbor-rocket");
  assert.equal(unsupportedNotice.hidden, false);
  assert.equal(connectButton.disabled, true);
  assert.equal(codeInput.disabled, true);
});

test("14. End-to-end single-file multi-chunk transfer over mock WebSocket commits swap buffer and sends encryptedEntryDone", async () => {
  MockWebSocket.reset();
  const { win, singleFileStreams } = createMockBrowserWindow();
  const statusEvents = [];

  const chunk0Plain = new Uint8Array([10, 20, 30, 40]);
  const chunk1Plain = new Uint8Array([50, 60, 70]);
  const chunk2Plain = new Uint8Array([80, 90]);
  const fullExpected = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80, 90]);
  const expectedAcceptReply = new Uint8Array([0xa1, 0xa2, 0xa3]);
  const expectedDoneReply = new Uint8Array([0xd0, 0xd1, 0xd2, 0xd3]);

  const receiver = new TotalDropWebReceiver({
    win,
    endpoints: {
      rendezvousOrigin: "ws://127.0.0.1:9300",
      relayOrigin: "ws://127.0.0.1:9301",
    },
    onStatus(ev) {
      statusEvents.push(ev);
    },
    wasmBridge: {
      parseShareInput(input) {
        assert.equal(input, "#7-abandon-ability");
        return { nameplate: 7, displayEnglish: "7-abandon-ability" };
      },
      negotiateLocale: () => ({ tag: "en", dir: "ltr" }),
      acceptEncryptedOffer(payload) {
        assert.deepEqual(payload, new Uint8Array([0xee, 0x01]));
        return {
          offer: {
            entries: [
              {
                index: 0,
                kind: "file",
                pathSegments: ["archive.tar.zst"],
                size: fullExpected.byteLength,
              },
            ],
          },
          encryptedAccept: expectedAcceptReply,
        };
      },
      verifyEntryChunk(entryIndex, chunkIndex, ciphertext) {
        assert.equal(entryIndex, 0);
        // Simulated stream opener: strips 0x55 marker prefix
        assert.equal(ciphertext[0], 0x55);
        const plain = ciphertext.subarray(1);
        const isLast = chunkIndex === 2;
        return {
          plaintext: plain,
          entryComplete: isLast,
          encryptedEntryDone: isLast ? expectedDoneReply : null,
          transferComplete: isLast,
        };
      },
    },
  });

  const { nameplate, mailboxClient } = receiver.connectMailbox("#7-abandon-ability");
  assert.equal(nameplate, 7);
  mailboxClient.socket.serverOpen();

  const pairName = "1a".repeat(32);
  const relay = receiver.attachRelayTransport(pairName, MockWebSocket);
  relay.socket.serverOpen();
  assert.equal(mailboxClient.sessionLocked, true);

  // Peer sends encrypted Control::Offer (0x01) followed by 3 encrypted chunk frames (0x02)
  relay.socket.serverSendBinary(encodeControlFrame(new Uint8Array([0xee, 0x01])));
  relay.socket.serverSendBinary(
    encodeChunkFrame(0, 0, new Uint8Array([0x55, ...chunk0Plain])),
  );
  relay.socket.serverSendBinary(
    encodeChunkFrame(0, 1, new Uint8Array([0x55, ...chunk1Plain])),
  );
  relay.socket.serverSendBinary(
    encodeChunkFrame(0, 2, new Uint8Array([0x55, ...chunk2Plain])),
  );

  await relay.whenIdle();

  // Verify showSaveFilePicker swap buffer committed exact plaintext
  assert.equal(singleFileStreams.length, 1);
  assert.equal(singleFileStreams[0].suggestedName, "archive.tar.zst");
  assert.equal(singleFileStreams[0].stream.closed, true);
  assert.equal(singleFileStreams[0].stream.aborted, false);
  assert.deepEqual(singleFileStreams[0].stream.committedBytes, fullExpected);

  // Verify outbound relay control frames: Accept followed by EntryDone
  assert.equal(relay.socket.sentFrames.length, 2);
  assert.deepEqual(
    decodeRelayFrame(relay.socket.sentFrames[0]),
    { kind: "control", payload: expectedAcceptReply },
  );
  assert.deepEqual(
    decodeRelayFrame(relay.socket.sentFrames[1]),
    { kind: "control", payload: expectedDoneReply },
  );

  // Verify clean completion status and WebSocket close(1000, "done")
  assert.equal(statusEvents.at(-1)?.phase, "done");
  assert.equal(relay.socket.closeCode, 1000);
  assert.equal(relay.socket.closeReason, "done");
});

test("15. End-to-end multi-file directory offer creates nested directories and commits all verified files", async () => {
  MockWebSocket.reset();
  const { win, directoryTree } = createMockBrowserWindow();
  const phases = [];

  const file1Part0 = new Uint8Array([1, 2, 3]);
  const file1Part1 = new Uint8Array([4, 5]);
  const file2Single = new Uint8Array([99, 100, 101, 102]);

  const receiver = new TotalDropWebReceiver({
    win,
    endpoints: { relayOrigin: "ws://localhost:9401" },
    onStatus(ev) {
      phases.push(ev.phase);
    },
    wasmBridge: {
      parseShareInput: () => ({ nameplate: 3, displayEnglish: "3-abandon-ability" }),
      negotiateLocale: () => ({ tag: "en", dir: "ltr" }),
      acceptEncryptedOffer() {
        return {
          offer: {
            entries: [
              { index: 0, kind: "dir", pathSegments: ["project", "assets"], size: 0 },
              {
                index: 1,
                kind: "file",
                pathSegments: ["project", "readme.txt"],
                size: 5,
              },
              {
                index: 2,
                kind: "file",
                pathSegments: ["project", "assets", "logo.bin"],
                size: 4,
              },
            ],
          },
          encryptedAccept: new Uint8Array([0x10]),
        };
      },
      verifyEntryChunk(entryIndex, chunkIndex, ciphertext) {
        if (entryIndex === 1) {
          const done = chunkIndex === 1;
          return {
            plaintext: ciphertext,
            entryComplete: done,
            encryptedEntryDone: done ? new Uint8Array([0xe1]) : null,
            transferComplete: false,
          };
        }
        if (entryIndex === 2 && chunkIndex === 0) {
          return {
            plaintext: ciphertext,
            entryComplete: true,
            encryptedEntryDone: new Uint8Array([0xe2]),
            transferComplete: true,
          };
        }
        throw new Error("Unexpected entry/chunk");
      },
    },
  });

  const relay = receiver.attachRelayTransport("2b".repeat(32), MockWebSocket);
  relay.socket.serverOpen();

  relay.socket.serverSendBinary(encodeControlFrame(new Uint8Array([0x01])));
  relay.socket.serverSendBinary(encodeChunkFrame(1, 0, file1Part0));
  relay.socket.serverSendBinary(encodeChunkFrame(1, 1, file1Part1));
  relay.socket.serverSendBinary(encodeChunkFrame(2, 0, file2Single));

  await relay.whenIdle();

  assert.equal(directoryTree.get("dir:project/assets"), true);
  const stream1 = directoryTree.get("file:project/readme.txt");
  const stream2 = directoryTree.get("file:project/assets/logo.bin");
  assert.deepEqual(stream1.committedBytes, new Uint8Array([1, 2, 3, 4, 5]));
  assert.deepEqual(stream2.committedBytes, new Uint8Array([99, 100, 101, 102]));
  assert.equal(relay.socket.sentFrames.length, 3); // Accept + EntryDone(1) + EntryDone(2)
  assert.ok(phases.includes("done"));
});

test("16. End-to-end session immediately aborts swap file (zero committed bytes) on AEAD verification failure", async () => {
  MockWebSocket.reset();
  const { win, singleFileStreams } = createMockBrowserWindow();
  const statusEvents = [];

  const receiver = new TotalDropWebReceiver({
    win,
    endpoints: { relayOrigin: "ws://127.0.0.1:9501" },
    onStatus(ev) {
      statusEvents.push(ev);
    },
    wasmBridge: {
      parseShareInput: () => ({ nameplate: 5, displayEnglish: "5-abandon-ability" }),
      negotiateLocale: () => ({ tag: "en", dir: "ltr" }),
      acceptEncryptedOffer() {
        return {
          offer: {
            entries: [
              {
                index: 0,
                kind: "file",
                pathSegments: ["sensitive.iso"],
                size: 8,
              },
            ],
          },
          encryptedAccept: new Uint8Array([0xaa]),
        };
      },
      verifyEntryChunk(_entryIndex, chunkIndex, ciphertext) {
        if (chunkIndex === 0) {
          return {
            plaintext: ciphertext,
            entryComplete: false,
            encryptedEntryDone: null,
            transferComplete: false,
          };
        }
        throw new Error("AEAD tag verification failed on chunk 1");
      },
    },
  });

  const relay = receiver.attachRelayTransport("3c".repeat(32), MockWebSocket);
  relay.socket.serverOpen();

  relay.socket.serverSendBinary(encodeControlFrame(new Uint8Array([0x01])));
  // Chunk 0 writes 4 bytes to temporary .crswap buffer
  relay.socket.serverSendBinary(encodeChunkFrame(0, 0, new Uint8Array([1, 2, 3, 4])));
  // Chunk 1 is tampered -> WASM throws -> VerifiedFileSink.abort() discards swap buffer!
  relay.socket.serverSendBinary(encodeChunkFrame(0, 1, new Uint8Array([9, 9, 9, 9])));

  await relay.whenIdle();

  assert.equal(receiver.aborted, true);
  assert.equal(receiver.activeSinkCount, 0);
  assert.equal(singleFileStreams.length, 1);
  const swapStream = singleFileStreams[0].stream;
  assert.equal(swapStream.aborted, true);
  assert.equal(swapStream.closed, false);
  assert.equal(swapStream.committedBytes, null);
  assert.equal(swapStream.swapChunks.length, 0);

  // Only the initial Accept control frame was sent; no EntryDone frame was emitted
  assert.equal(relay.socket.sentFrames.length, 1);
  assert.equal(statusEvents.at(-1)?.phase, "aborted");
});

test("17. index.html and styles.css uphold Aurora tokens, RTL logical CSS, motion-gated Kose mark, and SAS isolation", () => {
  const html = readFileSync(resolve(WEB_UI_DIR, "index.html"), "utf8");
  const css = readFileSync(resolve(WEB_UI_DIR, "styles.css"), "utf8");

  // Kose brand mark geometry & 4-word LTR isolated SAS card & Offer buttons & ARIA progressbar
  assert.match(html, /M55 15H97V57A42 42 0 1 1 55 15Z/);
  assert.match(html, /id="sas-word-list"[^>]*dir="ltr"/);
  assert.match(html, /Accept &amp; Save/);
  assert.match(html, /Decline/);
  assert.match(html, /role="progressbar"[\s\S]*?aria-valuenow="0"/);
  assert.match(html, /id="unsupported-browser-notice"/);

  // Aurora light (#6D4AE0) & dark (#A68BFF) accents + prefers-reduced-motion gating
  assert.match(css, /#6D4AE0/i);
  assert.match(css, /@media\s*\(prefers-color-scheme:\s*dark\)/);
  assert.match(css, /#A68BFF/i);
  assert.match(css, /@media\s*\(prefers-reduced-motion:\s*no-preference\)/);
  assert.match(css, /3\.2s/);

  // Logical CSS properties used instead of physical horizontal properties
  assert.match(css, /margin-inline/);
  assert.match(css, /padding-inline/);
  assert.match(css, /inset-inline-start/);
  assert.doesNotMatch(css, /\b(?:margin|padding|border)-(?:left|right)\s*:/);
});
