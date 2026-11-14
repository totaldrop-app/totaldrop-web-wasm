// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Zero-dependency WebSocket transport primitives for the TotalDrop Web Receiver:
// - `RendezvousMailboxClient`: connects to `/v0/mailbox/<nameplate>`, enforces
//   strict `wss://` (or loopback `ws://`) origin rules and a 64 KiB frame ceiling,
//   processes inbound binary frames sequentially in arrival order, and applies
//   deterministic capped exponential backoff for transient drops prior to session
//   lock.
// - `RelayStreamTransport`: connects to `/v0/relay/<pairName>`, validates the
//   symmetric hex pair identifier, enforces a `1 MiB + 4096 B` frame ceiling, and
//   demultiplexes `0x01` control frames from `0x02` encrypted entry chunk frames.

/** Maximum inbound/outbound binary frame size on the rendezvous mailbox (64 KiB). */
export const MAX_MAILBOX_FRAME_BYTES = 64 * 1024;

/** Maximum inbound/outbound binary frame size on the streaming relay (1 MiB + 4 KiB). */
export const MAX_RELAY_FRAME_BYTES = (1 << 20) + 4096;

/** Relay wire tag for encrypted session control frames (`Control::*`). */
export const RELAY_TAG_CONTROL = 0x01;

/** Relay wire tag for encrypted file chunk frames (`u32be entry || u64be chunk || ct`). */
export const RELAY_TAG_CHUNK = 0x02;

const CHUNK_HEADER_BYTES = 1 + 4 + 8;
const WS_CONNECTING = 0;
const WS_OPEN = 1;

const HEX_64_RE = /^[0-9a-f]{64}$/;
const HEX_PAIR_RE = /^([0-9a-f]{64})-([0-9a-f]{64})$/;

/**
 * Validate and normalize a WebSocket server origin.
 * Allows `wss://` on any valid host, and `ws://` strictly on loopback
 * (`127.0.0.1`, `[::1]`, `localhost`) for automated local test harnesses.
 *
 * @param {string} origin
 * @returns {string} Normalized origin without a trailing slash
 */
export function validateWebSocketOrigin(origin) {
  if (typeof origin !== "string" || origin.length === 0 || origin.trim() !== origin) {
    throw new Error("WebSocket origin must be a non-empty trimmed URL string");
  }
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error(`Malformed WebSocket origin URL: ${origin}`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new Error("WebSocket origin URL must not contain embedded credentials");
  }
  if (parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== "") {
    throw new Error("WebSocket origin URL must not include a path, query, or fragment");
  }
  if (parsed.protocol === "wss:") {
    return `${parsed.protocol}//${parsed.host}`;
  }
  if (parsed.protocol === "ws:") {
    const host = parsed.hostname;
    const isLoopback =
      host === "127.0.0.1" ||
      host === "[::1]" ||
      host === "::1" ||
      host === "localhost";
    if (!isLoopback) {
      throw new Error(`Insecure ws:// WebSocket origin rejected for public host: ${host}`);
    }
    return `${parsed.protocol}//${parsed.host}`;
  }
  throw new Error(`Unsupported WebSocket scheme: ${parsed.protocol}`);
}

/**
 * Validate a relay symmetric pair name (`64` lowercase hex characters, or
 * canonical sorted `<64-hex>-<64-hex>` endpoint pair).
 *
 * @param {string} pairName
 * @returns {string}
 */
export function validateRelayPairName(pairName) {
  if (typeof pairName !== "string") {
    throw new Error("Relay pair name must be a string");
  }
  if (HEX_64_RE.test(pairName)) {
    return pairName;
  }
  const pairMatch = HEX_PAIR_RE.exec(pairName);
  if (pairMatch && pairMatch[1] < pairMatch[2]) {
    return pairName;
  }
  throw new Error(
    "Invalid relay pair name: expected 64 lowercase hex characters (or canonical <hex64>-<hex64>)",
  );
}

/**
 * Compute deterministic exponential backoff with a strict jitter ceiling.
 *
 * @param {number} attempt Zero-based retry attempt counter
 * @param {{
 *   baseDelayMs?: number,
 *   maxDelayMs?: number,
 *   jitterCapMs?: number,
 * }} [options]
 * @returns {number} Delay in milliseconds
 */
export function computeBackoffDelayMs(
  attempt,
  { baseDelayMs = 200, maxDelayMs = 8000, jitterCapMs = 150 } = {},
) {
  if (!Number.isInteger(attempt) || attempt < 0) {
    throw new RangeError("Backoff attempt must be a non-negative integer");
  }
  const expShift = Math.min(attempt, 12);
  const expDelay = Math.min(maxDelayMs, baseDelayMs * 2 ** expShift);
  const safeJitterCap = Math.max(0, Math.trunc(jitterCapMs));
  const deterministicJitter =
    safeJitterCap > 0 ? (attempt * 73 + 19) % (safeJitterCap + 1) : 0;
  return Math.min(maxDelayMs, expDelay + deterministicJitter);
}

/**
 * Convert an inbound WebSocket binary payload (`ArrayBuffer` or `ArrayBufferView`)
 * into a `Uint8Array` view without unnecessary heap copies.
 *
 * @param {unknown} raw
 * @returns {Uint8Array}
 */
function coerceBinaryFrame(raw) {
  if (raw instanceof Uint8Array) {
    return raw;
  }
  if (raw instanceof ArrayBuffer) {
    return new Uint8Array(raw);
  }
  if (ArrayBuffer.isView(raw)) {
    return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
  }
  throw new TypeError("WebSocket frame must be binary (ArrayBuffer or Uint8Array)");
}

/**
 * Attach DOM-standard or minimal mock event handlers to a WebSocket instance.
 *
 * @param {WebSocket} socket
 * @param {{
 *   open: (ev: unknown) => void,
 *   message: (ev: { data: unknown }) => void,
 *   close: (ev: { code?: number, reason?: string }) => void,
 *   error: (ev: unknown) => void,
 * }} handlers
 */
function attachSocketListeners(socket, handlers) {
  if (typeof socket.addEventListener === "function") {
    socket.addEventListener("open", handlers.open);
    socket.addEventListener("message", handlers.message);
    socket.addEventListener("close", handlers.close);
    socket.addEventListener("error", handlers.error);
  } else {
    socket.onopen = handlers.open;
    socket.onmessage = handlers.message;
    socket.onclose = handlers.close;
    socket.onerror = handlers.error;
  }
}

/**
 * Encode an encrypted control payload with the `0x01` relay control tag.
 *
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 */
export function encodeControlFrame(payload) {
  if (!(payload instanceof Uint8Array) || payload.byteLength === 0) {
    throw new TypeError("Control frame payload must be a non-empty Uint8Array");
  }
  const totalBytes = 1 + payload.byteLength;
  if (totalBytes > MAX_RELAY_FRAME_BYTES) {
    throw new RangeError(
      `Control frame (${totalBytes} B) exceeds relay limit (${MAX_RELAY_FRAME_BYTES} B)`,
    );
  }
  const out = new Uint8Array(totalBytes);
  out[0] = RELAY_TAG_CONTROL;
  out.set(payload, 1);
  return out;
}

/**
 * Encode an encrypted entry chunk frame:
 * `0x02 || u32be(entryIndex) || u64be(chunkIndex) || ciphertext`.
 *
 * @param {number} entryIndex
 * @param {number | bigint} chunkIndex
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array}
 */
export function encodeChunkFrame(entryIndex, chunkIndex, ciphertext) {
  if (!Number.isInteger(entryIndex) || entryIndex < 0 || entryIndex > 0xffff_ffff) {
    throw new RangeError("entryIndex must be an unsigned 32-bit integer");
  }
  let chunkBig;
  if (typeof chunkIndex === "bigint") {
    if (chunkIndex < 0n || chunkIndex > 0xffff_ffff_ffff_ffffn) {
      throw new RangeError("chunkIndex bigint must fit in unsigned 64 bits");
    }
    chunkBig = chunkIndex;
  } else if (Number.isSafeInteger(chunkIndex) && chunkIndex >= 0) {
    chunkBig = BigInt(chunkIndex);
  } else {
    throw new RangeError("chunkIndex must be a non-negative safe integer or bigint");
  }
  if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength === 0) {
    throw new TypeError("Chunk ciphertext must be a non-empty Uint8Array");
  }
  const totalBytes = CHUNK_HEADER_BYTES + ciphertext.byteLength;
  if (totalBytes > MAX_RELAY_FRAME_BYTES) {
    throw new RangeError(
      `Chunk frame (${totalBytes} B) exceeds relay limit (${MAX_RELAY_FRAME_BYTES} B)`,
    );
  }
  const out = new Uint8Array(totalBytes);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  out[0] = RELAY_TAG_CHUNK;
  view.setUint32(1, entryIndex, false);
  view.setBigUint64(5, chunkBig, false);
  out.set(ciphertext, CHUNK_HEADER_BYTES);
  return out;
}

/**
 * Decode and demultiplex an inbound relay WebSocket binary frame.
 *
 * @param {ArrayBuffer | Uint8Array} rawFrame
 * @returns {
 *   | { kind: "control", payload: Uint8Array }
 *   | { kind: "chunk", entryIndex: number, chunkIndex: number, ciphertext: Uint8Array }
 * }
 */
export function decodeRelayFrame(rawFrame) {
  const bytes = coerceBinaryFrame(rawFrame);
  if (bytes.byteLength > MAX_RELAY_FRAME_BYTES) {
    throw new RangeError(
      `Inbound relay frame (${bytes.byteLength} B) exceeds limit (${MAX_RELAY_FRAME_BYTES} B)`,
    );
  }
  if (bytes.byteLength < 2) {
    throw new Error("Inbound relay frame is too short");
  }
  const tag = bytes[0];
  if (tag === RELAY_TAG_CONTROL) {
    return {
      kind: "control",
      payload: bytes.subarray(1),
    };
  }
  if (tag === RELAY_TAG_CHUNK) {
    if (bytes.byteLength <= CHUNK_HEADER_BYTES) {
      throw new Error("Inbound relay chunk frame is truncated");
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const entryIndex = view.getUint32(1, false);
    const chunkBig = view.getBigUint64(5, false);
    if (chunkBig > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new RangeError("Inbound chunkIndex exceeds Number.MAX_SAFE_INTEGER");
    }
    return {
      kind: "chunk",
      entryIndex,
      chunkIndex: Number(chunkBig),
      ciphertext: bytes.subarray(CHUNK_HEADER_BYTES),
    };
  }
  throw new Error(`Unknown relay frame tag: 0x${tag.toString(16).padStart(2, "0")}`);
}

/**
 * Rendezvous mailbox WebSocket client (`/v0/mailbox/<nameplate>`).
 */
export class RendezvousMailboxClient {
  #origin;
  #nameplate;
  #WebSocketImpl;
  #maxFrameBytes;
  #maxReconnectAttempts;
  #backoffOptions;
  #scheduleTimer;
  #cancelTimer;
  #onOpen;
  #onFrame;
  #onClose;
  #onError;

  #socket = null;
  #sessionLocked = false;
  #closedByCaller = false;
  #protocolFailed = false;
  #reconnectAttempts = 0;
  #reconnectTimer = null;
  #processingChain = Promise.resolve();

  /**
   * @param {{
   *   rendezvousOrigin?: string,
   *   nameplate: number,
   *   WebSocketImpl?: typeof WebSocket,
   *   maxFrameBytes?: number,
   *   maxReconnectAttempts?: number,
   *   baseDelayMs?: number,
   *   maxDelayMs?: number,
   *   jitterCapMs?: number,
   *   scheduleTimer?: (fn: () => void, delayMs: number) => unknown,
   *   cancelTimer?: (timerId: unknown) => void,
   *   onOpen?: () => void,
   *   onFrame?: (frame: Uint8Array) => void | Promise<void>,
   *   onClose?: (info: { code: number, reason: string, willReconnect: boolean }) => void,
   *   onError?: (err: Error) => void,
   * }} config
   */
  constructor({
    rendezvousOrigin = "wss://rendezvous.totaldrop.app",
    nameplate,
    WebSocketImpl = globalThis.WebSocket,
    maxFrameBytes = MAX_MAILBOX_FRAME_BYTES,
    maxReconnectAttempts = 3,
    baseDelayMs = 200,
    maxDelayMs = 8000,
    jitterCapMs = 150,
    scheduleTimer = (fn, ms) => setTimeout(fn, ms),
    cancelTimer = (id) => clearTimeout(id),
    onOpen = () => {},
    onFrame = () => {},
    onClose = () => {},
    onError = () => {},
  }) {
    this.#origin = validateWebSocketOrigin(rendezvousOrigin);
    if (!Number.isInteger(nameplate) || nameplate < 1 || nameplate > 0xffff_ffff) {
      throw new RangeError("Mailbox nameplate must be an integer between 1 and 4294967295");
    }
    if (typeof WebSocketImpl !== "function") {
      throw new TypeError("WebSocket implementation is unavailable");
    }
    if (!Number.isInteger(maxFrameBytes) || maxFrameBytes < 1 || maxFrameBytes > MAX_MAILBOX_FRAME_BYTES) {
      throw new RangeError(`maxFrameBytes must be between 1 and ${MAX_MAILBOX_FRAME_BYTES}`);
    }
    this.#nameplate = nameplate;
    this.#WebSocketImpl = WebSocketImpl;
    this.#maxFrameBytes = maxFrameBytes;
    this.#maxReconnectAttempts = Math.max(0, Math.trunc(maxReconnectAttempts));
    this.#backoffOptions = { baseDelayMs, maxDelayMs, jitterCapMs };
    this.#scheduleTimer = scheduleTimer;
    this.#cancelTimer = cancelTimer;
    this.#onOpen = onOpen;
    this.#onFrame = onFrame;
    this.#onClose = onClose;
    this.#onError = onError;
  }

  /** @returns {string} */
  get url() {
    return `${this.#origin}/v0/mailbox/${this.#nameplate}`;
  }

  /** @returns {number} */
  get nameplate() {
    return this.#nameplate;
  }

  /** @returns {WebSocket | null} */
  get socket() {
    return this.#socket;
  }

  /** @returns {boolean} */
  get sessionLocked() {
    return this.#sessionLocked;
  }

  /** @returns {number} */
  get reconnectAttempts() {
    return this.#reconnectAttempts;
  }

  /**
   * Mark the mailbox session as locked to a peer so subsequent disconnects fail
   * closed instead of silently reconnecting.
   */
  lockSession() {
    this.#sessionLocked = true;
    this.#clearReconnectTimer();
  }

  /**
   * Open the WebSocket connection to `/v0/mailbox/<nameplate>`.
   *
   * @returns {WebSocket}
   */
  connect() {
    if (this.#closedByCaller) {
      throw new Error("RendezvousMailboxClient has already been closed");
    }
    this.#clearReconnectTimer();
    const socket = new this.#WebSocketImpl(this.url);
    socket.binaryType = "arraybuffer";
    this.#socket = socket;

    attachSocketListeners(socket, {
      open: () => {
        if (this.#socket !== socket || this.#closedByCaller) return;
        this.#onOpen();
      },
      message: (event) => {
        if (this.#socket !== socket || this.#closedByCaller || this.#protocolFailed) return;
        let bytes;
        try {
          bytes = coerceBinaryFrame(event?.data);
        } catch (err) {
          this.#failProtocol(socket, 1003, "binary frames required", err);
          return;
        }
        if (bytes.byteLength > this.#maxFrameBytes) {
          this.#failProtocol(
            socket,
            1009,
            "mailbox frame too large",
            new RangeError(
              `Inbound mailbox frame (${bytes.byteLength} B) exceeds limit (${this.#maxFrameBytes} B)`,
            ),
          );
          return;
        }
        const copy = bytes.slice();
        this.#processingChain = this.#processingChain.then(async () => {
          if (this.#closedByCaller || this.#protocolFailed) return;
          try {
            await this.#onFrame(copy);
          } catch (err) {
            this.#failProtocol(socket, 1008, "mailbox handler error", err);
          }
        });
      },
      close: (event) => {
        if (this.#socket !== socket) return;
        const code = typeof event?.code === "number" ? event.code : 1006;
        const reason = typeof event?.reason === "string" ? event.reason : "";
        const canReconnect =
          !this.#closedByCaller &&
          !this.#protocolFailed &&
          !this.#sessionLocked &&
          code !== 1000 &&
          this.#reconnectAttempts < this.#maxReconnectAttempts;

        if (canReconnect) {
          const attempt = this.#reconnectAttempts;
          this.#reconnectAttempts += 1;
          const delayMs = computeBackoffDelayMs(attempt, this.#backoffOptions);
          this.#onClose({ code, reason, willReconnect: true });
          this.#reconnectTimer = this.#scheduleTimer(() => {
            this.#reconnectTimer = null;
            if (!this.#closedByCaller && !this.#protocolFailed && !this.#sessionLocked) {
              this.connect();
            }
          }, delayMs);
          return;
        }
        this.#onClose({ code, reason, willReconnect: false });
      },
      error: (event) => {
        if (this.#socket !== socket || this.#closedByCaller) return;
        const err =
          event instanceof Error
            ? event
            : new Error("Rendezvous mailbox WebSocket transport error");
        this.#onError(err);
      },
    });

    return socket;
  }

  /**
   * Send a binary frame over the open mailbox WebSocket.
   *
   * @param {Uint8Array} frame
   */
  send(frame) {
    if (!(frame instanceof Uint8Array)) {
      throw new TypeError("Outbound mailbox frame must be a Uint8Array");
    }
    if (frame.byteLength > this.#maxFrameBytes) {
      throw new RangeError(
        `Outbound mailbox frame (${frame.byteLength} B) exceeds limit (${this.#maxFrameBytes} B)`,
      );
    }
    if (!this.#socket || this.#socket.readyState !== WS_OPEN) {
      throw new Error("Rendezvous mailbox WebSocket is not open");
    }
    this.#socket.send(frame);
  }

  /**
   * Resolve once all queued inbound frames have finished asynchronous processing.
   *
   * @returns {Promise<void>}
   */
  whenIdle() {
    return this.#processingChain;
  }

  /**
   * Cleanly close the mailbox WebSocket and cancel any pending backoff retry.
   *
   * @param {number} [code]
   * @param {string} [reason]
   */
  close(code = 1000, reason = "done") {
    this.#closedByCaller = true;
    this.#clearReconnectTimer();
    if (
      this.#socket &&
      (this.#socket.readyState === WS_CONNECTING || this.#socket.readyState === WS_OPEN)
    ) {
      this.#socket.close(code, reason);
    }
  }

  #clearReconnectTimer() {
    if (this.#reconnectTimer !== null) {
      this.#cancelTimer(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
  }

  #failProtocol(socket, closeCode, closeReason, err) {
    if (this.#protocolFailed) return;
    this.#protocolFailed = true;
    this.#clearReconnectTimer();
    const errorObj = err instanceof Error ? err : new Error(String(err));
    if (socket.readyState === WS_CONNECTING || socket.readyState === WS_OPEN) {
      socket.close(closeCode, closeReason);
    }
    this.#onError(errorObj);
  }
}

/**
 * Relay streaming WebSocket transport (`/v0/relay/<pairName>`), demultiplexing
 * `0x01` control messages and `0x02` encrypted entry chunk frames in strict FIFO
 * arrival order.
 */
export class RelayStreamTransport {
  #origin;
  #pairName;
  #WebSocketImpl;
  #maxFrameBytes;
  #onOpen;
  #onFrame;
  #onControlFrame;
  #onChunkFrame;
  #onClose;
  #onError;

  #socket = null;
  #closedByCaller = false;
  #protocolFailed = false;
  #processingChain = Promise.resolve();

  /**
   * @param {{
   *   relayOrigin?: string,
   *   pairName: string,
   *   WebSocketImpl?: typeof WebSocket,
   *   maxFrameBytes?: number,
   *   onOpen?: () => void,
   *   onFrame?: (decoded: ReturnType<typeof decodeRelayFrame>) => void | Promise<void>,
   *   onControlFrame?: (payload: Uint8Array) => void | Promise<void>,
   *   onChunkFrame?: (chunk: { entryIndex: number, chunkIndex: number, ciphertext: Uint8Array }) => void | Promise<void>,
   *   onClose?: (info: { code: number, reason: string }) => void,
   *   onError?: (err: Error) => void,
   * }} config
   */
  constructor({
    relayOrigin = "wss://relay.totaldrop.app",
    pairName,
    WebSocketImpl = globalThis.WebSocket,
    maxFrameBytes = MAX_RELAY_FRAME_BYTES,
    onOpen = () => {},
    onFrame = () => {},
    onControlFrame = () => {},
    onChunkFrame = () => {},
    onClose = () => {},
    onError = () => {},
  }) {
    this.#origin = validateWebSocketOrigin(relayOrigin);
    this.#pairName = validateRelayPairName(pairName);
    if (typeof WebSocketImpl !== "function") {
      throw new TypeError("WebSocket implementation is unavailable");
    }
    if (!Number.isInteger(maxFrameBytes) || maxFrameBytes < 16 || maxFrameBytes > MAX_RELAY_FRAME_BYTES) {
      throw new RangeError(`maxFrameBytes must be between 16 and ${MAX_RELAY_FRAME_BYTES}`);
    }
    this.#WebSocketImpl = WebSocketImpl;
    this.#maxFrameBytes = maxFrameBytes;
    this.#onOpen = onOpen;
    this.#onFrame = onFrame;
    this.#onControlFrame = onControlFrame;
    this.#onChunkFrame = onChunkFrame;
    this.#onClose = onClose;
    this.#onError = onError;
  }

  /** @returns {string} */
  get url() {
    return `${this.#origin}/v0/relay/${this.#pairName}`;
  }

  /** @returns {string} */
  get pairName() {
    return this.#pairName;
  }

  /** @returns {WebSocket | null} */
  get socket() {
    return this.#socket;
  }

  /**
   * Open the relay WebSocket stream.
   *
   * @returns {WebSocket}
   */
  connect() {
    if (this.#closedByCaller) {
      throw new Error("RelayStreamTransport has already been closed");
    }
    const socket = new this.#WebSocketImpl(this.url);
    socket.binaryType = "arraybuffer";
    this.#socket = socket;

    attachSocketListeners(socket, {
      open: () => {
        if (this.#socket !== socket || this.#closedByCaller) return;
        this.#onOpen();
      },
      message: (event) => {
        if (this.#socket !== socket || this.#closedByCaller || this.#protocolFailed) return;
        let bytes;
        try {
          bytes = coerceBinaryFrame(event?.data);
        } catch (err) {
          this.#failProtocol(socket, 1003, "binary frames required", err);
          return;
        }
        if (bytes.byteLength > this.#maxFrameBytes) {
          this.#failProtocol(
            socket,
            1009,
            "relay frame too large",
            new RangeError(
              `Inbound relay frame (${bytes.byteLength} B) exceeds limit (${this.#maxFrameBytes} B)`,
            ),
          );
          return;
        }
        const ownedBytes = bytes.slice();
        this.#processingChain = this.#processingChain.then(async () => {
          if (this.#closedByCaller || this.#protocolFailed) return;
          try {
            const decoded = decodeRelayFrame(ownedBytes);
            await this.#onFrame(decoded);
            if (decoded.kind === "control") {
              await this.#onControlFrame(decoded.payload);
            } else {
              await this.#onChunkFrame({
                entryIndex: decoded.entryIndex,
                chunkIndex: decoded.chunkIndex,
                ciphertext: decoded.ciphertext,
              });
            }
          } catch (err) {
            this.#failProtocol(socket, 1008, "relay frame rejected", err);
          }
        });
      },
      close: (event) => {
        if (this.#socket !== socket) return;
        const code = typeof event?.code === "number" ? event.code : 1006;
        const reason = typeof event?.reason === "string" ? event.reason : "";
        this.#onClose({ code, reason });
      },
      error: (event) => {
        if (this.#socket !== socket || this.#closedByCaller) return;
        const err =
          event instanceof Error ? event : new Error("Relay WebSocket transport error");
        this.#onError(err);
      },
    });

    return socket;
  }

  /**
   * Send an encrypted session control frame (`0x01 || payload`).
   *
   * @param {Uint8Array} payload
   */
  sendControl(payload) {
    const encoded = encodeControlFrame(payload);
    this.#sendEncoded(encoded);
  }

  /**
   * Send an encrypted entry chunk frame (`0x02 || u32be || u64be || ciphertext`).
   *
   * @param {number} entryIndex
   * @param {number | bigint} chunkIndex
   * @param {Uint8Array} ciphertext
   */
  sendChunk(entryIndex, chunkIndex, ciphertext) {
    const encoded = encodeChunkFrame(entryIndex, chunkIndex, ciphertext);
    this.#sendEncoded(encoded);
  }

  /**
   * Resolve once all queued inbound frames have finished processing.
   *
   * @returns {Promise<void>}
   */
  whenIdle() {
    return this.#processingChain;
  }

  /**
   * Cleanly close the relay WebSocket stream.
   *
   * @param {number} [code]
   * @param {string} [reason]
   */
  close(code = 1000, reason = "done") {
    this.#closedByCaller = true;
    if (
      this.#socket &&
      (this.#socket.readyState === WS_CONNECTING || this.#socket.readyState === WS_OPEN)
    ) {
      this.#socket.close(code, reason);
    }
  }

  #sendEncoded(encoded) {
    if (encoded.byteLength > this.#maxFrameBytes) {
      throw new RangeError(
        `Outbound relay frame (${encoded.byteLength} B) exceeds limit (${this.#maxFrameBytes} B)`,
      );
    }
    if (!this.#socket || this.#socket.readyState !== WS_OPEN) {
      throw new Error("Relay WebSocket is not open");
    }
    this.#socket.send(encoded);
  }

  #failProtocol(socket, closeCode, closeReason, err) {
    if (this.#protocolFailed) return;
    this.#protocolFailed = true;
    const errorObj = err instanceof Error ? err : new Error(String(err));
    if (socket.readyState === WS_CONNECTING || socket.readyState === WS_OPEN) {
      socket.close(closeCode, closeReason);
    }
    this.#onError(errorObj);
  }
}
