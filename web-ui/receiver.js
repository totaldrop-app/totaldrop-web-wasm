// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Zero-framework browser Web Receiver controller (`https://totaldrop.app/r#…`).
//
// Responsibilities:
// 1. Reads the wormhole transfer code from `window.location.hash` (the `#`
//    fragment never leaves the browser in HTTP requests) and scrubs the URL bar
//    via `history.replaceState` to prevent shoulder-surfing or Referer leaks.
// 2. Probes WebAssembly fixed-width 128-bit SIMD (`simd128`) support and fetches
//    the matching WASM binary (`target-wasm32-simd128` vs `target-wasm32-baseline`)
//    pinned with a SHA-384 Subresource Integrity (`integrity`) digest.
// 3. Connects to `RendezvousMailboxClient` (`/v0/mailbox/<nameplate>`) and
//    `RelayStreamTransport` (`/v0/relay/<pairName>`), driving verified chunk
//    writes into `fs-writer.js` (`showSaveFilePicker` / `showDirectoryPicker`).

import {
  openDirectorySaveRoot,
  openSingleFileSavePicker,
  supportsFileSystemAccess,
} from "./fs-writer.js";
import {
  RelayStreamTransport,
  RendezvousMailboxClient,
} from "./transport.js";

const WS_OPEN_OR_CONNECTING_MAX = 1;

/**
 * Minimal 43-byte valid WebAssembly module containing a `v128.const` (`0xfd 0x0c`)
 * instruction, used to detect fixed-width 128-bit SIMD support synchronously.
 */
const WASM_SIMD128_PROBE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b,
  0x03, 0x02, 0x01, 0x00,
  0x0a, 0x16, 0x01, 0x14, 0x00,
  0xfd, 0x0c,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0b,
]);

/** Default production endpoints. */
export const DEFAULT_ENDPOINTS = Object.freeze({
  rendezvousOrigin: "wss://rendezvous.totaldrop.app",
  relayOrigin: "wss://relay.totaldrop.app",
});

/**
 * Detect whether the current JS/Wasm engine executes W3C fixed-width `simd128`.
 *
 * @returns {boolean}
 */
export function supportsWasmSimd128() {
  try {
    return typeof WebAssembly === "object" && WebAssembly.validate(WASM_SIMD128_PROBE);
  } catch {
    return false;
  }
}

/**
 * Read and optionally clear the receive fragment from `window.location` without
 * triggering a page reload.
 *
 * @param {Window & typeof globalThis} [win]
 * @param {{ scrubLocationBar?: boolean }} [options]
 * @returns {string | null}
 */
export function consumeLocationFragment(
  win = globalThis,
  { scrubLocationBar = true } = {},
) {
  const hash = win?.location?.hash ?? "";
  if (!hash || hash === "#" || hash.length > 1024) {
    return null;
  }
  if (scrubLocationBar && win.history && typeof win.history.replaceState === "function") {
    const cleanUrl = `${win.location.pathname}${win.location.search}`;
    win.history.replaceState(null, "", cleanUrl);
  }
  return hash;
}

/**
 * Fetch and instantiate the appropriate `totaldrop-wasm` artifact (`simd128` or
 * `baseline`) with mandatory SHA-384 Subresource Integrity verification.
 *
 * @param {{
 *   simd128: { url: string, integrity: string },
 *   baseline: { url: string, integrity: string },
 *   imports?: WebAssembly.Imports,
 *   fetchImpl?: typeof fetch,
 * }} artifacts
 * @returns {Promise<{ variant: "simd128" | "baseline", instance: WebAssembly.Instance }>}
 */
export async function loadVerifiedWasmReceiver(artifacts) {
  const variant = supportsWasmSimd128() ? "simd128" : "baseline";
  const selected = artifacts?.[variant];
  if (!selected?.url || !selected?.integrity?.startsWith("sha384-")) {
    throw new Error(`Missing URL or SHA-384 SRI integrity for ${variant} WASM artifact`);
  }

  const fetchFn = artifacts.fetchImpl ?? fetch;
  const response = await fetchFn(selected.url, {
    credentials: "omit",
    cache: "force-cache",
    integrity: selected.integrity,
    mode: "same-origin",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch ${variant} WASM (${response.status})`);
  }

  const imports = artifacts.imports ?? {};
  if (typeof WebAssembly.instantiateStreaming === "function" && !artifacts.fetchImpl) {
    const { instance } = await WebAssembly.instantiateStreaming(response, imports);
    return { variant, instance };
  }
  const bytes = await response.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  return { variant, instance };
}

/**
 * Zero-framework browser receiver coordinator binding DOM/UI callbacks, WASM
 * protocol verification (`totaldrop-wasm`), WebSocket transport (`transport.js`),
 * and streaming File System Access API disk writes (`fs-writer.js`).
 */
export class TotalDropWebReceiver {
  #wasmBridge;
  #endpoints;
  #onStatus;
  #onApproveOffer;
  #win;
  #socket = null;
  #mailboxClient = null;
  #relayTransport = null;
  #activeSinks = new Map();
  #totalExpectedBytes = 0;
  #receivedBytes = 0;
  #offerAccepted = false;
  #aborted = false;

  /**
   * @param {{
   *   wasmBridge: {
   *     parseShareInput: (input: string) => { nameplate: number, displayEnglish: string },
   *     negotiateLocale: (langs: readonly string[]) => { tag: string, dir: "ltr" | "rtl" },
   *     acceptEncryptedOffer?: (payload: Uint8Array) => {
   *       offer: {
   *         entries: ReadonlyArray<{
   *           index: number,
   *           kind: "file" | "dir",
   *           pathSegments: readonly string[],
   *           size: number,
   *         }>,
   *       },
   *       encryptedAccept: Uint8Array | null,
   *     },
   *     rejectOffer?: () => Uint8Array | null,
   *     verifyEntryChunk: (entryIndex: number, chunkIndex: number, ciphertext: Uint8Array) => {
   *       plaintext: Uint8Array,
   *       entryComplete: boolean,
   *       encryptedEntryDone: Uint8Array | null,
   *       transferComplete: boolean,
   *     },
   *   },
   *   endpoints?: { rendezvousOrigin?: string, relayOrigin?: string },
   *   onStatus?: (event: { phase: string, detail?: unknown }) => void,
   *   onApproveOffer?: (offer: unknown) => boolean | Promise<boolean>,
   *   win?: Window & typeof globalThis,
   * }} config
   */
  constructor({
    wasmBridge,
    endpoints = {},
    onStatus = () => {},
    onApproveOffer = async () => true,
    win = globalThis,
  }) {
    this.#wasmBridge = wasmBridge;
    this.#endpoints = { ...DEFAULT_ENDPOINTS, ...endpoints };
    this.#onStatus = onStatus;
    this.#onApproveOffer = onApproveOffer;
    this.#win = win;
  }

  /** @returns {boolean} */
  get aborted() {
    return this.#aborted;
  }

  /** @returns {number} */
  get activeSinkCount() {
    return this.#activeSinks.size;
  }

  /** @returns {RendezvousMailboxClient | null} */
  get mailboxClient() {
    return this.#mailboxClient;
  }

  /** @returns {RelayStreamTransport | null} */
  get relayTransport() {
    return this.#relayTransport;
  }

  /**
   * Apply negotiated locale directionality (`ltr` / `rtl`) and `lang` attribute
   * to the document root across all 35 supported TotalDrop languages.
   *
   * @param {Document} [doc]
   * @param {Navigator} [nav]
   * @returns {{ tag: string, dir: "ltr" | "rtl" }}
   */
  applyDocumentLocale(
    doc = this.#win?.document,
    nav = this.#win?.navigator,
  ) {
    const langs = nav?.languages?.length ? nav.languages : [nav?.language ?? "en"];
    const negotiated = this.#wasmBridge.negotiateLocale(langs);
    if (doc?.documentElement) {
      doc.documentElement.lang = negotiated.tag;
      doc.documentElement.dir = negotiated.dir;
    }
    return negotiated;
  }

  /**
   * Open the rendezvous mailbox WebSocket for a parsed wormhole code via
   * {@link RendezvousMailboxClient}.
   * Note: Requires the `Origin === "https://totaldrop.app"` allowlist rule
   * documented in `ORIGIN-ALLOWLIST.md` (#450) to be active on the Worker.
   *
   * @param {string} shareInputOrCode
   * @param {{
   *   WebSocketImpl?: typeof WebSocket,
   *   maxReconnectAttempts?: number,
   *   onOpen?: () => void,
   *   onFrame?: (frame: Uint8Array) => void | Promise<void>,
   *   onClose?: (info: { code: number, reason: string, willReconnect: boolean }) => void,
   *   onError?: (err: Error) => void,
   * }} [options]
   * @returns {{ nameplate: number, socket: WebSocket, mailboxClient: RendezvousMailboxClient }}
   */
  connectMailbox(shareInputOrCode, options = {}) {
    if (!supportsFileSystemAccess(this.#win)) {
      throw new Error(
        "This browser does not support streaming saves (File System Access API).",
      );
    }
    const parsed = this.#wasmBridge.parseShareInput(shareInputOrCode);
    if (!Number.isInteger(parsed.nameplate) || parsed.nameplate <= 0) {
      throw new Error("Invalid rendezvous nameplate");
    }

    const WebSocketImpl =
      options.WebSocketImpl ?? this.#win?.WebSocket ?? globalThis.WebSocket;
    const mailboxClient = new RendezvousMailboxClient({
      rendezvousOrigin: this.#endpoints.rendezvousOrigin,
      nameplate: parsed.nameplate,
      WebSocketImpl,
      maxReconnectAttempts: options.maxReconnectAttempts ?? 3,
      onOpen: () => {
        options.onOpen?.();
      },
      onFrame: async (frame) => {
        await options.onFrame?.(frame);
      },
      onClose: (info) => {
        options.onClose?.(info);
      },
      onError: (err) => {
        options.onError?.(err);
        void this.abortAll(err);
      },
    });

    const socket = mailboxClient.connect();
    this.#mailboxClient = mailboxClient;
    this.#socket = socket;
    this.#onStatus({ phase: "connecting", detail: { nameplate: parsed.nameplate } });
    return { nameplate: parsed.nameplate, socket, mailboxClient };
  }

  /**
   * Prepare streaming file sinks after the user clicks "Accept & Save" on a
   * validated offer (`Control::Offer`). Uses `showSaveFilePicker` for single-file
   * offers and `showDirectoryPicker` for multi-file or folder offers.
   *
   * @param {{
   *   entries: ReadonlyArray<{
   *     index: number,
   *     kind: "file" | "dir",
   *     pathSegments: readonly string[],
   *     size: number,
   *   }>,
   * }} validatedOffer
   * @returns {Promise<void>}
   */
  async prepareOfferSinks(validatedOffer) {
    if (this.#aborted) {
      throw new Error("Transfer already aborted");
    }
    const entries = validatedOffer.entries;
    this.#totalExpectedBytes = entries
      .filter((entry) => entry.kind === "file")
      .reduce((sum, entry) => sum + entry.size, 0);
    this.#receivedBytes = 0;

    if (
      entries.length === 1 &&
      entries[0].kind === "file" &&
      entries[0].pathSegments.length === 1
    ) {
      const only = entries[0];
      const sink = await openSingleFileSavePicker(
        {
          pathSegments: only.pathSegments,
          expectedBytes: only.size,
        },
        this.#win,
      );
      this.#activeSinks.set(only.index, sink);
      this.#offerAccepted = true;
      return;
    }

    const dirRoot = await openDirectorySaveRoot(this.#win);
    for (const entry of entries) {
      if (entry.kind === "dir") {
        await dirRoot.ensureDirectory(entry.pathSegments);
      } else {
        const sink = await dirRoot.openFile(entry.pathSegments, entry.size);
        this.#activeSinks.set(entry.index, sink);
      }
    }
    this.#offerAccepted = true;
  }

  /**
   * Connect a {@link RelayStreamTransport} for `pairName` and bind incoming
   * `0x01` encrypted control frames (such as `Control::Offer`) and `0x02`
   * encrypted entry chunks directly to WASM verification, `VerifiedFileSink`
   * commits, `encryptedEntryDone` replies, and clean completion.
   *
   * @param {string} pairName
   * @param {typeof WebSocket} [WebSocketImpl]
   * @returns {RelayStreamTransport}
   */
  attachRelayTransport(
    pairName,
    WebSocketImpl = this.#win?.WebSocket ?? globalThis.WebSocket,
  ) {
    if (this.#aborted) {
      throw new Error("Cannot attach relay transport after abort");
    }
    if (!supportsFileSystemAccess(this.#win)) {
      throw new Error(
        "This browser does not support streaming saves (File System Access API).",
      );
    }

    const relay = new RelayStreamTransport({
      relayOrigin: this.#endpoints.relayOrigin,
      pairName,
      WebSocketImpl,
      onOpen: () => {
        this.#mailboxClient?.lockSession();
        this.#onStatus({ phase: "relay-connected", detail: { pairName } });
      },
      onControlFrame: async (payload) => {
        if (
          !this.#offerAccepted &&
          typeof this.#wasmBridge.acceptEncryptedOffer === "function"
        ) {
          const { offer, encryptedAccept } =
            this.#wasmBridge.acceptEncryptedOffer(payload);
          this.#onStatus({ phase: "offer", detail: offer });

          const approved = await this.#onApproveOffer(offer);
          if (!approved) {
            if (typeof this.#wasmBridge.rejectOffer === "function") {
              const rejectPayload = this.#wasmBridge.rejectOffer();
              if (rejectPayload) {
                relay.sendControl(rejectPayload);
              }
            }
            relay.close(1000, "declined");
            this.#onStatus({ phase: "declined" });
            return;
          }

          await this.prepareOfferSinks(offer);
          if (encryptedAccept) {
            relay.sendControl(encryptedAccept);
          }
          if (this.#activeSinks.size === 0) {
            this.#onStatus({
              phase: "done",
              detail: { receivedBytes: 0, totalBytes: 0 },
            });
            relay.close(1000, "done");
          }
        }
      },
      onChunkFrame: async ({ entryIndex, chunkIndex, ciphertext }) => {
        await this.handleEncryptedChunk(
          entryIndex,
          chunkIndex,
          ciphertext,
          (controlCiphertext) => relay.sendControl(controlCiphertext),
        );
      },
      onError: (err) => {
        void this.abortAll(err);
      },
    });

    const socket = relay.connect();
    this.#relayTransport = relay;
    this.#socket = socket;
    return relay;
  }

  /**
   * Process one encrypted file chunk, writing authenticated plaintext straight
   * to disk and committing the file handle only once WASM confirms the full
   * file's BLAKE3 digest.
   *
   * @param {number} entryIndex
   * @param {number} chunkIndex
   * @param {Uint8Array} ciphertext
   * @param {(controlCiphertext: Uint8Array) => void} sendControlFrame
   * @returns {Promise<{ entryComplete: boolean, transferComplete: boolean }>}
   */
  async handleEncryptedChunk(entryIndex, chunkIndex, ciphertext, sendControlFrame) {
    if (this.#aborted) {
      throw new Error("Transfer already aborted");
    }
    const sink = this.#activeSinks.get(entryIndex);
    if (!sink) {
      throw new Error(`No open file sink for entry ${entryIndex}`);
    }

    try {
      const result = this.#wasmBridge.verifyEntryChunk(entryIndex, chunkIndex, ciphertext);
      await sink.writeVerifiedChunk(result.plaintext);
      this.#receivedBytes += result.plaintext.byteLength;

      const percent =
        this.#totalExpectedBytes > 0
          ? Math.min(100, Math.floor((this.#receivedBytes * 100) / this.#totalExpectedBytes))
          : 100;
      this.#onStatus({
        phase: "receiving",
        detail: {
          entryIndex,
          chunkIndex,
          receivedBytes: this.#receivedBytes,
          totalBytes: this.#totalExpectedBytes,
          percent,
        },
      });

      if (result.entryComplete) {
        await sink.commit(true);
        this.#activeSinks.delete(entryIndex);
        if (result.encryptedEntryDone) {
          sendControlFrame(result.encryptedEntryDone);
        }
      }
      if (result.transferComplete) {
        this.#onStatus({
          phase: "done",
          detail: {
            receivedBytes: this.#receivedBytes,
            totalBytes: this.#totalExpectedBytes,
          },
        });
        this.#relayTransport?.close(1000, "done");
        this.#mailboxClient?.close(1000, "done");
      }
      return {
        entryComplete: result.entryComplete,
        transferComplete: result.transferComplete,
      };
    } catch (err) {
      await this.abortAll(err);
      throw err;
    }
  }

  /**
   * Abort all uncommitted file streams and close active WebSocket transports.
   *
   * @param {unknown} [reason]
   * @returns {Promise<void>}
   */
  async abortAll(reason) {
    const firstAbort = !this.#aborted;
    this.#aborted = true;
    const sinks = Array.from(this.#activeSinks.values());
    this.#activeSinks.clear();
    await Promise.allSettled(sinks.map((s) => s.abort(reason)));
    this.#relayTransport?.close(1000, "aborted");
    this.#mailboxClient?.close(1000, "aborted");
    if (this.#socket && this.#socket.readyState <= WS_OPEN_OR_CONNECTING_MAX) {
      this.#socket.close(1000, "aborted");
    }
    if (firstAbort) {
      this.#onStatus({ phase: "aborted", detail: reason });
    }
  }
}

/**
 * Progressive DOM bootstrap invoked automatically on `web-ui/index.html` when
 * `<html data-totaldrop-auto-init="true">` is present.
 *
 * @param {Window & typeof globalThis} [win]
 */
export function bootstrapBrowserUi(win = globalThis) {
  const doc = win?.document;
  if (!doc) return;

  const unsupportedNotice = doc.getElementById("unsupported-browser-notice");
  const codeInput = doc.getElementById("transfer-code-input");
  const connectButton = doc.getElementById("connect-button");
  const statusLine = doc.getElementById("connection-status");

  const fragment = consumeLocationFragment(win, { scrubLocationBar: true });
  if (fragment && codeInput && "value" in codeInput) {
    codeInput.value = decodeURIComponent(fragment.slice(1));
  }

  if (!supportsFileSystemAccess(win)) {
    if (unsupportedNotice) {
      unsupportedNotice.hidden = false;
    }
    if (connectButton && "disabled" in connectButton) {
      connectButton.disabled = true;
    }
    if (codeInput && "disabled" in codeInput) {
      codeInput.disabled = true;
    }
    if (statusLine) {
      statusLine.textContent =
        "Streaming saves require a browser with the File System Access API.";
      statusLine.hidden = false;
    }
  }
}

if (globalThis.document?.documentElement?.dataset?.totaldropAutoInit === "true") {
  bootstrapBrowserUi(globalThis);
}
