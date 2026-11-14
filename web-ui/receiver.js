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
// 3. Connects to `wss://rendezvous.totaldrop.app/v0/mailbox/<nameplate>` and
//    drives chunk verification into `fs-writer.js` (`showSaveFilePicker`).

import {
  openDirectorySaveRoot,
  openSingleFileSavePicker,
  supportsFileSystemAccess,
} from "./fs-writer.js";

/**
 * Minimal 21-byte valid WebAssembly module containing a `v128.const` (`0xfd 0x0c`)
 * instruction, used to detect fixed-width 128-bit SIMD support synchronously.
 */
const WASM_SIMD128_PROBE = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7b, 0x03,
  0x02, 0x01, 0x00, 0x0a, 0x0a, 0x01, 0x08, 0x00,
  0xfd, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
 * }} artifacts
 * @returns {Promise<{ variant: "simd128" | "baseline", instance: WebAssembly.Instance }>}
 */
export async function loadVerifiedWasmReceiver(artifacts) {
  const variant = supportsWasmSimd128() ? "simd128" : "baseline";
  const selected = artifacts[variant];
  if (!selected?.url || !selected?.integrity?.startsWith("sha384-")) {
    throw new Error(`Missing URL or SHA-384 SRI integrity for ${variant} WASM artifact`);
  }

  const response = await fetch(selected.url, {
    credentials: "omit",
    cache: "force-cache",
    integrity: selected.integrity,
    mode: "same-origin",
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch ${variant} WASM (${response.status})`);
  }

  const imports = artifacts.imports ?? {};
  if (typeof WebAssembly.instantiateStreaming === "function") {
    const { instance } = await WebAssembly.instantiateStreaming(response, imports);
    return { variant, instance };
  }
  const bytes = await response.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  return { variant, instance };
}

/**
 * Zero-framework browser receiver coordinator binding DOM/UI callbacks, WASM
 * protocol verification (`totaldrop-wasm`), WebSocket transport, and streaming
 * File System Access API disk writes (`fs-writer.js`).
 */
export class TotalDropWebReceiver {
  #wasmBridge;
  #endpoints;
  #onStatus;
  #socket = null;
  #activeSinks = new Map();
  #aborted = false;

  /**
   * @param {{
   *   wasmBridge: {
   *     parseShareInput: (input: string) => { nameplate: number, displayEnglish: string },
   *     negotiateLocale: (langs: readonly string[]) => { tag: string, dir: "ltr" | "rtl" },
   *     verifyEntryChunk: (entryIndex: number, chunkIndex: number, ciphertext: Uint8Array) => {
   *       plaintext: Uint8Array,
   *       entryComplete: boolean,
   *       encryptedEntryDone: Uint8Array | null,
   *       transferComplete: boolean,
   *     },
   *   },
   *   endpoints?: { rendezvousOrigin?: string, relayOrigin?: string },
   *   onStatus?: (event: { phase: string, detail?: unknown }) => void,
   * }} config
   */
  constructor({ wasmBridge, endpoints = {}, onStatus = () => {} }) {
    this.#wasmBridge = wasmBridge;
    this.#endpoints = { ...DEFAULT_ENDPOINTS, ...endpoints };
    this.#onStatus = onStatus;
  }

  /**
   * Apply negotiated locale directionality (`ltr` / `rtl`) and `lang` attribute
   * to the document root across all 35 supported TotalDrop languages.
   *
   * @param {Document} [doc]
   * @param {Navigator} [nav]
   * @returns {{ tag: string, dir: "ltr" | "rtl" }}
   */
  applyDocumentLocale(doc = globalThis.document, nav = globalThis.navigator) {
    const langs = nav?.languages?.length ? nav.languages : [nav?.language ?? "en"];
    const negotiated = this.#wasmBridge.negotiateLocale(langs);
    if (doc?.documentElement) {
      doc.documentElement.lang = negotiated.tag;
      doc.documentElement.dir = negotiated.dir;
    }
    return negotiated;
  }

  /**
   * Open the rendezvous mailbox WebSocket for a parsed wormhole code.
   * Note: Requires the `Origin === "https://totaldrop.app"` allowlist rule
   * documented in `ORIGIN-ALLOWLIST.md` (#450) to be active on the Worker.
   *
   * @param {string} shareInputOrCode
   * @returns {{ nameplate: number, socket: WebSocket }}
   */
  connectMailbox(shareInputOrCode) {
    if (!supportsFileSystemAccess()) {
      throw new Error(
        "This browser does not support streaming saves (File System Access API).",
      );
    }
    const parsed = this.#wasmBridge.parseShareInput(shareInputOrCode);
    if (!Number.isInteger(parsed.nameplate) || parsed.nameplate <= 0) {
      throw new Error("Invalid rendezvous nameplate");
    }
    const url = `${this.#endpoints.rendezvousOrigin}/v0/mailbox/${parsed.nameplate}`;
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";
    this.#socket = socket;
    this.#onStatus({ phase: "connecting", detail: { nameplate: parsed.nameplate } });
    return { nameplate: parsed.nameplate, socket };
  }

  /**
   * Prepare streaming file sinks after the user clicks "Accept" on a validated
   * offer (`Control::Offer`). Uses `showSaveFilePicker` for single-file offers
   * and `showDirectoryPicker` for multi-file or folder offers.
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
    const entries = validatedOffer.entries;
    if (entries.length === 1 && entries[0].kind === "file" && entries[0].pathSegments.length === 1) {
      const only = entries[0];
      const sink = await openSingleFileSavePicker({
        pathSegments: only.pathSegments,
        expectedBytes: only.size,
      });
      this.#activeSinks.set(only.index, sink);
      return;
    }

    const dirRoot = await openDirectorySaveRoot();
    for (const entry of entries) {
      if (entry.kind === "dir") {
        await dirRoot.ensureDirectory(entry.pathSegments);
      } else {
        const sink = await dirRoot.openFile(entry.pathSegments, entry.size);
        this.#activeSinks.set(entry.index, sink);
      }
    }
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

      if (result.entryComplete) {
        await sink.commit(true);
        this.#activeSinks.delete(entryIndex);
        if (result.encryptedEntryDone) {
          sendControlFrame(result.encryptedEntryDone);
        }
      }
      if (result.transferComplete) {
        this.#onStatus({ phase: "done" });
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
   * Abort all uncommitted file streams and close the active WebSocket.
   *
   * @param {unknown} [reason]
   * @returns {Promise<void>}
   */
  async abortAll(reason) {
    this.#aborted = true;
    const sinks = Array.from(this.#activeSinks.values());
    this.#activeSinks.clear();
    await Promise.allSettled(sinks.map((s) => s.abort(reason)));
    if (this.#socket && this.#socket.readyState <= WebSocket.OPEN) {
      this.#socket.close(1000, "aborted");
    }
    this.#onStatus({ phase: "aborted", detail: reason });
  }
}
