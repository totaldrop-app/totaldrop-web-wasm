// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Zero-framework browser disk writer built on the File System Access API
// (`window.showSaveFilePicker` / `window.showDirectoryPicker`).
//
// Security invariants:
// 1. Plaintext chunks decrypted by `totaldrop-wasm` are streamed sequentially
//    into `FileSystemWritableFileStream` (1 MiB at a time) so multi-gigabyte
//    files never buffer in browser heap memory.
// 2. Chromium writes to an isolated `.crswap` temporary file until `close()`
//    is awaited. `commit()` is called ONLY after `totaldrop-wasm` confirms both
//    every chunk's Poly1305/XChaCha20-Poly1305 tag AND the whole-file BLAKE3
//    digest from the signed manifest.
// 3. Any AEAD failure, disconnect, cancellation, or BLAKE3 mismatch invokes
//    `abort()`, which discards the temporary swap file so unverified bytes
//    never appear at the destination path.

const FORBIDDEN_SEGMENT_CHARS = /[\/\\\0:<>\"|?*]/;
const BIDI_CONTROL_CHARS = /[\u202A-\u202E\u2066-\u2069]/;
const WINDOWS_RESERVED = new Set([
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
]);

/**
 * Check whether the current browser context supports the File System Access API
 * (`SecureContext` + `showSaveFilePicker`).
 *
 * @param {Window & typeof globalThis} [win]
 * @returns {boolean}
 */
export function supportsFileSystemAccess(win = globalThis) {
  return Boolean(
    win &&
      win.isSecureContext &&
      typeof win.showSaveFilePicker === "function",
  );
}

/**
 * Defense-in-depth JavaScript check mirroring `totaldrop_proto::validate_path`
 * before handing any segment to `showSaveFilePicker` or `getDirectoryHandle`.
 *
 * @param {readonly string[]} segments
 * @returns {string[]} NFC-normalized safe path segments
 */
export function assertSafeBrowserPath(segments) {
  if (!Array.isArray(segments) || segments.length === 0 || segments.length > 64) {
    throw new Error("Unsafe manifest path depth");
  }
  const normalized = [];
  let totalUtf8 = 0;
  const encoder = new TextEncoder();

  for (let i = 0; i < segments.length; i += 1) {
    const raw = segments[i];
    if (typeof raw !== "string") {
      throw new Error(`Path segment ${i} is not a string`);
    }
    const seg = raw.normalize("NFC");
    if (seg.length === 0 || seg === "." || seg === "..") {
      throw new Error(`Dot or empty segment at index ${i}`);
    }
    if (FORBIDDEN_SEGMENT_CHARS.test(seg) || BIDI_CONTROL_CHARS.test(seg)) {
      throw new Error(`Forbidden or bidirectional control character at index ${i}`);
    }
    for (let c = 0; c < seg.length; c += 1) {
      const code = seg.charCodeAt(c);
      if (code <= 0x1f || (code >= 0x7f && code <= 0x9f)) {
        throw new Error(`Control character in path segment ${i}`);
      }
    }
    if (seg.endsWith(".") || seg.endsWith(" ")) {
      throw new Error(`Trailing dot or space in path segment ${i}`);
    }
    const stem = seg.split(".")[0].trimEnd().toUpperCase();
    if (WINDOWS_RESERVED.has(stem)) {
      throw new Error(`Reserved device name in path segment ${i}`);
    }
    const segBytes = encoder.encode(seg).byteLength;
    if (segBytes > 255) {
      throw new Error(`Path segment ${i} exceeds 255 UTF-8 bytes`);
    }
    totalUtf8 += segBytes + (i > 0 ? 1 : 0);
    if (totalUtf8 > 4096) {
      throw new Error("Full path exceeds 4096 UTF-8 bytes");
    }
    normalized.push(seg);
  }
  return normalized;
}

/**
 * Streaming, atomically-committed writer for a single verified file handle.
 */
export class VerifiedFileSink {
  #writable;
  #expectedBytes;
  #bytesWritten = 0;
  #closed = false;

  /**
   * @param {FileSystemWritableFileStream} writable
   * @param {number} expectedBytes
   */
  constructor(writable, expectedBytes) {
    this.#writable = writable;
    this.#expectedBytes = expectedBytes;
  }

  /** @returns {number} */
  get bytesWritten() {
    return this.#bytesWritten;
  }

  /**
   * Write one authenticated plaintext chunk returned by `totaldrop-wasm`.
   *
   * @param {Uint8Array} plaintextChunk
   * @returns {Promise<void>}
   */
  async writeVerifiedChunk(plaintextChunk) {
    if (this.#closed) {
      throw new Error("Cannot write to a closed VerifiedFileSink");
    }
    if (!(plaintextChunk instanceof Uint8Array)) {
      throw new TypeError("plaintextChunk must be a Uint8Array");
    }
    const nextTotal = this.#bytesWritten + plaintextChunk.byteLength;
    if (nextTotal > this.#expectedBytes) {
      await this.abort("Received more plaintext bytes than signed manifest declared");
      throw new Error("Plaintext stream exceeded declared manifest size");
    }
    try {
      await this.#writable.write(plaintextChunk);
      this.#bytesWritten = nextTotal;
    } catch (err) {
      await this.abort(err);
      throw err;
    }
  }

  /**
   * Atomically swap the temporary `.crswap` file into place ONLY after WASM
   * confirms `entry_complete === true` (whole-file BLAKE3 verified).
   *
   * @param {boolean} wasmEntryVerified
   * @returns {Promise<void>}
   */
  async commit(wasmEntryVerified) {
    if (this.#closed) {
      throw new Error("VerifiedFileSink is already closed");
    }
    if (!wasmEntryVerified || this.#bytesWritten !== this.#expectedBytes) {
      await this.abort("Refusing to commit unverified or incomplete file");
      throw new Error("Refusing to commit unverified or incomplete file");
    }
    this.#closed = true;
    await this.#writable.close();
  }

  /**
   * Discard the uncommitted swap stream so tampered or truncated bytes never
   * reach the user's chosen path.
   *
   * @param {unknown} [reason]
   * @returns {Promise<void>}
   */
  async abort(reason) {
    if (this.#closed) return;
    this.#closed = true;
    try {
      await this.#writable.abort(reason);
    } catch {
      // Underlying stream already aborted by browser.
    }
  }
}

/**
 * Prompt the user with `window.showSaveFilePicker` (must be called from a user
 * activation gesture such as clicking "Accept") and open a streaming
 * {@link VerifiedFileSink}.
 *
 * @param {{ pathSegments: readonly string[], expectedBytes: number }} options
 * @param {Window & typeof globalThis} [win]
 * @returns {Promise<VerifiedFileSink>}
 */
export async function openSingleFileSavePicker(
  { pathSegments, expectedBytes },
  win = globalThis,
) {
  if (!supportsFileSystemAccess(win)) {
    throw new Error("File System Access API (showSaveFilePicker) is unavailable");
  }
  const safeSegments = assertSafeBrowserPath(pathSegments);
  const suggestedName = safeSegments[safeSegments.length - 1];

  const handle = await win.showSaveFilePicker({
    suggestedName,
    id: "totaldrop-receive",
    startIn: "downloads",
  });
  const writable = await handle.createWritable({ keepExistingData: false });
  return new VerifiedFileSink(writable, expectedBytes);
}

/**
 * Prompt the user with `window.showDirectoryPicker` for a multi-file manifest
 * and return a factory that creates nested directories and opens
 * {@link VerifiedFileSink}s strictly beneath the chosen root folder.
 *
 * @param {Window & typeof globalThis} [win]
 * @returns {Promise<{
 *   ensureDirectory: (segments: readonly string[]) => Promise<void>,
 *   openFile: (segments: readonly string[], expectedBytes: number) => Promise<VerifiedFileSink>,
 * }>}
 */
export async function openDirectorySaveRoot(win = globalThis) {
  if (!win?.isSecureContext || typeof win.showDirectoryPicker !== "function") {
    throw new Error("File System Access API (showDirectoryPicker) is unavailable");
  }
  const rootHandle = await win.showDirectoryPicker({
    id: "totaldrop-receive-dir",
    mode: "readwrite",
    startIn: "downloads",
  });

  async function walkDirectories(dirSegments) {
    let current = rootHandle;
    for (const seg of dirSegments) {
      current = await current.getDirectoryHandle(seg, { create: true });
    }
    return current;
  }

  return {
    async ensureDirectory(segments) {
      const safe = assertSafeBrowserPath(segments);
      await walkDirectories(safe);
    },
    async openFile(segments, expectedBytes) {
      const safe = assertSafeBrowserPath(segments);
      const parent = await walkDirectories(safe.slice(0, -1));
      const fileName = safe[safe.length - 1];
      const fileHandle = await parent.getFileHandle(fileName, { create: true });
      const writable = await fileHandle.createWritable({ keepExistingData: false });
      return new VerifiedFileSink(writable, expectedBytes);
    },
  };
}
