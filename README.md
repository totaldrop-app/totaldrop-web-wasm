# TotalDrop WebAssembly Workspace (`totaldrop-web-wasm` — Reserved / Shelved)

> [!IMPORTANT]
> **Status: Reserved / Shelved (`Not planned`)**
>
> - **Browser receiver is not planned:** [`totaldrop-app/totaldrop#30`](https://github.com/totaldrop-app/totaldrop/issues/30) (*Receive in the browser*) was closed as **Not planned**.
> - **Blocked at the server edge (`T9`):** Since [`totaldrop-app/totaldrop#450`](https://github.com/totaldrop-app/totaldrop/issues/450) / [`PR #453`](https://github.com/totaldrop-app/totaldrop/pull/453), all four production and self-hosted TotalDrop Rendezvous and Relay server implementations reject WebSocket upgrades carrying an HTTP `Origin` header with `403 Forbidden` before per-client rate-limit accounting.
> - **Repository scope boundary (`ADR 0025`):** Under Phase 0 and rule 6 of the modular multi-repository architecture, this repository is **reserved**. The pure-Rust `wasm32` crates and `web-ui/` prototype modules below are non-authoritative, undeployed, and unsupported unless a dedicated future ADR and threat-model `T9` revision are accepted by the maintainers.

Archived prototype pure-Rust WebAssembly protocol/cryptography workspace and zero-framework browser receiver research modules extracted from [`totaldrop-app/totaldrop`](https://github.com/totaldrop-app/totaldrop) at upstream commit `ebe2b19` (`v0.2.0-beta.5`).

Every crate in this workspace enforces `unsafe_code = "forbid"` alongside upstream's strict Clippy lint profile (`missing_docs`, `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`).

---

## Architecture Overview

| Component | Path | Description |
| --- | --- | --- |
| `totaldrop-wasm` | `crates/totaldrop-wasm` | Pure-Rust `wasm32`-ready protocol, cryptography, and localization crate wrapping `totaldrop-crypto`, `totaldrop-proto`, and `totaldrop-l10n`. |
| `totaldrop-crypto` | `crates/totaldrop-crypto` | Suite `TD0` cryptographic primitives (`BLAKE3` key derivation, `CPace` over `ristretto255`, `Ed25519` + `X25519` + `ML-KEM-768`, `ChaCha20-Poly1305` STREAM). |
| `totaldrop-proto` | `crates/totaldrop-proto` | `TransferCode::from_link` / `parse` / `find`, deterministic CBOR wire codecs, and cross-platform `SafePath` validation. |
| `totaldrop-l10n` | `crates/totaldrop-l10n` | Compile-time localization catalog (`l10n/`) covering all 35 TotalDrop languages, CLDR plural rules, regional SI byte formatting, and RTL bidi isolation. |
| `web-ui/` | `web-ui/{receiver.js,fs-writer.js,ORIGIN-ALLOWLIST.md}` | Zero-framework ES modules implementing runtime Wasm `simd128` probing, SRI-verified loading, URL fragment scrubbing, streaming `File System Access API` (`showSaveFilePicker`) disk writes, and the `#450` Worker `Origin` allowlist design. |
| `target-wasm32-simd128/` | `target-wasm32-simd128/build.sh` | Isolated release build unit (`-C target-feature=+simd128`) + SHA-384 Subresource Integrity (`sha384-…`) manifest generator. |
| `target-wasm32-baseline/` | `target-wasm32-baseline/build.sh` | Portable baseline `wasm32-unknown-unknown` build unit (`-C target-feature=-simd128`) + SHA-384 SRI manifest generator. |

---

## `crates/totaldrop-wasm` Capabilities

1. **Strict Share-URL & Wormhole Code Parsing (`totaldrop_wasm::link`)**
   - Wraps `TransferCode::from_link`, `TransferCode::parse`, and `TransferCode::find`.
   - Parses `https://totaldrop.app/r#…`, browser `window.location.hash` fragments (`#7-harbor-rocket`), `totaldrop://r/…` URIs, and bare codes while enforcing `MAX_LINK_BYTES = 1024`, stripping `INVISIBLE_FORMAT` bidi/zero-width marks prior to prefix matching, normalizing Arabic-Indic digits, and decoding `%XX` escapes **strictly once** (rejecting double-encoded `%25XX` payloads and trailing query strings).

2. **Suite `TD0` Browser Receiver State Machine (`totaldrop_wasm::state`)**
   - `Td0Parameters`: validates protocol version `0`, `ML-KEM-768` encapsulation key lengths (`1184` bytes), and strict RFC 8032 Ed25519 self-signed peer `Certificate`s.
   - `WebReceiverSession`: drives `LinkParsed` → `CpaceStarted` → `MailboxReady` → `SessionReady` → `ReceivingFiles` → `Completed`:
     - `CPace` responder exchange (`CHANNEL_ID = b"totaldrop/0"`) and directional `MailboxCipher`.
     - Post-quantum hybrid session derivation (`Noise` hash + `ML-KEM-768` shared secret) and 4-word English SAS verification words.
     - `Control::Offer` validation: checks `1 MiB` chunk size, verifies Ed25519 manifest signatures, normalizes all paths to NFC via `validate_path`, rejects case-insensitive `collision_key()` duplicates, and authenticates every incoming `EntryCipher` chunk plus the whole-file `BLAKE3` digest before emitting `Control::EntryDone`.

3. **`XChaCha20-Poly1305` Stream & Chunk Verifier (`totaldrop_wasm::xchacha`)**
   - Domain-separated key and 19-byte nonce-prefix derivation (`Purpose::LinkContent`, `Purpose::LinkManifest`, `"totaldrop TD0 xchacha20 nonce"`) forming 24-byte `XNonce`s (`prefix19 || u32be(chunk_index) || last_flag`) with 28-byte container/entry/chunk AAD.
   - `XChaChaStreamVerifier` rejects chunk reordering, truncation, cross-entry splicing, and tampered tags, and checks the cumulative `BLAKE3` plaintext digest in constant time on `finish()`.

4. **35-Language Browser Status Localization (`totaldrop_wasm::l10n`)**
   - `WebLocalizer::from_browser_languages` negotiates `navigator.languages` across all 35 compiled TotalDrop languages (38 locale catalogs in `l10n/app`), exposing localized status lines, pluralized offer summaries, regional SI byte sizes, `html_dir()` (`"ltr"` / `"rtl"`), and safety-critical draft translation gating.

---

## Zero-Framework Web UI & Worker `Origin` Allowlist (`web-ui/`)

- **[`web-ui/fs-writer.js`](web-ui/fs-writer.js)**: Wraps `window.showSaveFilePicker` and `window.showDirectoryPicker` (`FileSystemWritableFileStream`) so decrypted 1 MiB chunks stream straight to disk without RAM buffering. Temporary swap files are committed via `close()` **only** after `totaldrop-wasm` confirms the whole-file `BLAKE3` hash; any failure calls `abort()` so unverified bytes never materialize on disk.
- **[`web-ui/receiver.js`](web-ui/receiver.js)**: Probes Wasm `simd128` support via `WebAssembly.validate`, loads the matching WASM build with mandatory SHA-384 `integrity` checking, scrubs `window.location.hash` via `history.replaceState`, and coordinates WebSocket + disk streaming.
- **[`web-ui/ORIGIN-ALLOWLIST.md`](web-ui/ORIGIN-ALLOWLIST.md)**: Documents how `rendezvous-worker` and `relay-worker` issue `#450` WebSocket guards transition from `request.headers.has("Origin")` (`403`) to `Origin === "https://totaldrop.app"` (scoped to `/v0/mailbox/<n>` before rate-limit accounting) when the Web Receiver is enabled.

---

## Building, Testing, and Linting

```sh
# Run all workspace unit tests (totaldrop-crypto, totaldrop-proto, totaldrop-l10n, totaldrop-wasm)
RUSTUP_TOOLCHAIN=stable cargo test --workspace --offline

# Enforce strict workspace and Clippy lints with zero warnings
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --offline -- -D warnings

# Inspect or run isolated WASM target build units (+ SHA-384 SRI generation)
./target-wasm32-simd128/build.sh --dry-run
./target-wasm32-baseline/build.sh --dry-run
```
