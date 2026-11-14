// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Pure-Rust browser-ready protocol and cryptographic state machine for suite
//! `TD0` (`totaldrop/0`).
//!
//! Models the receiver lifecycle inside `wasm32` without any OS socket or
//! filesystem dependency:
//! 1. Strict share-link / wormhole code parsing (`ParsedTransferLink`).
//! 2. `CPace` (`ristretto255` + `SHA-512`) responder exchange bound to the
//!    rendezvous `sid` and `CHANNEL_ID = b"totaldrop/0"`.
//! 3. `MailboxCipher` encrypted `HINTS` / handshake message framing.
//! 4. Hybrid post-quantum session key derivation (`Noise` hash + `ML-KEM-768`
//!    shared secret) and 4-word SAS verification derivation.
//! 5. Strict `Control::Offer` validation (`TD0` parameter bounds, Ed25519
//!    manifest signature verification, cross-platform `SafePath` normalization,
//!    case-folding collision detection, and byte-sum overflow checks).
//! 6. Per-entry `EntryCipher` (`ChaCha20-Poly1305` STREAM) chunk decryption and
//!    constant-time whole-file `BLAKE3` verification prior to committing files
//!    via the browser `File System Access API`.

use std::collections::BTreeSet;

use totaldrop_crypto::channel::{
    MailboxCipher, Opener, Sealer, session, session_keys, verification_indices,
};
use totaldrop_crypto::cpace::{CHANNEL_ID, Cpace, MESSAGE_SIZE as CPACE_MESSAGE_SIZE, Role};
use totaldrop_crypto::identity::{KEM_CIPHERTEXT_SIZE, KEM_PUBLIC_SIZE, verify_signature};
use totaldrop_crypto::{CHUNK_SIZE, ContentKey, EntryCipher, Error as CryptoError, TAG_SIZE};
use totaldrop_proto::wire::{Certificate, Control, EntryKind, Manifest, RejectReason, WireError};
use totaldrop_proto::{PathError, SafePath, chunk_count, limits, validate_path};

use crate::link::{LinkParseError, ParsedTransferLink};

/// Protocol version implemented by suite `TD0`.
pub const TD0_PROTOCOL_VERSION: u64 = 0;

/// Validated protocol suite `TD0` parameter snapshot exposed to the browser
/// runtime for sanity checks and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Td0Parameters {
    /// Wire protocol version (`0`).
    pub protocol_version: u64,
    /// CPace channel identifier (`b"totaldrop/0"`).
    pub channel_id: &'static [u8],
    /// Plaintext file chunk size in bytes (`1 MiB`).
    pub chunk_size: usize,
    /// AEAD authentication tag size in bytes (`16`).
    pub tag_size: usize,
    /// `CPace` ristretto255 public element size in bytes (`32`).
    pub cpace_message_size: usize,
    /// `ML-KEM-768` encapsulation public key size in bytes (`1184`).
    pub kem_public_size: usize,
    /// `ML-KEM-768` ciphertext size in bytes (`1088`).
    pub kem_ciphertext_size: usize,
    /// Maximum entries allowed in a single manifest (`100_000`).
    pub max_entries: usize,
    /// Maximum encoded manifest size in bytes (`16 MiB`).
    pub max_manifest_bytes: usize,
}

impl Td0Parameters {
    /// Return the canonical `TD0` suite parameter set.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            protocol_version: TD0_PROTOCOL_VERSION,
            channel_id: CHANNEL_ID,
            chunk_size: CHUNK_SIZE,
            tag_size: TAG_SIZE,
            cpace_message_size: CPACE_MESSAGE_SIZE,
            kem_public_size: KEM_PUBLIC_SIZE,
            kem_ciphertext_size: KEM_CIPHERTEXT_SIZE,
            max_entries: limits::MAX_ENTRIES,
            max_manifest_bytes: limits::MAX_MANIFEST_BYTES,
        }
    }

    /// Validate a peer's `Certificate` against `TD0` version, `ML-KEM-768` key
    /// size, and strict RFC 8032 Ed25519 self-signature rules.
    pub fn validate_peer_certificate(cert_bytes: &[u8]) -> Result<Certificate, WebReceiverError> {
        let cert = Certificate::decode(cert_bytes).map_err(WebReceiverError::Wire)?;
        if cert.version != TD0_PROTOCOL_VERSION || cert.kem_key.len() != KEM_PUBLIC_SIZE {
            return Err(WebReceiverError::InvalidTd0Parameter("peer certificate"));
        }
        let signed = cert.signed_bytes();
        verify_signature(&cert.signing_key, &signed, &cert.signature)
            .map_err(WebReceiverError::Crypto)?;
        Ok(cert)
    }

    /// Check that a peer's advertised `HINTS` version list includes `TD0` (`0`).
    pub fn ensure_version_supported(versions: &[u64]) -> Result<(), WebReceiverError> {
        if versions.contains(&TD0_PROTOCOL_VERSION) {
            Ok(())
        } else {
            Err(WebReceiverError::InvalidTd0Parameter(
                "peer protocol version",
            ))
        }
    }
}

/// Current lifecycle stage of a [`WebReceiverSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverStage {
    /// Link/code parsed; waiting for rendezvous mailbox `sid` to start `CPace`.
    LinkParsed,
    /// `CPace` responder point `Yb` sent; waiting for sender's `Ya`.
    CpaceStarted,
    /// `CPace` finished and `MailboxCipher` established.
    MailboxReady,
    /// Post-quantum hybrid session keys (`Sealer` / `Opener`) and SAS words ready.
    SessionReady,
    /// Signed `Control::Offer` validated and accepted; receiving file chunks.
    ReceivingFiles,
    /// Every file entry passed chunk AEAD and whole-file `BLAKE3` verification.
    Completed,
    /// Offer was rejected by policy or user choice.
    Rejected,
}

/// Errors returned by the pure-Rust browser receiver state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebReceiverError {
    /// Share link or code failed validation.
    Link(LinkParseError),
    /// State machine method was invoked in the wrong [`ReceiverStage`].
    InvalidState {
        /// Expected stage description.
        expected: &'static str,
        /// Actual current stage.
        actual: ReceiverStage,
    },
    /// Cryptographic primitive or authentication check failed.
    Crypto(CryptoError),
    /// Wire CBOR decoding failed.
    Wire(WireError),
    /// A `TD0` suite parameter or invariant was violated.
    InvalidTd0Parameter(&'static str),
    /// Entry path failed cross-platform safety validation (`SafePath`).
    UnsafePath {
        /// Index of the offending entry in the manifest.
        entry_index: usize,
        /// Specific path validation failure.
        error: PathError,
    },
    /// Two entries in the manifest collide under case-insensitive comparison.
    DuplicatePathCollision(String),
    /// Chunk index or entry index was invalid or out of order.
    ChunkOrder(&'static str),
    /// Whole-file `BLAKE3` plaintext digest or byte total did not match the
    /// signed manifest.
    FileHashMismatch {
        /// Manifest index of the corrupted file entry.
        entry_index: u64,
    },
}

impl core::fmt::Display for WebReceiverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Link(e) => core::fmt::Display::fmt(e, f),
            Self::InvalidState { expected, actual } => {
                write!(
                    f,
                    "invalid receiver state: expected {expected}, got {actual:?}"
                )
            }
            Self::Crypto(e) => core::fmt::Display::fmt(e, f),
            Self::Wire(e) => core::fmt::Display::fmt(e, f),
            Self::InvalidTd0Parameter(what) => write!(f, "invalid TD0 parameter: {what}"),
            Self::UnsafePath { entry_index, error } => {
                write!(f, "unsafe path at entry {entry_index}: {error:?}")
            }
            Self::DuplicatePathCollision(key) => {
                write!(f, "case-insensitive path collision in manifest: {key}")
            }
            Self::ChunkOrder(msg) => write!(f, "chunk ordering violation: {msg}"),
            Self::FileHashMismatch { entry_index } => {
                write!(f, "BLAKE3 file digest mismatch for entry {entry_index}")
            }
        }
    }
}

impl std::error::Error for WebReceiverError {}

/// A validated manifest entry with NFC-normalized [`SafePath`] and precomputed
/// chunk count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEntry {
    /// Index of this entry in `Manifest::entries`.
    pub index: u64,
    /// Validated NFC-normalized relative path.
    pub safe_path: SafePath,
    /// File or directory kind.
    pub kind: EntryKind,
    /// Exact plaintext size in bytes (`0` for directories).
    pub size: u64,
    /// Expected 32-byte `BLAKE3` digest (`Some` for all `EntryKind::File` items).
    pub blake3_hash: Option<[u8; 32]>,
    /// Number of chunks (`0` for directories, `>= 1` for files).
    pub total_chunks: u64,
}

/// Summary of a cryptographically verified and path-sanitized `Control::Offer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOffer {
    /// 16-byte random transfer identifier.
    pub transfer_id: [u8; 16],
    /// Sanitized entries in manifest order.
    pub entries: Vec<ValidatedEntry>,
    /// Number of regular file entries (`EntryKind::File`).
    pub file_count: u64,
    /// Exact sum of file byte sizes.
    pub total_size: u64,
    /// Whether the offer represents a single inline text snippet rather than
    /// files to save to disk.
    pub is_text: bool,
}

struct ActiveFileVerifier {
    cipher: EntryCipher,
    expected_size: u64,
    expected_hash: [u8; 32],
    total_chunks: u64,
    next_chunk: u64,
    bytes_verified: u64,
    hasher: blake3::Hasher,
    finished: bool,
}

/// Outcome of decrypting and verifying a single incoming file chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChunk {
    /// Authenticated plaintext bytes of this chunk, safe to stream into an
    /// uncommitted `FileSystemWritableFileStream`.
    pub plaintext: Vec<u8>,
    /// `true` when this was the final chunk of the file AND its whole-file
    /// `BLAKE3` digest matched the signed manifest (the caller may now commit
    /// `writable.close()`).
    pub entry_complete: bool,
    /// Encrypted `Control::EntryDone` frame ready to send on the control
    /// stream when `entry_complete` is `true`.
    pub encrypted_entry_done: Option<Vec<u8>>,
    /// `true` when every file in the transfer has now completed verification.
    pub transfer_complete: bool,
}

/// Pure-Rust `TD0` protocol and cryptographic state machine for the WebAssembly
/// browser receiver.
pub struct WebReceiverSession {
    link: ParsedTransferLink,
    stage: ReceiverStage,
    cpace: Option<Cpace>,
    mailbox: Option<MailboxCipher>,
    sealer: Option<Sealer>,
    opener: Option<Opener>,
    sas_words: Option<[String; 4]>,
    offer: Option<ValidatedOffer>,
    files: Vec<Option<ActiveFileVerifier>>,
    remaining_files: usize,
}

impl core::fmt::Debug for WebReceiverSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebReceiverSession")
            .field("nameplate", &self.link.nameplate())
            .field("stage", &self.stage)
            .field("remaining_files", &self.remaining_files)
            .finish_non_exhaustive()
    }
}

impl WebReceiverSession {
    /// Initialize a receiver session from a browser share URL, `#fragment`, or
    /// bare transfer code.
    pub fn from_share_input(input: &str) -> Result<Self, WebReceiverError> {
        let link =
            ParsedTransferLink::parse_link_or_fragment(input).map_err(WebReceiverError::Link)?;
        Ok(Self {
            link,
            stage: ReceiverStage::LinkParsed,
            cpace: None,
            mailbox: None,
            sealer: None,
            opener: None,
            sas_words: None,
            offer: None,
            files: Vec::new(),
            remaining_files: 0,
        })
    }

    /// Parsed share link and wormhole code metadata.
    #[must_use]
    pub fn link(&self) -> &ParsedTransferLink {
        &self.link
    }

    /// Current stage of the receiver state machine.
    #[must_use]
    pub fn stage(&self) -> ReceiverStage {
        self.stage
    }

    /// Four English SAS verification words once the hybrid session is active.
    #[must_use]
    pub fn verification_words(&self) -> Option<&[String; 4]> {
        self.sas_words.as_ref()
    }

    /// Validated offer metadata once an incoming `Control::Offer` has been
    /// accepted.
    #[must_use]
    pub fn validated_offer(&self) -> Option<&ValidatedOffer> {
        self.offer.as_ref()
    }

    /// Step 1: Start `CPace` as `Role::Responder` using the canonical ASCII
    /// code (`PRS`) and the 16-byte mailbox `sid` assigned by the rendezvous
    /// server. Returns the 32-byte ristretto255 public point `Yb`.
    pub fn start_cpace(
        &mut self,
        mailbox_sid: &[u8; 16],
    ) -> Result<[u8; CPACE_MESSAGE_SIZE], WebReceiverError> {
        if self.stage != ReceiverStage::LinkParsed {
            return Err(WebReceiverError::InvalidState {
                expected: "LinkParsed",
                actual: self.stage,
            });
        }
        let prs = self.link.canonical_cpace_prs();
        let (cpace, yb) = Cpace::start(Role::Responder, prs.as_bytes(), mailbox_sid)
            .map_err(WebReceiverError::Crypto)?;
        self.cpace = Some(cpace);
        self.stage = ReceiverStage::CpaceStarted;
        Ok(yb)
    }

    /// Step 2: Complete `CPace` with the sender's 32-byte `Ya` message and
    /// initialize the directional `MailboxCipher`.
    pub fn finish_cpace(
        &mut self,
        peer_ya: &[u8; CPACE_MESSAGE_SIZE],
    ) -> Result<(), WebReceiverError> {
        if self.stage != ReceiverStage::CpaceStarted {
            return Err(WebReceiverError::InvalidState {
                expected: "CpaceStarted",
                actual: self.stage,
            });
        }
        let cpace = self.cpace.take().ok_or(WebReceiverError::InvalidState {
            expected: "CpaceStarted",
            actual: self.stage,
        })?;
        let isk = cpace.finish(peer_ya).map_err(WebReceiverError::Crypto)?;
        self.mailbox = Some(MailboxCipher::new(&isk, Role::Responder));
        self.stage = ReceiverStage::MailboxReady;
        Ok(())
    }

    /// Encrypt an outgoing phase-bound rendezvous mailbox payload under
    /// `K_mailbox`.
    pub fn seal_mailbox(
        &mut self,
        phase: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, WebReceiverError> {
        let mailbox = self
            .mailbox
            .as_mut()
            .ok_or(WebReceiverError::InvalidState {
                expected: "MailboxReady",
                actual: self.stage,
            })?;
        mailbox
            .seal(phase, plaintext)
            .map_err(WebReceiverError::Crypto)
    }

    /// Decrypt and authenticate an incoming phase-bound rendezvous mailbox
    /// payload under `K_mailbox`.
    pub fn open_mailbox(
        &mut self,
        phase: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, WebReceiverError> {
        let mailbox = self
            .mailbox
            .as_mut()
            .ok_or(WebReceiverError::InvalidState {
                expected: "MailboxReady",
                actual: self.stage,
            })?;
        mailbox
            .open(phase, ciphertext)
            .map_err(WebReceiverError::Crypto)
    }

    /// Step 3: Derive the post-quantum hybrid session ciphers (`k_i2r`, `k_r2i`)
    /// and the four 11-bit English SAS verification words from the Noise
    /// handshake hash `h` and 32-byte `ML-KEM-768` shared secret `ss`.
    pub fn establish_hybrid_session(
        &mut self,
        handshake_hash: &[u8],
        kem_secret: &[u8; 32],
    ) -> Result<[String; 4], WebReceiverError> {
        if self.stage != ReceiverStage::MailboxReady {
            return Err(WebReceiverError::InvalidState {
                expected: "MailboxReady",
                actual: self.stage,
            });
        }
        if handshake_hash.is_empty() {
            return Err(WebReceiverError::InvalidTd0Parameter(
                "empty handshake hash",
            ));
        }
        let (k_i2r, k_r2i) = session_keys(handshake_hash, kem_secret);
        // Browser receiver is always the responder (`initiator = false`).
        let (sealer, opener) = session(k_i2r, k_r2i, false);
        let indices = verification_indices(handshake_hash, kem_secret);
        let wordlist = bip39::Language::English.word_list();
        let words = indices.map(|idx| {
            wordlist
                .get(usize::from(idx))
                .copied()
                .unwrap_or("unknown")
                .to_owned()
        });
        self.sealer = Some(sealer);
        self.opener = Some(opener);
        self.sas_words = Some(words.clone());
        self.stage = ReceiverStage::SessionReady;
        Ok(words)
    }

    /// Step 4: Decrypt an incoming encrypted control message, verify that it is
    /// a valid `TD0` `Control::Offer` signed by `peer_signing_key`, sanitize
    /// all paths, and return both the [`ValidatedOffer`] and the encrypted
    /// `Control::Accept` frame to transmit back.
    pub fn accept_encrypted_offer(
        &mut self,
        encrypted_offer: &[u8],
        peer_signing_key: &[u8; 32],
    ) -> Result<(ValidatedOffer, Vec<u8>), WebReceiverError> {
        if self.stage != ReceiverStage::SessionReady {
            return Err(WebReceiverError::InvalidState {
                expected: "SessionReady",
                actual: self.stage,
            });
        }
        let opener = self.opener.as_mut().ok_or(WebReceiverError::InvalidState {
            expected: "SessionReady",
            actual: self.stage,
        })?;
        let plain = opener
            .open(encrypted_offer)
            .map_err(WebReceiverError::Crypto)?;
        let control = Control::decode(&plain).map_err(WebReceiverError::Wire)?;

        let Control::Offer {
            manifest,
            content_key,
            signature,
            progress,
            text,
        } = control
        else {
            return Err(WebReceiverError::InvalidTd0Parameter(
                "expected Control::Offer",
            ));
        };

        let validated = validate_manifest(&manifest, &signature, peer_signing_key, text)?;
        let ck = ContentKey::from_bytes(content_key);

        let mut wanted = Vec::new();
        let mut file_verifiers = Vec::with_capacity(validated.entries.len());
        let mut remaining_files: usize = 0;

        for entry in &validated.entries {
            match entry.kind {
                EntryKind::Dir => {
                    file_verifiers.push(None);
                }
                EntryKind::File => {
                    let expected_hash =
                        entry
                            .blake3_hash
                            .ok_or(WebReceiverError::InvalidTd0Parameter(
                                "file entry missing BLAKE3 hash",
                            ))?;
                    wanted.push((entry.index, Vec::new()));
                    file_verifiers.push(Some(ActiveFileVerifier {
                        cipher: EntryCipher::new(&ck, &validated.transfer_id, entry.index),
                        expected_size: entry.size,
                        expected_hash,
                        total_chunks: entry.total_chunks,
                        next_chunk: 0,
                        bytes_verified: 0,
                        hasher: blake3::Hasher::new(),
                        finished: false,
                    }));
                    remaining_files = remaining_files.saturating_add(1);
                }
            }
        }

        let accept_frame = Control::Accept {
            transfer_id: validated.transfer_id,
            wanted,
            progress,
        }
        .encode();
        let sealer = self.sealer.as_mut().ok_or(WebReceiverError::InvalidState {
            expected: "SessionReady",
            actual: self.stage,
        })?;
        let encrypted_accept = sealer
            .seal(&accept_frame)
            .map_err(WebReceiverError::Crypto)?;

        self.files = file_verifiers;
        self.remaining_files = remaining_files;
        self.stage = if remaining_files == 0 {
            ReceiverStage::Completed
        } else {
            ReceiverStage::ReceivingFiles
        };
        self.offer = Some(validated.clone());

        Ok((validated, encrypted_accept))
    }

    /// Encode and encrypt a `Control::Reject` frame if the user declines the
    /// incoming offer.
    pub fn reject_offer(&mut self, reason: RejectReason) -> Result<Vec<u8>, WebReceiverError> {
        let Some(offer) = &self.offer else {
            return Err(WebReceiverError::InvalidState {
                expected: "ReceivingFiles",
                actual: self.stage,
            });
        };
        let sealer = self.sealer.as_mut().ok_or(WebReceiverError::InvalidState {
            expected: "ReceivingFiles",
            actual: self.stage,
        })?;
        let frame = Control::Reject {
            transfer_id: offer.transfer_id,
            reason,
        }
        .encode();
        let ct = sealer.seal(&frame).map_err(WebReceiverError::Crypto)?;
        self.stage = ReceiverStage::Rejected;
        Ok(ct)
    }

    /// Step 5: Authenticate and decrypt one incoming `EntryCipher` chunk for
    /// `entry_index` at `chunk_index`, updating its running `BLAKE3` plaintext
    /// hash and emitting an encrypted `Control::EntryDone` message when the
    /// file completes intact.
    pub fn verify_entry_chunk(
        &mut self,
        entry_index: u64,
        chunk_index: u32,
        ciphertext: &[u8],
    ) -> Result<VerifiedChunk, WebReceiverError> {
        if self.stage != ReceiverStage::ReceivingFiles {
            return Err(WebReceiverError::InvalidState {
                expected: "ReceivingFiles",
                actual: self.stage,
            });
        }
        let offer = self.offer.as_ref().ok_or(WebReceiverError::InvalidState {
            expected: "ReceivingFiles",
            actual: self.stage,
        })?;
        let idx_usize = usize::try_from(entry_index)
            .map_err(|_| WebReceiverError::ChunkOrder("bad entry index"))?;
        let slot = self
            .files
            .get_mut(idx_usize)
            .and_then(Option::as_mut)
            .ok_or(WebReceiverError::ChunkOrder("entry is not an active file"))?;

        if slot.finished || u64::from(chunk_index) != slot.next_chunk {
            return Err(WebReceiverError::ChunkOrder(
                "unexpected chunk index or entry already finished",
            ));
        }

        let next_after = slot
            .next_chunk
            .checked_add(1)
            .ok_or(WebReceiverError::ChunkOrder("chunk counter overflow"))?;
        let is_last = next_after == slot.total_chunks;

        let plaintext = slot
            .cipher
            .open(chunk_index, is_last, ciphertext)
            .map_err(WebReceiverError::Crypto)?;
        let plain_len = u64::try_from(plaintext.len())
            .map_err(|_| WebReceiverError::ChunkOrder("chunk size"))?;

        if !is_last && plaintext.len() != CHUNK_SIZE {
            return Err(WebReceiverError::ChunkOrder(
                "non-final chunk shorter than 1 MiB",
            ));
        }
        if is_last && slot.expected_size > 0 && plaintext.is_empty() {
            return Err(WebReceiverError::ChunkOrder(
                "final chunk of non-empty file cannot be empty",
            ));
        }

        let new_bytes = slot
            .bytes_verified
            .checked_add(plain_len)
            .ok_or(WebReceiverError::ChunkOrder("byte total overflow"))?;
        if new_bytes > slot.expected_size {
            return Err(WebReceiverError::FileHashMismatch { entry_index });
        }

        slot.hasher.update(&plaintext);
        slot.bytes_verified = new_bytes;
        slot.next_chunk = next_after;

        if !is_last {
            return Ok(VerifiedChunk {
                plaintext,
                entry_complete: false,
                encrypted_entry_done: None,
                transfer_complete: false,
            });
        }

        if slot.bytes_verified != slot.expected_size {
            return Err(WebReceiverError::FileHashMismatch { entry_index });
        }
        let computed = slot.hasher.finalize();
        let expected = blake3::Hash::from_bytes(slot.expected_hash);
        if computed != expected {
            return Err(WebReceiverError::FileHashMismatch { entry_index });
        }

        slot.finished = true;
        self.remaining_files = self.remaining_files.saturating_sub(1);
        let transfer_complete = self.remaining_files == 0;
        if transfer_complete {
            self.stage = ReceiverStage::Completed;
        }

        let done_frame = Control::EntryDone {
            transfer_id: offer.transfer_id,
            index: entry_index,
            ok: true,
        }
        .encode();
        let sealer = self.sealer.as_mut().ok_or(WebReceiverError::InvalidState {
            expected: "ReceivingFiles",
            actual: self.stage,
        })?;
        let encrypted_done = sealer.seal(&done_frame).map_err(WebReceiverError::Crypto)?;

        Ok(VerifiedChunk {
            plaintext,
            entry_complete: true,
            encrypted_entry_done: Some(encrypted_done),
            transfer_complete,
        })
    }
}

/// Validate all `TD0` safety rules on a decoded `Manifest` and its Ed25519
/// signature.
pub fn validate_manifest(
    manifest: &Manifest,
    signature: &[u8; 64],
    peer_signing_key: &[u8; 32],
    is_text: bool,
) -> Result<ValidatedOffer, WebReceiverError> {
    if manifest.chunk_size != limits::CHUNK_SIZE {
        return Err(WebReceiverError::InvalidTd0Parameter(
            "manifest chunk_size must equal 1 MiB",
        ));
    }
    if manifest.entries.is_empty() || manifest.entries.len() > limits::MAX_ENTRIES {
        return Err(WebReceiverError::InvalidTd0Parameter(
            "manifest entries count out of bounds",
        ));
    }

    let signed_bytes = manifest.signed_bytes();
    if signed_bytes.len() > limits::MAX_MANIFEST_BYTES {
        return Err(WebReceiverError::InvalidTd0Parameter(
            "encoded manifest exceeds 16 MiB",
        ));
    }

    verify_signature(peer_signing_key, &signed_bytes, signature)
        .map_err(WebReceiverError::Crypto)?;

    if is_text
        && (manifest.entries.len() != 1
            || manifest
                .entries
                .first()
                .is_none_or(|e| e.kind != EntryKind::File))
    {
        return Err(WebReceiverError::InvalidTd0Parameter(
            "text offer must contain exactly one file entry",
        ));
    }

    let mut collision_keys = BTreeSet::new();
    let mut entries = Vec::with_capacity(manifest.entries.len());
    let mut computed_total: u64 = 0;
    let mut file_count: u64 = 0;

    for (idx, raw_entry) in manifest.entries.iter().enumerate() {
        let safe_path =
            validate_path(&raw_entry.path).map_err(|error| WebReceiverError::UnsafePath {
                entry_index: idx,
                error,
            })?;
        let key = safe_path.collision_key();
        if !collision_keys.insert(key.clone()) {
            return Err(WebReceiverError::DuplicatePathCollision(key));
        }

        let idx_u64 =
            u64::try_from(idx).map_err(|_| WebReceiverError::InvalidTd0Parameter("entry index"))?;

        let total_chunks = match raw_entry.kind {
            EntryKind::Dir => {
                if raw_entry.size != 0 {
                    return Err(WebReceiverError::InvalidTd0Parameter(
                        "directory size must be zero",
                    ));
                }
                0
            }
            EntryKind::File => {
                if raw_entry.hash.is_none() {
                    return Err(WebReceiverError::InvalidTd0Parameter(
                        "file entry missing BLAKE3 hash",
                    ));
                }
                let chunks = chunk_count(raw_entry.size).ok_or(
                    WebReceiverError::InvalidTd0Parameter("file exceeds MAX_CHUNKS"),
                )?;
                computed_total = computed_total
                    .checked_add(raw_entry.size)
                    .ok_or(WebReceiverError::InvalidTd0Parameter("total_size overflow"))?;
                file_count = file_count.saturating_add(1);
                chunks
            }
        };

        entries.push(ValidatedEntry {
            index: idx_u64,
            safe_path,
            kind: raw_entry.kind,
            size: raw_entry.size,
            blake3_hash: raw_entry.hash,
            total_chunks,
        });
    }

    if computed_total != manifest.total_size {
        return Err(WebReceiverError::InvalidTd0Parameter(
            "manifest total_size does not match sum of file sizes",
        ));
    }

    Ok(ValidatedOffer {
        transfer_id: manifest.transfer_id,
        entries,
        file_count,
        total_size: computed_total,
        is_text,
    })
}
