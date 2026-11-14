// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Pure-Rust `XChaCha20-Poly1305` stream and chunk encryption/verification
//! helpers for browser link containers and chunked WebAssembly downloads.
//!
//! Each entry derives an isolated 256-bit `XChaCha20-Poly1305` key and a
//! 19-byte stream nonce prefix from a root link/container secret via domain-
//! separated BLAKE3 key derivation (`Purpose::LinkContent` and
//! `"totaldrop TD0 xchacha20 nonce"`). Every 1 MiB chunk is sealed and
//! authenticated with a 24-byte `XNonce`:
//!
//! ```text
//! key      = derive_key("totaldrop TD0 link content", secret || container_id || u64be(entry))
//! prefix19 = blake3::derive_key("totaldrop TD0 xchacha20 nonce", secret || container_id || u64be(entry))[0..19]
//! xnonce24 = prefix19 || u32be(chunk_index) || last_flag
//! aad28    = container_id || u64be(entry) || u32be(chunk_index)
//! ```
//!
//! This layout guarantees STREAM-style end-of-stream truncation resistance,
//! prevents chunk reordering or cross-entry splicing, and pairs with an
//! incremental `BLAKE3` whole-entry digest check before a browser commits a
//! `FileSystemWritableFileStream` to disk.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use totaldrop_crypto::{CHUNK_SIZE, Purpose, TAG_SIZE, derive_key};
use totaldrop_proto::chunk_count;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain-separation context for deriving the 19-byte `XChaCha20-Poly1305`
/// stream nonce prefix.
pub const XCHACHA_NONCE_CONTEXT: &str = "totaldrop TD0 xchacha20 nonce";

/// Size in bytes of an `XChaCha20-Poly1305` extended nonce (192 bits).
pub const XNONCE_SIZE: usize = 24;

/// Size in bytes of the STREAM-style nonce prefix (`24 - 4 - 1 = 19` bytes).
pub const XNONCE_PREFIX_SIZE: usize = 19;

/// Errors produced during `XChaCha20-Poly1305` chunk sealing or streaming
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XChaChaError {
    /// Chunk ciphertext failed Poly1305 authentication (tampered, reordered,
    /// wrong `last` flag, or encrypted under another key/entry).
    Inauthentic,
    /// Plaintext exceeded [`CHUNK_SIZE`], ciphertext was shorter than
    /// [`TAG_SIZE`], or declared file size exceeded protocol chunk bounds.
    Malformed,
    /// Caller supplied a `chunk_index` that did not match the expected next
    /// sequential chunk, or pushed chunks after the final chunk.
    OutOfSequence,
    /// Decrypted byte total or final `BLAKE3` plaintext digest did not match
    /// the signed manifest's expected size and hash.
    DigestMismatch,
    /// `finish` was called before all expected chunks of the entry arrived.
    IncompleteStream,
}

impl core::fmt::Display for XChaChaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Inauthentic => "stream chunk failed Poly1305 authentication",
            Self::Malformed => "malformed stream chunk or size limit exceeded",
            Self::OutOfSequence => "chunk index out of sequence or past end of stream",
            Self::DigestMismatch => "plaintext BLAKE3 digest or byte length mismatch",
            Self::IncompleteStream => "stream ended before all expected chunks were verified",
        })
    }
}

impl std::error::Error for XChaChaError {}

/// A 32-byte root secret for an `XChaCha20-Poly1305` link container or browser
/// transfer stream. Automatically zeroized when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct LinkSecret([u8; 32]);

impl LinkSecret {
    /// Wrap a 32-byte secret key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive the 32-byte manifest encryption key (`Purpose::LinkManifest`).
    #[must_use]
    pub fn derive_manifest_key(&self, container_id: &[u8; 16]) -> [u8; 32] {
        let mut material = [0u8; 48];
        if let Some((left, right)) = material.split_at_mut_checked(32) {
            left.copy_from_slice(&self.0);
            right.copy_from_slice(container_id);
        }
        let out = derive_key(Purpose::LinkManifest, &material);
        material.zeroize();
        out
    }
}

impl core::fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LinkSecret(..)")
    }
}

/// Stateless `XChaCha20-Poly1305` per-entry chunk cipher using a 19-byte
/// derived prefix, 4-byte big-endian chunk counter, and 1-byte final-chunk flag.
pub struct XChaChaChunkCipher {
    cipher: XChaCha20Poly1305,
    prefix: [u8; XNONCE_PREFIX_SIZE],
    container_id: [u8; 16],
    entry: u64,
}

impl core::fmt::Debug for XChaChaChunkCipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XChaChaChunkCipher")
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

impl XChaChaChunkCipher {
    /// Construct the `XChaCha20-Poly1305` chunk cipher for `entry` inside
    /// `container_id`.
    #[must_use]
    pub fn new(secret: &LinkSecret, container_id: &[u8; 16], entry: u64) -> Self {
        let mut material = [0u8; 32 + 16 + 8];
        if let Some((secret_dst, tail)) = material.split_at_mut_checked(32)
            && let Some((id_dst, entry_dst)) = tail.split_at_mut_checked(16)
        {
            secret_dst.copy_from_slice(secret.as_bytes());
            id_dst.copy_from_slice(container_id);
            entry_dst.copy_from_slice(&entry.to_be_bytes());
        }

        let mut key = derive_key(Purpose::LinkContent, &material);
        let mut nonce_full = blake3::derive_key(XCHACHA_NONCE_CONTEXT, &material);
        material.zeroize();

        let mut prefix = [0u8; XNONCE_PREFIX_SIZE];
        if let Some(src) = nonce_full.get(..XNONCE_PREFIX_SIZE) {
            prefix.copy_from_slice(src);
        }
        nonce_full.zeroize();

        let cipher = XChaCha20Poly1305::new(&Key::from(key));
        key.zeroize();

        Self {
            cipher,
            prefix,
            container_id: *container_id,
            entry,
        }
    }

    fn xnonce(&self, chunk_index: u32, last: bool) -> XNonce {
        let mut raw = [0u8; XNONCE_SIZE];
        if let Some((pref_dst, tail)) = raw.split_at_mut_checked(XNONCE_PREFIX_SIZE)
            && let Some((idx_dst, flag_dst)) = tail.split_at_mut_checked(4)
        {
            pref_dst.copy_from_slice(&self.prefix);
            idx_dst.copy_from_slice(&chunk_index.to_be_bytes());
            flag_dst.copy_from_slice(&[u8::from(last)]);
        }
        XNonce::from(raw)
    }

    fn aad(&self, chunk_index: u32) -> [u8; 28] {
        let mut out = [0u8; 28];
        if let Some((id_dst, tail)) = out.split_at_mut_checked(16)
            && let Some((entry_dst, idx_dst)) = tail.split_at_mut_checked(8)
        {
            id_dst.copy_from_slice(&self.container_id);
            entry_dst.copy_from_slice(&self.entry.to_be_bytes());
            idx_dst.copy_from_slice(&chunk_index.to_be_bytes());
        }
        out
    }

    /// Encrypt and authenticate one chunk (up to 1 MiB) with `XChaCha20-Poly1305`.
    pub fn seal(
        &self,
        chunk_index: u32,
        last: bool,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, XChaChaError> {
        if plaintext.len() > CHUNK_SIZE {
            return Err(XChaChaError::Malformed);
        }
        let aad = self.aad(chunk_index);
        self.cipher
            .encrypt(
                &self.xnonce(chunk_index, last),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| XChaChaError::Malformed)
    }

    /// Decrypt and authenticate one `XChaCha20-Poly1305` chunk.
    pub fn open(
        &self,
        chunk_index: u32,
        last: bool,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, XChaChaError> {
        let max_ct = CHUNK_SIZE.saturating_add(TAG_SIZE);
        if ciphertext.len() < TAG_SIZE || ciphertext.len() > max_ct {
            return Err(XChaChaError::Malformed);
        }
        let aad = self.aad(chunk_index);
        self.cipher
            .decrypt(
                &self.xnonce(chunk_index, last),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| XChaChaError::Inauthentic)
    }
}

/// Stateful streaming verifier for one file entry encrypted with
/// [`XChaChaChunkCipher`].
///
/// Enforces sequential chunk indices starting from `0`, exact chunk count
/// matching `totaldrop_proto::chunk_count(expected_size)`, mandatory `last`
/// flag on the final chunk, exact cumulative byte length, and constant-time
/// `BLAKE3` digest equality upon [`Self::finish`].
pub struct XChaChaStreamVerifier {
    cipher: XChaChaChunkCipher,
    expected_size: u64,
    expected_hash: [u8; 32],
    total_chunks: u64,
    next_chunk: u64,
    bytes_verified: u64,
    hasher: blake3::Hasher,
}

impl core::fmt::Debug for XChaChaStreamVerifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XChaChaStreamVerifier")
            .field("expected_size", &self.expected_size)
            .field("total_chunks", &self.total_chunks)
            .field("next_chunk", &self.next_chunk)
            .field("bytes_verified", &self.bytes_verified)
            .finish_non_exhaustive()
    }
}

impl XChaChaStreamVerifier {
    /// Create a streaming verifier for `entry` with signed `expected_size` and
    /// `expected_hash`.
    pub fn new(
        secret: &LinkSecret,
        container_id: &[u8; 16],
        entry: u64,
        expected_size: u64,
        expected_hash: [u8; 32],
    ) -> Result<Self, XChaChaError> {
        let total_chunks = chunk_count(expected_size).ok_or(XChaChaError::Malformed)?;
        Ok(Self {
            cipher: XChaChaChunkCipher::new(secret, container_id, entry),
            expected_size,
            expected_hash,
            total_chunks,
            next_chunk: 0,
            bytes_verified: 0,
            hasher: blake3::Hasher::new(),
        })
    }

    /// Expected total number of chunks for this file (at least `1`, since an
    /// empty file is transmitted as a single empty final chunk).
    #[must_use]
    pub fn total_chunks(&self) -> u64 {
        self.total_chunks
    }

    /// Number of plaintext bytes authenticated so far.
    #[must_use]
    pub fn bytes_verified(&self) -> u64 {
        self.bytes_verified
    }

    /// Verify and decrypt the next chunk in order, updating the running
    /// `BLAKE3` plaintext digest.
    pub fn verify_next_chunk(
        &mut self,
        chunk_index: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, XChaChaError> {
        if u64::from(chunk_index) != self.next_chunk || self.next_chunk >= self.total_chunks {
            return Err(XChaChaError::OutOfSequence);
        }
        let next_after = self
            .next_chunk
            .checked_add(1)
            .ok_or(XChaChaError::Malformed)?;
        let is_last = next_after == self.total_chunks;

        let plaintext = self.cipher.open(chunk_index, is_last, ciphertext)?;
        let plain_len = u64::try_from(plaintext.len()).map_err(|_| XChaChaError::Malformed)?;

        // Non-final chunks must be full 1 MiB blocks; an empty chunk is valid
        // only when `expected_size == 0` (single empty final chunk).
        if !is_last && plaintext.len() != CHUNK_SIZE {
            return Err(XChaChaError::Malformed);
        }
        if is_last && self.expected_size > 0 && plaintext.is_empty() {
            return Err(XChaChaError::Malformed);
        }

        let new_total = self
            .bytes_verified
            .checked_add(plain_len)
            .ok_or(XChaChaError::Malformed)?;
        if new_total > self.expected_size {
            return Err(XChaChaError::DigestMismatch);
        }

        self.hasher.update(&plaintext);
        self.bytes_verified = new_total;
        self.next_chunk = next_after;
        Ok(plaintext)
    }

    /// Complete the stream after all chunks have been pushed, verifying both
    /// the exact byte count and the whole-file `BLAKE3` digest in constant time
    /// (`blake3::Hash::eq` is constant-time).
    pub fn finish(self) -> Result<[u8; 32], XChaChaError> {
        if self.next_chunk != self.total_chunks {
            return Err(XChaChaError::IncompleteStream);
        }
        if self.bytes_verified != self.expected_size {
            return Err(XChaChaError::DigestMismatch);
        }
        let computed = self.hasher.finalize();
        let expected = blake3::Hash::from_bytes(self.expected_hash);
        if computed != expected {
            return Err(XChaChaError::DigestMismatch);
        }
        Ok(*computed.as_bytes())
    }
}
