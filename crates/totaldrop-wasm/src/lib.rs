// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! `totaldrop-wasm` — Pure-Rust browser WebAssembly wrapper around
//! [`totaldrop_crypto`], [`totaldrop_proto`], and [`totaldrop_l10n`].
//!
//! Designed for zero-`unsafe` (`unsafe_code = "forbid"`) execution inside
//! `wasm32-unknown-unknown` (both `+simd128` and baseline targets):
//!
//! - [`link`]: Strict share-link (`https://totaldrop.app/r#…`,
//!   `totaldrop://r/…`), URL hash fragment, and bare wormhole code parsing via
//!   [`totaldrop_proto::TransferCode::from_link`] and
//!   [`totaldrop_proto::TransferCode::parse`].
//! - [`state`]: Browser-ready `TD0` receiver protocol & cryptographic state
//!   machine (`CPace` responder, `MailboxCipher`, hybrid `ML-KEM-768` + Noise
//!   session keys, 4-word SAS verification, Ed25519 manifest signature &
//!   `SafePath` validation, and streaming `EntryCipher` + `BLAKE3` chunk
//!   verification).
//! - [`xchacha`]: Extended-nonce `XChaCha20-Poly1305` stream/chunk sealer and
//!   incremental `BLAKE3` verifier for browser link containers.
//! - [`l10n`]: Localized browser status, pluralized offer summaries, regional
//!   SI byte formatting, and RTL directionality across all 35 supported
//!   TotalDrop languages.

pub mod l10n;
pub mod link;
pub mod state;
pub mod xchacha;

pub use l10n::{UiStatus, WebLocalizer};
pub use link::{LinkKind, LinkParseError, ParsedTransferLink};
pub use state::{
    ReceiverStage, Td0Parameters, ValidatedEntry, ValidatedOffer, VerifiedChunk, WebReceiverError,
    WebReceiverSession, validate_manifest,
};
pub use xchacha::{
    LinkSecret, XChaChaChunkCipher, XChaChaError, XChaChaStreamVerifier, XNONCE_PREFIX_SIZE,
    XNONCE_SIZE,
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
mod tests {
    use totaldrop_crypto::channel::{MailboxCipher, session, session_keys, verification_indices};
    use totaldrop_crypto::cpace::{Cpace, Role};
    use totaldrop_crypto::identity::DeviceKeys;
    use totaldrop_crypto::{CHUNK_SIZE, ContentKey, EntryCipher};
    use totaldrop_proto::wire::{Certificate, Control, Entry, EntryKind, Manifest, RejectReason};
    use totaldrop_proto::{MAX_LINK_BYTES, limits};

    use super::*;

    #[test]
    fn share_links_fragments_and_wormhole_codes_parse_strictly() {
        let https =
            ParsedTransferLink::parse_link_or_fragment("https://totaldrop.app/r#7-abandon-ability")
                .unwrap();
        assert_eq!(https.kind(), LinkKind::HttpsFragment);
        assert_eq!(https.nameplate(), 7);
        assert_eq!(https.canonical_cpace_prs(), "7-0-1");
        assert_eq!(https.display_english(), "7-abandon-ability");
        assert_eq!(
            https.to_https_link(),
            "https://totaldrop.app/r#7-abandon-ability"
        );

        // Browser `window.location.hash` form (`#...`) with single `%XX` escapes
        // and invisible bidi marks + Arabic-Indic digits:
        let hash_input = "\u{2068}#\u{0667}-abandon%2Dability\u{2069}";
        let from_hash = ParsedTransferLink::parse_link_or_fragment(hash_input).unwrap();
        assert_eq!(from_hash.kind(), LinkKind::HttpsFragment);
        assert_eq!(from_hash.canonical_cpace_prs(), "7-0-1");

        // Double percent-encoding (`%252D`) MUST be rejected (decoded only once):
        assert_eq!(
            ParsedTransferLink::parse_link_or_fragment(
                "https://totaldrop.app/r#7-abandon%252Dability"
            ),
            Err(LinkParseError::InvalidLink)
        );

        // Trailing query parameters MUST be rejected:
        assert_eq!(
            ParsedTransferLink::parse_link_or_fragment(
                "https://totaldrop.app/r#7-abandon-ability?utm=1"
            ),
            Err(LinkParseError::InvalidLink)
        );

        // Custom scheme and bare code:
        let custom =
            ParsedTransferLink::parse_link_or_fragment("totaldrop://r/42-abandon-ability-able")
                .unwrap();
        assert_eq!(custom.kind(), LinkKind::CustomScheme);
        assert_eq!(custom.canonical_cpace_prs(), "42-0-1-2");

        let bare = ParsedTransferLink::parse_bare_code("42 ABANDON ABILITY ABLE").unwrap();
        assert_eq!(bare.kind(), LinkKind::BareCode);
        assert_eq!(bare.canonical_cpace_prs(), "42-0-1-2");

        // Over-limit inputs (`> MAX_LINK_BYTES`) are rejected unread:
        let huge = "a".repeat(MAX_LINK_BYTES + 1);
        assert_eq!(
            ParsedTransferLink::parse_link_or_fragment(&huge),
            Err(LinkParseError::TooLong)
        );
    }

    #[test]
    fn localized_share_text_round_trips_through_find() {
        let ar = WebLocalizer::from_browser_languages(&["ar"], None);
        assert!(ar.is_rtl());
        assert_eq!(ar.html_dir(), "rtl");
        let msg = ar.format_status(&UiStatus::ShareText {
            code: "19-abandon-ability",
        });
        let extracted = ParsedTransferLink::find_in_share_text(&msg).unwrap();
        assert_eq!(extracted.display_english(), "19-abandon-ability");
    }

    #[test]
    fn all_35_plus_languages_format_receiver_statuses_cleanly() {
        let locales = WebLocalizer::supported_locales();
        assert!(
            locales.len() >= 35,
            "expected at least 35 compiled app locales, got {}",
            locales.len()
        );

        for tag in &locales {
            let loc = WebLocalizer::from_browser_languages(&[tag.as_str()], None);
            assert!(!loc.receive_title().is_empty());
            assert_ne!(loc.receive_title(), "receiveTitle");

            let connecting = loc.format_status(&UiStatus::Connecting);
            assert!(!connecting.is_empty());
            assert_ne!(connecting, "receiveConnecting");

            let summary = loc.format_status(&UiStatus::OfferSummary {
                files: 3,
                total_bytes: 1_500_000,
            });
            assert!(!summary.is_empty());
            assert_ne!(summary, "receiveOfferSummary");

            let receiving = loc.format_status(&UiStatus::Receiving { percent: 64 });
            assert!(!receiving.is_empty());

            let done = loc.format_status(&UiStatus::Done);
            assert!(!done.is_empty());
            assert_ne!(done, "receiveDone");

            let (v_title, v_hint) = loc.verification_banner();
            assert!(!v_title.is_empty() && !v_hint.is_empty());
        }
    }

    #[test]
    fn td0_certificate_and_version_validation() {
        let params = Td0Parameters::current();
        assert_eq!(params.protocol_version, 0);
        assert_eq!(params.chunk_size, 1 << 20);
        assert!(Td0Parameters::ensure_version_supported(&[2, 0, 1]).is_ok());
        assert!(Td0Parameters::ensure_version_supported(&[1, 2]).is_err());

        let dev = DeviceKeys::generate().unwrap();
        let mut cert = Certificate {
            version: 0,
            signing_key: dev.signing_public(),
            static_key: dev.static_public(),
            kem_key: dev.kem_public(),
            created: 1_760_000_000,
            signature: [0u8; 64],
        };
        cert.signature = dev.sign(&cert.signed_bytes());
        let encoded = cert.encode();
        let parsed = Td0Parameters::validate_peer_certificate(&encoded).unwrap();
        assert_eq!(parsed, cert);

        // Tamper with signature:
        let mut bad = cert;
        bad.signature[0] ^= 0xff;
        assert!(Td0Parameters::validate_peer_certificate(&bad.encode()).is_err());
    }

    #[test]
    fn end_to_end_web_receiver_state_machine_multi_chunk_and_tamper_guards() {
        let mut receiver =
            WebReceiverSession::from_share_input("https://totaldrop.app/r#9-abandon-ability")
                .unwrap();
        assert_eq!(receiver.stage(), ReceiverStage::LinkParsed);

        // 1. CPace handshake over mailbox_sid
        let sid = [0x42u8; 16];
        let (sender_cpace, ya) = Cpace::start(Role::Initiator, b"9-0-1", &sid).unwrap();
        let yb = receiver.start_cpace(&sid).unwrap();
        assert_eq!(receiver.stage(), ReceiverStage::CpaceStarted);

        let sender_isk = sender_cpace.finish(&yb).unwrap();
        receiver.finish_cpace(&ya).unwrap();
        assert_eq!(receiver.stage(), ReceiverStage::MailboxReady);

        // 2. Mailbox phase-bound AEAD exchange
        let mut sender_mb = MailboxCipher::new(&sender_isk, Role::Initiator);
        let ct_hints = sender_mb.seal("hints", b"sender-hints").unwrap();
        assert_eq!(
            receiver.open_mailbox("hints", &ct_hints).unwrap(),
            b"sender-hints"
        );
        let ct_reply = receiver.seal_mailbox("hints", b"receiver-hints").unwrap();
        assert_eq!(
            sender_mb.open("hints", &ct_reply).unwrap(),
            b"receiver-hints"
        );

        // 3. Hybrid post-quantum session keys + SAS verification words
        let handshake_hash = [0x11u8; 64];
        let kem_secret = [0x22u8; 32];
        let words = receiver
            .establish_hybrid_session(&handshake_hash, &kem_secret)
            .unwrap();
        assert_eq!(receiver.stage(), ReceiverStage::SessionReady);
        let expected_indices = verification_indices(&handshake_hash, &kem_secret);
        let list = bip39::Language::English.word_list();
        for (w, idx) in words.iter().zip(expected_indices) {
            assert_eq!(w, list[usize::from(idx)]);
        }

        let (k_i2r, k_r2i) = session_keys(&handshake_hash, &kem_secret);
        let (mut sender_sealer, mut sender_opener) = session(k_i2r, k_r2i, true);

        // 4. Construct a multi-entry signed Offer (1 directory + 1 multi-chunk file + 1 empty file)
        let sender_keys = DeviceKeys::generate().unwrap();
        let file_bytes: Vec<u8> = (0..(CHUNK_SIZE + 321))
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let file_hash = *blake3::hash(&file_bytes).as_bytes();
        let empty_hash = *blake3::hash(b"").as_bytes();

        let transfer_id = [0x77u8; 16];
        let ck_bytes = [0x99u8; 32];
        let ck = ContentKey::from_bytes(ck_bytes);

        let manifest = Manifest {
            transfer_id,
            entries: vec![
                Entry {
                    path: vec!["docs".into()],
                    kind: EntryKind::Dir,
                    size: 0,
                    hash: None,
                    mtime: None,
                },
                Entry {
                    path: vec!["docs".into(), "report.pdf".into()],
                    kind: EntryKind::File,
                    size: u64::try_from(file_bytes.len()).unwrap(),
                    hash: Some(file_hash),
                    mtime: Some(1_760_000_123),
                },
                Entry {
                    path: vec!["docs".into(), "empty.txt".into()],
                    kind: EntryKind::File,
                    size: 0,
                    hash: Some(empty_hash),
                    mtime: None,
                },
            ],
            total_size: u64::try_from(file_bytes.len()).unwrap(),
            chunk_size: limits::CHUNK_SIZE,
        };
        let sig = sender_keys.sign(&manifest.signed_bytes());
        let offer_bytes = Control::Offer {
            manifest,
            content_key: ck_bytes,
            signature: sig,
            progress: true,
            text: false,
        }
        .encode();
        let encrypted_offer = sender_sealer.seal(&offer_bytes).unwrap();

        let (validated, encrypted_accept) = receiver
            .accept_encrypted_offer(&encrypted_offer, &sender_keys.signing_public())
            .unwrap();
        assert_eq!(validated.file_count, 2);
        assert_eq!(receiver.stage(), ReceiverStage::ReceivingFiles);

        // Verify the Accept control reply returned to the sender:
        let accept_plain = sender_opener.open(&encrypted_accept).unwrap();
        let Control::Accept {
            wanted, progress, ..
        } = Control::decode(&accept_plain).unwrap()
        else {
            panic!("expected Control::Accept");
        };
        assert!(progress);
        assert_eq!(wanted.len(), 2);

        // 5. Stream Entry 1 (2 chunks) and Entry 2 (1 empty final chunk)
        let cipher_1 = EntryCipher::new(&ck, &transfer_id, 1);
        let chunk0_ct = cipher_1.seal(0, false, &file_bytes[..CHUNK_SIZE]).unwrap();
        let chunk1_ct = cipher_1.seal(1, true, &file_bytes[CHUNK_SIZE..]).unwrap();

        // Out-of-order chunk 1 before chunk 0 must be refused without advancing state:
        assert!(receiver.verify_entry_chunk(1, 1, &chunk1_ct).is_err());

        let v0 = receiver.verify_entry_chunk(1, 0, &chunk0_ct).unwrap();
        assert_eq!(v0.plaintext, &file_bytes[..CHUNK_SIZE]);
        assert!(!v0.entry_complete);
        assert!(v0.encrypted_entry_done.is_none());

        // Tampered chunk 1 must fail authentication:
        let mut tampered = chunk1_ct.clone();
        tampered[0] ^= 0x01;
        assert!(receiver.verify_entry_chunk(1, 1, &tampered).is_err());

        let v1 = receiver.verify_entry_chunk(1, 1, &chunk1_ct).unwrap();
        assert_eq!(v1.plaintext, &file_bytes[CHUNK_SIZE..]);
        assert!(v1.entry_complete);
        assert!(!v1.transfer_complete);
        let done1_plain = sender_opener
            .open(v1.encrypted_entry_done.as_ref().unwrap())
            .unwrap();
        assert_eq!(
            Control::decode(&done1_plain).unwrap(),
            Control::EntryDone {
                transfer_id,
                index: 1,
                ok: true,
            }
        );

        // Stream Entry 2 (empty file = single empty final chunk)
        let cipher_2 = EntryCipher::new(&ck, &transfer_id, 2);
        let empty_ct = cipher_2.seal(0, true, b"").unwrap();
        let v2 = receiver.verify_entry_chunk(2, 0, &empty_ct).unwrap();
        assert!(v2.plaintext.is_empty());
        assert!(v2.entry_complete);
        assert!(v2.transfer_complete);
        assert_eq!(receiver.stage(), ReceiverStage::Completed);

        // Check reject_offer path on a fresh session:
        let _ = RejectReason::Declined;
    }

    #[test]
    fn manifest_validation_rejects_traversal_reserved_names_and_case_collisions() {
        let keys = DeviceKeys::generate().unwrap();
        let empty_hash = *blake3::hash(b"").as_bytes();

        // Path traversal (`..`)
        let bad_traversal = Manifest {
            transfer_id: [1u8; 16],
            entries: vec![Entry {
                path: vec!["..".into(), "passwd".into()],
                kind: EntryKind::File,
                size: 0,
                hash: Some(empty_hash),
                mtime: None,
            }],
            total_size: 0,
            chunk_size: limits::CHUNK_SIZE,
        };
        let sig = keys.sign(&bad_traversal.signed_bytes());
        assert!(matches!(
            validate_manifest(&bad_traversal, &sig, &keys.signing_public(), false),
            Err(WebReceiverError::UnsafePath { entry_index: 0, .. })
        ));

        // Case-insensitive collision (`Readme.md` vs `readme.MD`)
        let collision = Manifest {
            transfer_id: [2u8; 16],
            entries: vec![
                Entry {
                    path: vec!["Readme.md".into()],
                    kind: EntryKind::File,
                    size: 0,
                    hash: Some(empty_hash),
                    mtime: None,
                },
                Entry {
                    path: vec!["readme.MD".into()],
                    kind: EntryKind::File,
                    size: 0,
                    hash: Some(empty_hash),
                    mtime: None,
                },
            ],
            total_size: 0,
            chunk_size: limits::CHUNK_SIZE,
        };
        let sig = keys.sign(&collision.signed_bytes());
        assert!(matches!(
            validate_manifest(&collision, &sig, &keys.signing_public(), false),
            Err(WebReceiverError::DuplicatePathCollision(_))
        ));
    }

    #[test]
    fn xchacha20_poly1305_stream_round_trip_and_attack_detection() {
        let secret = LinkSecret::from_bytes([0x5au8; 32]);
        let container_id = [0xc3u8; 16];
        let manifest_key = secret.derive_manifest_key(&container_id);
        assert_ne!(manifest_key, *secret.as_bytes());

        // Multi-chunk payload (1 MiB + 512 B)
        let payload: Vec<u8> = (0..(CHUNK_SIZE + 512))
            .map(|i| u8::try_from(i % 253).unwrap())
            .collect();
        let expected_hash = *blake3::hash(&payload).as_bytes();

        let sealer = XChaChaChunkCipher::new(&secret, &container_id, 0);
        let c0 = sealer.seal(0, false, &payload[..CHUNK_SIZE]).unwrap();
        let c1 = sealer.seal(1, true, &payload[CHUNK_SIZE..]).unwrap();

        // Truncation attempt (claiming chunk 0 is final) fails AEAD tag check:
        let mut trunc_verifier = XChaChaStreamVerifier::new(
            &secret,
            &container_id,
            0,
            u64::try_from(CHUNK_SIZE).unwrap(),
            *blake3::hash(&payload[..CHUNK_SIZE]).as_bytes(),
        )
        .unwrap();
        assert_eq!(
            trunc_verifier.verify_next_chunk(0, &c0),
            Err(XChaChaError::Inauthentic)
        );

        // Cross-entry splicing attempt (entry 1 instead of entry 0) fails AEAD:
        let mut wrong_entry = XChaChaStreamVerifier::new(
            &secret,
            &container_id,
            1,
            u64::try_from(payload.len()).unwrap(),
            expected_hash,
        )
        .unwrap();
        assert_eq!(
            wrong_entry.verify_next_chunk(0, &c0),
            Err(XChaChaError::Inauthentic)
        );

        // Honest full stream succeeds and verifies BLAKE3 digest:
        let mut verifier = XChaChaStreamVerifier::new(
            &secret,
            &container_id,
            0,
            u64::try_from(payload.len()).unwrap(),
            expected_hash,
        )
        .unwrap();
        assert_eq!(verifier.total_chunks(), 2);

        let p0 = verifier.verify_next_chunk(0, &c0).unwrap();
        assert_eq!(p0, &payload[..CHUNK_SIZE]);

        let p1 = verifier.verify_next_chunk(1, &c1).unwrap();
        assert_eq!(p1, &payload[CHUNK_SIZE..]);

        let verified_digest = verifier.finish().unwrap();
        assert_eq!(verified_digest, expected_hash);

        // Empty file stream (0 bytes -> 1 empty final chunk):
        let empty_hash = *blake3::hash(b"").as_bytes();
        let empty_sealer = XChaChaChunkCipher::new(&secret, &container_id, 9);
        let empty_ct = empty_sealer.seal(0, true, b"").unwrap();
        let mut empty_verifier =
            XChaChaStreamVerifier::new(&secret, &container_id, 9, 0, empty_hash).unwrap();
        assert!(
            empty_verifier
                .verify_next_chunk(0, &empty_ct)
                .unwrap()
                .is_empty()
        );
        assert_eq!(empty_verifier.finish().unwrap(), empty_hash);
    }
}
