// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Browser UI localization across all 35 supported TotalDrop languages via
//! `totaldrop-l10n`.

use totaldrop_l10n::{Arg, Domain, Strings, available, locale};

/// High-level browser receiver UI phase used to render localized status lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiStatus<'a> {
    /// Connecting to rendezvous / establishing the encrypted channel.
    Connecting,
    /// Displaying an incoming file offer summary (`files` count and byte `size`).
    OfferSummary {
        /// Number of files offered.
        files: u64,
        /// Total transfer size in bytes.
        total_bytes: u64,
    },
    /// Actively receiving and verifying encrypted chunks (`0..=100`).
    Receiving {
        /// Transfer completion percentage (`0..=100`).
        percent: u64,
    },
    /// All files arrived and passed authentication and `BLAKE3` verification.
    Done,
    /// A text-only transfer arrived and passed verification.
    TextDone,
    /// Receiver declined the offer.
    Declined,
    /// Share code syntax was invalid.
    InvalidCode,
    /// Key confirmation failed (wrong code or active interception).
    WrongCode,
    /// Rendezvous nameplate was not active or expired.
    CodeNotInUse,
    /// Sender's offer violated a protocol safety rule.
    InvalidOffer,
    /// Peer disconnected before completion.
    PeerLeft,
    /// Formatted share message containing `code`.
    ShareText {
        /// English transfer code (`7-harbor-rocket`).
        code: &'a str,
    },
}

/// Browser-ready localizer negotiated from `navigator.languages` preferences.
#[derive(Debug)]
pub struct WebLocalizer {
    strings: Strings,
}

impl WebLocalizer {
    /// Negotiate the best language from ordered BCP-47 tags (for example
    /// `navigator.languages` in a browser) with optional regional number
    /// formatting. Falls back to English (`"en"`) when no preference matches.
    #[must_use]
    pub fn from_browser_languages(preferences: &[&str], numeric_locale: Option<&str>) -> Self {
        let parsed: Vec<_> = preferences
            .iter()
            .filter_map(|tag| locale::parse(tag))
            .collect();
        let numeric = numeric_locale.and_then(locale::parse);
        Self {
            strings: Strings::new(Domain::App, &parsed, numeric.as_ref()),
        }
    }

    /// Return every BCP-47 locale tag compiled into the `App` domain catalog
    /// (covering all 35 TotalDrop languages and script/regional variants).
    #[must_use]
    pub fn supported_locales() -> Vec<String> {
        available(Domain::App)
    }

    /// Negotiated BCP-47 language tag (for example `"tr"`, `"ar"`, `"pt-BR"`).
    #[must_use]
    pub fn tag(&self) -> &str {
        self.strings.tag()
    }

    /// Whether the negotiated language uses a right-to-left (`dir="rtl"`)
    /// document layout.
    #[must_use]
    pub fn is_rtl(&self) -> bool {
        self.strings.is_rtl()
    }

    /// HTML `dir` attribute value (`"rtl"` or `"ltr"`) for the negotiated locale.
    #[must_use]
    pub fn html_dir(&self) -> &'static str {
        if self.strings.is_rtl() { "rtl" } else { "ltr" }
    }

    /// Whether any non-critical string in this locale comes from an unreviewed
    /// draft translation (safety-critical keys automatically stay in English).
    #[must_use]
    pub fn has_unreviewed_drafts(&self) -> bool {
        self.strings.is_draft()
    }

    /// Format a byte count in localized SI units (`"1.5 MB"`, `"1,5 MB"`).
    #[must_use]
    pub fn format_bytes(&self, bytes: u64) -> String {
        self.strings.bytes(bytes)
    }

    /// Localized screen title for the Web Receiver (`receiveTitle`).
    #[must_use]
    pub fn receive_title(&self) -> String {
        self.strings.get("receiveTitle", &[])
    }

    /// Localized verification words heading and safety warning
    /// (`verificationTitle`, `verificationHint`).
    #[must_use]
    pub fn verification_banner(&self) -> (String, String) {
        (
            self.strings.get("verificationTitle", &[]),
            self.strings.get("verificationHint", &[]),
        )
    }

    /// Format a [`UiStatus`] into localized text for the negotiated language.
    #[must_use]
    pub fn format_status(&self, status: &UiStatus<'_>) -> String {
        match status {
            UiStatus::Connecting => self.strings.get("receiveConnecting", &[]),
            UiStatus::OfferSummary { files, total_bytes } => {
                let size = self.strings.bytes(*total_bytes);
                self.strings.get(
                    "receiveOfferSummary",
                    &[("files", Arg::Count(*files)), ("size", Arg::Text(&size))],
                )
            }
            UiStatus::Receiving { percent } => {
                let capped = (*percent).min(100);
                let pct = self
                    .strings
                    .get("progressPercent", &[("percent", Arg::Count(capped))]);
                let label = self.strings.get("receiveReceiving", &[]);
                format!("{label} · {pct}")
            }
            UiStatus::Done => self.strings.get("receiveDone", &[]),
            UiStatus::TextDone => self.strings.get("receiveTextDone", &[]),
            UiStatus::Declined => self.strings.get("receiveDeclined", &[]),
            UiStatus::InvalidCode => self.strings.get("receiveCodeInvalid", &[]),
            UiStatus::WrongCode => self.strings.get("errorWrongCode", &[]),
            UiStatus::CodeNotInUse => self.strings.get("errorCodeNotInUse", &[]),
            UiStatus::InvalidOffer => self.strings.get("errorInvalidOffer", &[]),
            UiStatus::PeerLeft => self.strings.get("errorPeerLeft", &[]),
            UiStatus::ShareText { code } => self
                .strings
                .get("sendShareText", &[("code", Arg::Text(code))]),
        }
    }
}
