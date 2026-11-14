// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
//! Strict share-URL and wormhole transfer-code parsing for browser receivers.

use totaldrop_proto::{
    CodeError, MAX_LINK_BYTES, TransferCode, ascii_digits, strip_invisible_format,
};

/// How a transfer code reached the browser receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// `https://totaldrop.app/r#<code_or_escaped>` URL fragment.
    HttpsFragment,
    /// `http://totaldrop.app/r#<code_or_escaped>` URL fragment.
    HttpFragment,
    /// `totaldrop://r/<code>` or `totaldrop:<code>` custom URI scheme.
    CustomScheme,
    /// Bare transfer code entered or pasted directly (for example `7-harbor-rocket`).
    BareCode,
}

/// Errors returned when parsing a browser share URL, URI fragment, or bare code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkParseError {
    /// Input exceeded [`MAX_LINK_BYTES`] (1024 bytes) and was refused unread.
    TooLong,
    /// Input carried a URL prefix, query string, or trailing text rejected by
    /// [`TransferCode::from_link`].
    InvalidLink,
    /// Bare code input failed [`TransferCode::parse`].
    InvalidCode(CodeError),
}

impl core::fmt::Display for LinkParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLong => write!(f, "share link exceeds {MAX_LINK_BYTES} bytes"),
            Self::InvalidLink => f.write_str("input is not a valid TotalDrop receive link"),
            Self::InvalidCode(err) => core::fmt::Display::fmt(err, f),
        }
    }
}

impl std::error::Error for LinkParseError {}

/// A validated TotalDrop transfer code together with how it was supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTransferLink {
    code: TransferCode,
    kind: LinkKind,
}

impl ParsedTransferLink {
    /// Parse a full share link (`https://totaldrop.app/r#…`, `totaldrop://r/…`),
    /// a bare URL hash fragment (`#7-harbor-rocket`), or a typed code strictly
    /// via [`TransferCode::from_link`].
    ///
    /// Inputs longer than [`MAX_LINK_BYTES`] are rejected immediately, invisible
    /// bidirectional/format marks are stripped prior to prefix matching, and
    /// `%XX` escapes are decoded at most once.
    pub fn parse_link_or_fragment(input: &str) -> Result<Self, LinkParseError> {
        if input.len() > MAX_LINK_BYTES {
            return Err(LinkParseError::TooLong);
        }
        let cleaned = strip_invisible_format(input);
        let trimmed = cleaned.trim();

        // A browser reading `window.location.hash` obtains `#7-harbor-rocket`.
        // Prefix it as the canonical HTTPS receive URL so `TransferCode::from_link`
        // applies its exact single-pass `%XX` decoding and trailing-garbage checks.
        if let Some(fragment) = trimmed.strip_prefix('#') {
            if fragment.is_empty() {
                return Err(LinkParseError::InvalidLink);
            }
            let synthetic = format!("https://totaldrop.app/r#{fragment}");
            let code = TransferCode::from_link(&synthetic).ok_or(LinkParseError::InvalidLink)?;
            return Ok(Self {
                code,
                kind: LinkKind::HttpsFragment,
            });
        }

        let kind = classify_prefix(trimmed);
        let code = TransferCode::from_link(input).ok_or(LinkParseError::InvalidLink)?;
        Ok(Self { code, kind })
    }

    /// Parse a bare wormhole transfer code directly via [`TransferCode::parse`],
    /// returning the specific [`CodeError`] when the nameplate or word list check
    /// fails.
    pub fn parse_bare_code(input: &str) -> Result<Self, LinkParseError> {
        if input.len() > MAX_LINK_BYTES {
            return Err(LinkParseError::TooLong);
        }
        let code = TransferCode::parse(input).map_err(LinkParseError::InvalidCode)?;
        Ok(Self {
            code,
            kind: LinkKind::BareCode,
        })
    }

    /// Extract a transfer code embedded inside a longer pasted share message
    /// (for example localized share text with `U+2068`…`U+2069` RTL isolates)
    /// using [`TransferCode::find`].
    #[must_use]
    pub fn find_in_share_text(text: &str) -> Option<Self> {
        if text.len() > MAX_LINK_BYTES {
            return None;
        }
        TransferCode::find(text).map(|code| Self {
            code,
            kind: LinkKind::BareCode,
        })
    }

    /// Underlying [`TransferCode`].
    #[must_use]
    pub fn code(&self) -> &TransferCode {
        &self.code
    }

    /// How the code was supplied to the parser.
    #[must_use]
    pub fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Rendezvous nameplate number (`1..=u32::MAX`).
    #[must_use]
    pub fn nameplate(&self) -> u32 {
        self.code.nameplate()
    }

    /// Canonical index-based ASCII string passed as `PRS` into CPace
    /// (for example `"7-840-1499"`). Always ASCII regardless of input script.
    #[must_use]
    pub fn canonical_cpace_prs(&self) -> String {
        self.code.canonical()
    }

    /// Human-readable English transfer code (`"7-harbor-rocket"`).
    #[must_use]
    pub fn display_english(&self) -> String {
        self.code.to_english()
    }

    /// Canonical HTTPS web receive link keeping the code inside the `#`
    /// URL fragment so browsers never transmit the code in HTTP requests.
    #[must_use]
    pub fn to_https_link(&self) -> String {
        format!("https://totaldrop.app/r#{}", self.code.to_english())
    }

    /// Normalize user-typed text by stripping invisible format marks and
    /// converting Arabic-Indic / Extended Arabic-Indic digits to ASCII.
    #[must_use]
    pub fn sanitize_code_input(raw: &str) -> String {
        ascii_digits(&strip_invisible_format(raw))
    }
}

fn classify_prefix(trimmed: &str) -> LinkKind {
    if trimmed.starts_with("https://totaldrop.app/r#") {
        LinkKind::HttpsFragment
    } else if trimmed.starts_with("http://totaldrop.app/r#") {
        LinkKind::HttpFragment
    } else if trimmed.starts_with("totaldrop://r/") || trimmed.starts_with("totaldrop:") {
        LinkKind::CustomScheme
    } else {
        LinkKind::BareCode
    }
}
