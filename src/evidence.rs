// SPDX-License-Identifier: Apache-2.0

//! Evidence types — the breadcrumbs a diagnosis emits to justify itself.
//!
//! Every [`crate::report::Diagnosis`] carries a `Vec<Evidence>`. Each
//! [`Evidence`] is one short human-readable observation paired with an
//! optional [`Pointer`] to the source the observation came from (a
//! request field, a response header, a specific log line). The CLI's
//! `explain` subcommand surfaces the pointers so a support engineer
//! can audit a diagnosis line by line.
//!
//! Keeping evidence and pointers as plain owned strings (no borrowed
//! slices, no `Cow`) makes [`crate::report::Report`] cheap to clone,
//! `Send + Sync`, and trivially serialisable as JSON.

use serde::{Deserialize, Serialize};

/// One observation that supports a diagnosis.
///
/// `message` is the human-readable claim; `pointer`, when present,
/// names the source the claim was derived from. Both fields are owned
/// strings so an `Evidence` can survive being moved across rule
/// boundaries without lifetime gymnastics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evidence {
    /// Human-readable observation. Should be a single sentence;
    /// rendered as a bullet point in the report's `EVIDENCE:` block.
    pub message: String,

    /// Where the observation came from. `None` is allowed for
    /// statements derived from multiple sources at once (e.g.
    /// "tolerance is 300 s; observed drift 4800 s") — these are
    /// labelled `computed` in practice.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<Pointer>,
}

/// Reference to the source of an [`Evidence`].
///
/// `source` is a logical path into the case (`"request.headers.authorization"`,
/// `"response.status"`, `"server.log"`, or the literal `"computed"` for
/// values the rule produced rather than read). `line` is a 1-indexed
/// line number into a log file when relevant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pointer {
    /// Logical source of the value, e.g. `"request.headers.authorization"`,
    /// `"response.status"`, `"server.log"`, `"case.context.webhook.tolerance_seconds"`,
    /// or `"computed"` for values the rule produced rather than read.
    pub source: String,

    /// Optional 1-indexed line number when `source` is a log file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Evidence {
    /// Construct an evidence item with no source pointer.
    ///
    /// Use this for derived statements that do not refer to a specific
    /// case field — for example, summary lines computed by the rule
    /// itself ("tolerance is 300 s; observed drift 4800 s").
    ///
    /// # Examples
    ///
    /// ```
    /// use api_debug_lab::Evidence;
    /// let e = Evidence::new("Response status 401 Unauthorized");
    /// assert!(e.pointer.is_none());
    /// ```
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            pointer: None,
        }
    }

    /// Construct an evidence item that names a logical source but no
    /// specific line.
    ///
    /// Most rule-emitted evidence uses this form. The `source` is a
    /// logical path into the case (see [`Pointer::source`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use api_debug_lab::Evidence;
    /// let e = Evidence::with("Authorization header absent", "request.headers.authorization");
    /// assert_eq!(e.pointer.unwrap().source, "request.headers.authorization");
    /// ```
    pub fn with(message: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            pointer: Some(Pointer {
                source: source.into(),
                line: None,
            }),
        }
    }

    /// Construct an evidence item that points at a specific 1-indexed
    /// line of a log file.
    ///
    /// This is the form used when a rule has identified a single log
    /// line as the smoking gun. The CLI's `explain` subcommand renders
    /// these as `[server.log:42] message`.
    ///
    /// # Examples
    ///
    /// ```
    /// use api_debug_lab::Evidence;
    /// let e = Evidence::at_line("timeout entry", "server.log", 3);
    /// assert_eq!(e.pointer.unwrap().line, Some(3));
    /// ```
    pub fn at_line(message: impl Into<String>, source: impl Into<String>, line: u32) -> Self {
        Self {
            message: message.into(),
            pointer: Some(Pointer {
                source: source.into(),
                line: Some(line),
            }),
        }
    }
}
