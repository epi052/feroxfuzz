//! Custom error-type definitions
#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize
use std::str::Utf8Error;

#[cfg(feature = "reqwest")]
use reqwest;
use thiserror::Error;
use url::ParseError;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::input::Data;

/// primary error-type for the feroxfuzz library
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FeroxFuzzError {
    /// Represents a failure to open a file during corpus creation.
    #[error("The file `{path}` for corpus population couldn't be opened.")]
    CorpusFileOpenError {
        /// underlying source error-type
        source: std::io::Error,

        /// path to the file that couldn't be opened
        path: String,
    },

    /// Represents all other cases of `std::io::Error`.
    #[error(transparent)]
    IOError {
        /// underlying source error-type
        #[from]
        source: std::io::Error,
    },

    /// Represents a failure to parse the given string into a [`url::Url`](https://docs.rs/url/latest/url/struct.Url.html).
    #[error("The url `{url}` is invalid and couldn't be parsed.")]
    InvalidUrl {
        /// underlying source error-type
        source: ParseError,

        /// the url that couldn't be parsed
        url: String,
    },

    /// Represents a failure to parse the given string into a key:value pair
    #[error("Could not parse `{}`: {reason}", Data::from(key_value_pair.clone()))]
    KeyValueParseError {
        /// underlying reason for the parsing error
        reason: String,

        /// the key and value pair that couldn't be parsed
        key_value_pair: Vec<u8>,
    },

    /// Represents a failure to use a valid `ShouldFuzz` directive
    #[error("The ShouldFuzz variant `{directive}` is invalid in this context")]
    InvalidDirective {
        /// the invalid directive
        directive: String,
    },

    /// Represents a failure to read the body of a `reqwest::Response` object
    #[cfg(feature = "reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
    #[error("Could not read the response body")]
    ResponseReadError {
        /// underlying source error-type
        #[from]
        source: reqwest::Error,
    },

    /// Represents a failure to generate a [`reqwest::Method`] from a set of bytes
    #[cfg(feature = "reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
    #[error("Could not parse the given http method `{method}`")]
    MethodParseError {
        /// the method that couldn't be parsed
        method: String,
    },

    /// Represents an invalid index passed to [`Corpus::get`]
    ///
    /// [`Corpus::get`]: crate::corpora::Corpus::get
    #[error("Requested entry at `{index}` could not be found in Corpus `{name}`")]
    CorpusEntryNotFound {
        /// the name of the corpus
        name: String,

        /// the index that couldn't be found
        index: usize,
    },

    /// Represents an invalid name passed to [`SharedState::corpus_by_name`]
    ///
    /// [`SharedState::corpus_by_name`]: crate::state::SharedState::corpus_by_name
    #[error("Requested Corpus named `{name}` could not be found")]
    CorpusNotFound {
        /// name of the requested corpus that couldn't be found
        name: String,
    },

    /// Represents an invalid name passed to [`SharedState::corpus_index_by_name`]
    ///
    /// [`SharedState::corpus_index_by_name`]: crate::state::SharedState::corpus_index_by_name
    #[error("Requested index associated with Corpus named `{name}` could not be found")]
    CorpusIndexNotFound {
        /// name of the requested corpus index that couldn't be found
        name: String,
    },

    /// Represents a failure to generate a [`reqwest::Version`] from a set of bytes
    #[cfg(feature = "reqwest")]
    #[cfg_attr(docsrs, doc(cfg(feature = "reqwest")))]
    #[error(
        "Could not parse the given http version `{version}`. For now, versions must be syntactically correct."
    )]
    InvalidVersionError {
        /// the version that couldn't be parsed
        version: String,
    },

    /// Represents a failure to parse an object into JSON
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    #[error("Could not convert the given object to JSON")]
    JSONParseError {
        /// underlying source error-type
        #[from]
        source: serde_json::Error,
    },

    /// Represents an empty [`Corpus`], which isn't allowed
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    #[error("No entries were found in the Corpus `{name}`")]
    EmptyCorpus {
        /// name of the empty corpus
        name: String,
    },

    /// Represents an empty [`CorpusMap`], which isn't allowed
    ///
    /// [`CorpusMap`]: crate::corpora::CorpusMap
    #[error("No corpora were found in the CorpusMap")]
    EmptyCorpusMap,

    /// Represents an empty [`CorpusIndices`], which isn't allowed
    ///
    /// [`CorpusIndices`]: crate::corpora::CorpusIndices
    #[error("No indices were found in the CorpusIndices map")]
    EmptyCorpusIndices,

    /// Represents a failure to validate the given u16 as a proper status code.
    #[error("The status code `{status_code}` is invalid and couldn't be parsed.")]
    InvalidStatusCode {
        /// the status code that couldn't be parsed
        status_code: u16,
    },

    /// Represents a point at which the scheduler should stop retrieving indices
    #[error("Iteration has stopped")]
    IterationStopped,

    /// Represents a [`Request`] field that could not be parsed into a valid utf-8 &str
    ///
    /// [`Request`]: crate::requests::Request
    #[error("Could not parse bytes into valid utf-8 (required by &str)")]
    UnparsableData {
        /// underlying source error-type
        #[from]
        source: Utf8Error,
    },

    /// Represents an invalid parameter passed to some function or constructor
    #[error("Invalid parameter provided, {message}: {param}")]
    InvalidParameter {
        /// the failing parameter
        param: String,

        /// the associated message to help the user
        message: &'static str,
    },

    /// Represents a failed mutation of a [`Request`] object
    ///
    /// [`Request`]: crate::requests::Request
    #[error("Mutation failed")]
    FailedMutation {
        /// underlying source error-type
        source: libafl::Error,
    },

    /// Represents a failure encountered during sending a request / receiving a response
    #[error("An error occurred while sending the request: {kind:?} {message}")]
    RequestError {
        /// what category of error occurred
        kind: RequestErrorKind,

        /// the underlying error message
        message: String,
    },

    /// Represents a discarded request during asynchronous fuzzing
    ///
    /// Note: this is only used because of how the async fuzz_once loop
    /// is implemented. It is not intended to be used outside of the
    /// async fuzz_once loop.
    #[error("Discarded request based on user-provided criteria")]
    DiscardedRequest,

    /// Represents a recommended [`Action::StopFuzzing`] during asynchronous fuzzing
    ///
    /// Note: this is only used because of how the async fuzz_once loop
    /// is implemented. It is not intended to be used outside of the
    /// async fuzz_once loop.
    ///
    /// [`Action::StopFuzzing`]: crate::actions::Action::StopFuzzing
    #[error("Stopped fuzzing based on user-provided criteria")]
    FuzzingStopped,
}

/// Used to differentiate between different types of errors that occur when making requests.
///
/// That differentiation is then used internally to update the proper error counts in [`Statistics`]
///
/// [`Statistics`]: crate::statistics::Statistics
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum RequestErrorKind {
    /// Represents a failure to read a response body
    Body(Option<u16>),

    /// Represents a failure during client connection to target
    Connect(Option<u16>),

    /// Represents a failure to decode a response body
    Decode(Option<u16>),

    /// Represents a failure to related to redirection, i.e. too many redirects
    Redirect(Option<u16>),

    /// Represents a failure related to the request
    Request(Option<u16>),

    /// Represents a timeout during the request
    Timeout(Option<u16>),

    /// Represents an unexpected error
    #[default]
    Unknown,
}
