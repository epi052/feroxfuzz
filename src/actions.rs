//! represents an action that should be performed, typically in response to some event
#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::corpora::CorpusItemType;

/// all possible actions
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Action {
    /// when used in a pre-send context, retain the current [`Request`], if
    /// used in a post-send context, retain the current [`Response`]
    ///
    /// [`Request`]: crate::requests::Request
    /// [`Response`]: crate::responses::Response
    Keep,

    /// when used in a pre-send context, ignore the current [`Request`], if
    /// used in a post-send context, ignore the current [`Response`]
    ///
    /// [`Request`]: crate::requests::Request
    /// [`Response`]: crate::responses::Response
    Discard,

    /// add the current mutated field(s) to the [`Corpus`] associated
    /// with the given `name`.
    ///
    /// the [`FlowControl`] passed to the `AddToCorpus` action is used to
    /// embed a `Keep` or `Discard` action that will dictate whether the
    /// mutated request or response should be allowed to be processed
    /// any further, after being added to the corpus.
    ///
    /// said another way: when the action is `AddToCorpus`, the current
    /// request's fuzzable fields will (unconditionally) be added to the
    /// named corpus. If the `FlowControl` is `Keep`, the request will continue
    /// in the fuzz loop, and if the `FlowControl` is `Discard`, the request
    /// won't progress beyond being added to the corpus. In either case, the
    /// resulting `Action` will still be passed to any configured
    /// [`Processor`]s.
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    /// [`Processor`]: crate::processors::Processor
    AddToCorpus(String, CorpusItemType, FlowControl),

    /// break out of the current fuzz loop; no more iterations other than
    /// what's already in flight will be performed
    StopFuzzing,
}

/// analogous to the [`Action::Keep`], [`Action::Discard`], and [`Action::StopFuzzing`] variants
///
/// used when the [`Action`] isn't a flow control directive itself
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum FlowControl {
    /// when used in a pre-send context, retain the current [`Request`], if
    /// used in a post-send context, retain the current [`Response`]
    ///
    /// [`Request`]: crate::requests::Request
    /// [`Response`]: crate::responses::Response
    Keep,

    /// when used in a pre-send context, ignore the current [`Request`], if
    /// used in a post-send context, ignore the current [`Response`]
    ///
    /// [`Request`]: crate::requests::Request
    /// [`Response`]: crate::responses::Response
    Discard,

    /// break out of the current fuzz loop; no more iterations other than
    /// what's already in flight will be performed
    StopFuzzing,
}
