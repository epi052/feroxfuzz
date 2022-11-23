//! subscribable events for introspection into some of the more opaque parts of the fuzzer
//!
//! Custom events can be defined by simply adding a new type to the [`SharedState`]'s
//! `events` map. The [`EventPublisher`] trait provides a simple interface for subscribing
//! to and notifying listeners of events.
//!
//! [`SharedState`]: crate::state::SharedState
//!
//! # Examples
//!
//! Subscribe to the [`ModifiedCorpus`] event:
//!
//! ```
//! use feroxfuzz::events::{EventPublisher, ModifiedCorpus};
//! use feroxfuzz::state::SharedState;
//! use feroxfuzz::corpora::Wordlist;
//!
//! let wordlist = Wordlist::with_words(["test"])
//!     .name("words")
//!     .build();
//!
//! let mut state = SharedState::with_corpus(wordlist);
//!
//! let listener_id = state.events().subscribe(|event: ModifiedCorpus| {
//!    println!("{:?}", event);
//! });
//!
//! // ... fuzzer calls state.events().notify(ModifiedCorpus { .. }) ...
//!
//! // unsubscribe from the event
//! state.events().unsubscribe::<ModifiedCorpus>(listener_id.unwrap());
//!
//! assert!(!state.events().has_listeners::<ModifiedCorpus>());
//! ```
//!
//! Define a custom event
//!
//! ```
//! use feroxfuzz::events::{EventPublisher, Publisher};
//! use feroxfuzz::state::SharedState;
//! use feroxfuzz::corpora::Wordlist;
//!
//! let wordlist = Wordlist::with_words(["test"])
//!     .name("words")
//!     .build();
//!
//! let mut state = SharedState::with_corpus(wordlist);
//!
//! // define a custom event (must be Clone)
//! #[derive(Clone)]
//! struct CustomEvent {
//!    message: String,
//! }
//!
//! // subscribe to the event
//! let listener_id = state.events().subscribe(|event: CustomEvent| {
//!    assert_eq!(event.message, "hello world");
//! });
//!
//! // notify listeners of the event
//! state.events().notify(CustomEvent {
//!   message: "hello world".to_string(),
//! });
//!
//! // unsubscribe from the event
//! state.events().unsubscribe::<CustomEvent>(listener_id.unwrap());
//!
//! assert!(!state.events().has_listeners::<CustomEvent>());
//! ```

mod publisher;

use crate::input::Data;
use crate::requests::RequestId;
use crate::std_ext::ops::LogicOperation;

pub use self::publisher::{EventPublisher, Publisher};

/// This event is emitted when an [`Action::AddToCorpus`] is performed
/// by the fuzzer.
///
/// [`Action::AddToCorpus`]: crate::actions::Action::AddToCorpus
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModifiedCorpus {
    /// The request ID of the request that triggered corpus modification
    pub id: RequestId,

    /// the name of the corpus that was modified
    pub corpus: String,

    /// the way in which the corpus was modified (currently only additions are
    /// performed)
    pub action: &'static str,

    /// the fuzzable field that triggered the modification
    pub from_field: &'static str,

    /// the data that was added to the corpus
    pub entry: Data,
}

/// This event is emitted when a [`Request`] is discarded prior to
/// being sent to the target.
///
/// [`Request`]: crate::requests::Request
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscardedRequest {
    /// discarded request's [`RequestId`]
    pub id: RequestId,
}

/// This event is emitted when a [`Request`] is retained and allowed to
/// be sent to the target.
///
/// [`Request`]: crate::requests::Request
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeptRequest {
    /// discarded request's [`RequestId`]
    pub id: RequestId,
}

/// This event is emitted when a [`Response`] is discarded after
/// being received from the target.
///
/// [`Response`]: crate::responses::Response
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscardedResponse {
    /// discarded respone's [`RequestId`]
    pub id: RequestId,
}

/// This event is emitted when a [`Response`] is retained after being
/// received from the target.
///
/// [`Response`]: crate::responses::Response
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeptResponse {
    /// discarded response's [`RequestId`]
    pub id: RequestId,
}

/// This event is emitted when a fuzzer enters its fuzzing loop via the
/// [`Fuzzer::fuzz`] method.
///
/// [`Fuzzer::fuzz`]: crate::fuzzers::AsyncFuzzing::fuzz
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuzzForever;

/// This event is emitted when a fuzzer enters its fuzzing loop via the
/// [`Fuzzer::fuzz_n_iterations`] method.
///
/// [`Fuzzer::fuzz_n_iterations`]: crate::fuzzers::AsyncFuzzing::fuzz_n_iterations
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuzzNTimes {
    /// The number of iterations for which the fuzzer will iterate over the corpus
    pub iterations: usize,
}

/// This event is emitted when a fuzzer enters its fuzzing loop via the
/// [`Fuzzer::fuzz_once`] method. If the fuzzer was started with [`Fuzzer::fuzz_n_iterations`]
/// or [`Fuzzer::fuzz`], this event will be emitted once per iteration.
///
/// [`Fuzzer::fuzz_once`]: crate::fuzzers::AsyncFuzzing::fuzz_once
/// [`Fuzzer::fuzz_n_iterations`]: crate::fuzzers::AsyncFuzzing::fuzz_n_iterations
/// [`Fuzzer::fuzz`]: crate::fuzzers::AsyncFuzzing::fuzz
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FuzzOnce {
    /// the number of threads the fuzzer is configured to use
    pub threads: usize,

    /// how pre-send [`Action`]s are joined logically
    ///
    /// [`Action`]: crate::actions::Action
    pub pre_send_logic: LogicOperation,

    /// how post-send [`Action`]s are joined logically
    ///
    /// [`Action`]: crate::actions::Action
    pub post_send_logic: LogicOperation,
}

/// This event is emitted when a fuzzer exits the fuzzing loop. This can happen
/// when the fuzzer has iterated over the entire corpus for the specified number
/// of times, or when the fuzzer exits early due to an [`Action::StopFuzzing`]
///
/// [`Action::StopFuzzing`]: crate::actions::Action::StopFuzzing
#[derive(Copy, Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StopFuzzing;

/// This event is fired when a [`Request`] is mutated by a [`Mutator`]. It contains the
/// [`RequestId`] of the mutated request and the name of the field that was mutated.
///
/// # Note
///
/// This event is useful for debugging purposes. It is not recommended to use this event
/// where speed is a concern. Each mutation will fire this event, and they're in the
/// critical path of the fuzzer.
///
/// Additionally, the `mutation` field of this event is a [`Data`] variant, and must
/// be cloned. This can be expensive for large inputs.
///
/// [`Mutator`]: crate::mutators::Mutator
/// [`Request`]: crate::requests::Request
#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mutation {
    /// mutated request's [`RequestId`]
    pub id: RequestId,

    /// name of the mutated field, i.e. "scheme", "host", "path", etc.
    pub field: &'static str,

    /// the mutated value
    pub entry: Data,
}
