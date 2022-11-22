//! small collection of widely used core types and traits
//!
//! The goal in using the prelude is to reduce the number of imports
//! needed to (mostly) only those that have direct impact on the actual
//! implementation of a fuzzer.
//!
//! # Traits
//!
//! - [`HttpClient`] - exposes the `with_client` constructor
//! - [`Corpus`] - exposes the `add` method
//! - [`Response`] - exposes a plethora of methods on an implementing type (i.e. [`AsyncResponse`])
//! - [`Timed`] - exposes the `elapsed` method on implementing `Response` types
//! - [`Len`] - exposes the `len` method on implementing `Corpus` types
//! - [`Decider`] - exposes the `decide_with_request` and `decide_with_observers` methods on implementing `Decider` types
//! - [`AsInner`] - exposes the `inner` method on implementing types such as [`Data`]
//! - [`Fuzzer`] - exposes the `fuzz*` methods on implementing types such as [`AsyncFuzzer`]
//!
//! [`AsyncFuzzer`]: crate::fuzzers::AsyncFuzzer
//! [`AsyncResponse`]: crate::responses::AsyncResponse
//! [`Data`]: crate::input::Data
//! [`Corpus`]: crate::corpora::Corpus
//! [`Decider`]: crate::deciders::Decider
//! [`HttpClient`]: crate::client::HttpClient
//! [`Response`]: crate::responses::Response
//! [`Timed`]: crate::responses::Timed
//! [`AsInner`]: crate::std_ext::convert::AsInner
//! [`Fuzzer`]: crate::fuzzers::Fuzzer
//! [`Len`]: crate::std_ext::ops::Len
//!
//! # Structs & Enums
//!
//! While a bit more controversial, the types included here are
//! core aspects to any fuzzer and have no other alternatives
//! within the library. They are included here for convenience.
//!
//! - [`Data`] - the core input type
//! - [`Request`] - the core request type
//! - [`SharedState`] - the core fuzzer-state type
//! - [`Action`] - the core fuzzer behavior specification
//! - [`ShouldFuzz`] - fuzz directives, i.e. which pieces of a [`Request`] should be fuzzed
//!
//! # Macros
//!
//! - [`build_mutators`] - builds recursive data structure that exposes the recursive `call_mutate_hooks` method
//! - [`build_observers`] - builds recursive data structure that exposes the recursive `call_pre_send_hooks` and `call_post_send_hooks` methods
//! - [`build_deciders`] - builds recursive data structure that exposes the recursive `call_pre_send_hooks` and `call_post_send_hooks` methods
//! - [`build_processors`] - builds recursive data structure that exposes the recursive `call_pre_send_hooks` and `call_post_send_hooks` methods

// traits that are likely to be used by anyone when building a fuzzer
pub use crate::client::HttpClient as _;
pub use crate::corpora::Corpus as _;
pub use crate::deciders::Decider as _;
pub use crate::fuzzers::AsyncFuzzing as _;
pub use crate::fuzzers::BlockingFuzzing as _;
pub use crate::fuzzers::Fuzzer as _;
pub use crate::responses::Response as _;
pub use crate::responses::Timed as _;
pub use crate::AsInner as _;
pub use crate::Len as _;

// core structs needed by everyone
pub use crate::actions::Action;
pub use crate::input::Data;
pub use crate::requests::Request;
pub use crate::requests::ShouldFuzz;
pub use crate::state::SharedState;

// crate's error type
pub use crate::error::FeroxFuzzError;

// core macros for building out fuzzer stages
pub use crate::{build_deciders, build_mutators, build_observers, build_processors};
