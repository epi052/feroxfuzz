// ignore the two false positives for the `type_repetition_in_bounds` lint in this module
#![allow(clippy::type_repetition_in_bounds)]

use std::marker::PhantomData;

use super::{Decider, DeciderHooks};
use crate::actions::Action;
use crate::observers::{Observers, ResponseObserver};
use crate::requests::Request;
use crate::responses::Response;
use crate::state::SharedState;
use regex::bytes::Regex;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// a `RequestRegexDecider` takes a regular expression, compiles it to a [`Regex`] and then
/// applies it in whatever way is passed via the `comparator` closure.
///
/// # Examples
///
/// ```
/// # use feroxfuzz::prelude::*;
/// # use feroxfuzz::corpora::RangeCorpus;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::deciders::{RequestRegexDecider, DeciderHooks, LogicOperation};
/// # use regex::bytes::Regex;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// // not relevant to the current example, but needed to make the call to .post_send_hook
/// let mut state = SharedState::with_corpus(RangeCorpus::with_stop(10).name("corpus").build()?);
///
/// // our example Request, typically received from calling the Mutator hooks
/// let request = Request::from_url("http://localhost:8000/ignore", None)?;
///
/// // create a RequestRegexDecider with a regular expression and a closure
/// // that will provide the 'how' of the decision making process.
/// let decider = RequestRegexDecider::new("[iI]gnored?", |regex, request, _state| {
///     match request.path().as_str() {
///         Ok(path) => {
///             if regex.is_match(path.as_bytes()) {
///                 Action::Discard
///             } else {
///                 Action::Keep
///             }
///         }
///         Err(_) => {
///             Action::Discard
///         }
///     }
/// });
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RequestRegexDecider<F>
where
    F: Fn(&Regex, &Request, &SharedState) -> Action,
{
    comparator: F,

    #[cfg_attr(feature = "serde", serde(with = "serde_regex"))]
    regex: Regex,
}

impl<F> RequestRegexDecider<F>
where
    F: Fn(&Regex, &Request, &SharedState) -> Action,
{
    /// create a new `RequestRegexDecider` that calls `comparator` in its
    /// `pre_send_hook` method
    ///
    /// # Panics
    ///
    /// function will panic if provided a regex that can't compile
    pub fn new(regex: &str, comparator: F) -> Self {
        Self {
            regex: Regex::new(regex).unwrap(),
            comparator,
        }
    }
}

impl<O, R, F> DeciderHooks<O, R> for RequestRegexDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(&Regex, &Request, &SharedState) -> Action,
{
}

impl<O, R, F> Decider<O, R> for RequestRegexDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(&Regex, &Request, &SharedState) -> Action,
{
    fn decide_with_request(&mut self, state: &SharedState, request: &Request) -> Option<Action> {
        Some((self.comparator)(&self.regex, request, state))
    }
}

/// a `ResponseRegexDecider` takes a regular expression, compiles it to a [`Regex`] and then
/// applies it in whatever way is passed via the `comparator` closure.
///
/// # Examples
///
/// ```
/// # use http::response;
/// # use std::time::Duration;
/// # use feroxfuzz::prelude::*;
/// # use feroxfuzz::corpora::RangeCorpus;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::deciders::{ResponseRegexDecider, DeciderHooks, LogicOperation, Deciders};
/// # use feroxfuzz::observers::ResponseObserver;
/// # use feroxfuzz::responses::BlockingResponse;
/// # use feroxfuzz::requests::{Request, RequestId};
/// # use regex::bytes::Regex;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// // for testing; normally a Response comes as a result of a sent request
/// let reqwest_response = http::response::Builder::new().status(200).body("XyZDeRpZyX").unwrap();
/// let id = RequestId::new(0);
/// let elapsed = Duration::from_secs(1);
/// let response = BlockingResponse::try_from_reqwest_response(id, reqwest_response.into(), elapsed)?;
///
/// // not relevant to the current example, but needed to make the call to .post_send_hook
/// let mut state = SharedState::with_corpus(RangeCorpus::with_stop(10).name("corpus").build()?);
///
/// // our example Request, typically received from calling the Mutator hooks
/// let request = Request::from_url("http://localhost:8000/ignore", None)?;
///
/// // create a ResponseRegexDecider with a regular expression and a closure
/// // that will provide the 'how' of the decision making process. Since
/// // there are two different implementations of DeciderHooks, we need to provide type
/// // information to the closure definition / compiler.
/// let mut decider = ResponseRegexDecider::new("[dD][eE][rR][pP]", |regex, observer: &ResponseObserver<BlockingResponse>, _state| {
///     if regex.is_match(&observer.body()) {
///         Action::Keep
///     } else {
///         Action::Discard
///     }
/// });
///
/// let observer = ResponseObserver::with_response(response);
/// let observers = build_observers!(observer);
///
/// // normally this is called from within a Fuzzer, not manually
/// let action = decider.decide_with_observers(&mut state, &observers);
///
/// assert_eq!(action, Some(Action::Keep));
///
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResponseRegexDecider<F, R>
where
    R: Response,
    F: Fn(&Regex, &ResponseObserver<R>, &SharedState) -> Action,
{
    comparator: F,

    #[cfg_attr(feature = "serde", serde(with = "serde_regex"))]
    regex: Regex,

    marker: PhantomData<R>,
}

impl<F, R> ResponseRegexDecider<F, R>
where
    F: Fn(&Regex, &ResponseObserver<R>, &SharedState) -> Action,
    R: Response,
{
    /// create a new `ResponseRegexDecider` that calls `comparator` in its
    /// `post_send_hook` method
    ///
    /// # Panics
    ///
    /// function will panic if provided a regex that can't compile
    pub fn new(regex: &str, comparator: F) -> Self {
        Self {
            regex: Regex::new(regex).unwrap(),
            comparator,
            marker: PhantomData,
        }
    }
}

impl<O, R, F> DeciderHooks<O, R> for ResponseRegexDecider<F, R>
where
    O: Observers<R>,
    R: Response,
    F: Fn(&Regex, &ResponseObserver<R>, &SharedState) -> Action,
{
}

impl<O, R, F> Decider<O, R> for ResponseRegexDecider<F, R>
where
    O: Observers<R>,
    R: Response,
    F: Fn(&Regex, &ResponseObserver<R>, &SharedState) -> Action,
{
    fn decide_with_observers(&mut self, state: &SharedState, observers: &O) -> Option<Action> {
        // there's an implicit expectation that there is only a single ResponseObserver in the
        // list of given Observers
        if let Some(observer) = observers.match_name::<ResponseObserver<R>>("ResponseObserver") {
            // call the comparator to arrive at a decided action
            return Some((self.comparator)(&self.regex, observer, state));
        }

        None
    }
}
