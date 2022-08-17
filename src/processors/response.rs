use std::marker::PhantomData;

use super::ProcessorHooks;

use crate::actions::Action;
use crate::observers::{Observers, ResponseObserver};
use crate::responses::Response;
use crate::state::SharedState;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::build_processors;
        use crate::fuzzers::Fuzzer;
        use crate::processors::Processors;
        use crate::deciders::Deciders;
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// a `ResponseProcessor` provides access to the fuzzer's instance of [`ResponseObserver`]
/// as well as the [`Action`] returned from calling the analogous hook on [`Deciders`].
/// Those two objects may be used to produce side-effects, such as printing, logging,
/// etc...
///
/// # Examples
///
/// While the example below works, the normal use-case for this struct is to pass
/// it, and any other [`Processors`] to the [`build_processors`] macro, and pass
/// the result of that call to your chosen [`Fuzzer`] implementation.
///
/// ```
/// # use http::response;
/// # use feroxfuzz::prelude::*;
/// # use feroxfuzz::processors::{ResponseProcessor, ProcessorHooks};
/// # use feroxfuzz::observers::ResponseObserver;
/// # use feroxfuzz::responses::BlockingResponse;
/// # use feroxfuzz::corpora::RangeCorpus;
/// # use feroxfuzz::requests::RequestId;
/// # use feroxfuzz::actions::Action;
/// # use std::time::Duration;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// // for testing, normal Response comes as a result of a sent request
/// let reqwest_response = http::response::Builder::new().status(200).body("").unwrap();
/// let id = RequestId::new(0);
/// let elapsed = Duration::from_secs(1);
/// let response = BlockingResponse::try_from_reqwest_response(id, reqwest_response.into(), elapsed)?;
///
/// // also not relevant to the current example, but it's needed to make the call to the hook
/// let mut state = SharedState::with_corpus(RangeCorpus::with_stop(3).name("range").build()?);
///
/// // a ResponseObserver should have already been created at some point
/// let response_observer = ResponseObserver::with_response(response);
/// let observers = build_observers!(response_observer);
///
/// // create a ResponseProcessor that executes the provided closure after
/// // the client has sent the request. Within the closure,
/// // access to the fuzzer's instance of `ResponseObserver` is provided
/// let mut response_printer = ResponseProcessor::new(
///     |response_observer: &ResponseObserver<BlockingResponse>, action, _state| {
///         if let Some(action) = action {
///             if matches!(action, Action::Keep) {
///                 println!(
///                     "[{}] {} - {} - {:?}",
///                     response_observer.status_code(),
///                     response_observer.content_length(),
///                     response_observer.url().to_string(),
///                     response_observer.elapsed()
///                 );
///             }
///         }
///     },
/// );
///
/// // finally, make the call to `post_send_hook`, allowing the side-effect to take place
/// response_printer.post_send_hook(&mut state, &observers, None);
///
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct ResponseProcessor<F, R>
where
    R: Response,
    F: Fn(&ResponseObserver<R>, Option<&Action>, &SharedState),
{
    processor: F,
    marker: PhantomData<R>,
}

impl<F, R> ResponseProcessor<F, R>
where
    F: Fn(&ResponseObserver<R>, Option<&Action>, &SharedState),
    R: Response,
{
    /// create a new `ResponseProcessor` that calls `processor` in
    /// its `post_send_hook` method. Since `processor` receives a
    /// [`ResponseObserver`] as input, the implication is that it
    /// only makes sense to make `post_send_hook` available.
    pub const fn new(processor: F) -> Self {
        Self {
            processor,
            marker: PhantomData,
        }
    }
}

impl<F, FnR> ProcessorHooks for ResponseProcessor<F, FnR>
where
    F: Fn(&ResponseObserver<FnR>, Option<&Action>, &SharedState),
    FnR: Response,
{
    #[instrument(skip_all, fields(?action), level = "trace")]
    fn post_send_hook<O, R>(&mut self, state: &SharedState, observers: &O, action: Option<&Action>)
    where
        O: Observers<R>,
        R: Response,
    {
        if let Some(observer) = observers.match_name::<ResponseObserver<FnR>>("ResponseObserver") {
            (self.processor)(observer, action, state);
        }
    }
}
