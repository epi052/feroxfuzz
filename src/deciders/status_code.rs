use super::{Decider, DeciderHooks};
use crate::actions::Action;
use crate::observers::{Observers, ResponseObserver};
use crate::responses::Response;
use crate::state::SharedState;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::fuzzers::Fuzzer;
        use crate::build_deciders;
        use crate::deciders::Deciders;
    }
}

/// Decide upon an [`Action`] based on a [`ResponseObserver`]'s status code
///
/// # Examples
///
/// While the example below works, the normal use-case for this struct is to pass
/// it, and any other [`Deciders`] to the [`build_deciders`] macro, and pass
/// the result of that call to your chosen [`Fuzzer`] implementation.
///
/// ```
/// # use http::response;
/// # use feroxfuzz::responses::{Response, AsyncResponse};
/// # use feroxfuzz::requests::RequestId;
/// # use feroxfuzz::error::FeroxFuzzError;
/// # use tokio_test;
/// # use std::time::Duration;
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::actions::Action;
/// # use feroxfuzz::deciders::StatusCodeDecider;
/// # use feroxfuzz::deciders::Decider;
/// # use feroxfuzz::observers::Observers;
/// # use feroxfuzz::observers::Observer;
/// # use feroxfuzz::observers::ResponseObserver;
/// # use feroxfuzz::build_observers;
/// # use feroxfuzz::deciders::{DeciderHooks, LogicOperation};
/// # use feroxfuzz::MatchName;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// # tokio_test::block_on(async {
/// // for testing; normally a Response comes as a result of a sent request
/// let reqwest_response = http::response::Builder::new().status(200).body("").unwrap();
/// let id = RequestId::new(0);
/// let elapsed = Duration::from_secs(1);
/// let response = AsyncResponse::try_from_reqwest_response(id, reqwest_response.into(), elapsed).await?;
///
/// // also not relevant to the current example, but needed to make the call to .post_send_hook
/// let corpus = Wordlist::with_words(["a", "b", "c"]).name("chars").build();
/// let mut state = SharedState::with_corpus(corpus);
///
///
/// // a ResponseObserver should be already created at some earlier point
/// let response_observer: ResponseObserver<_> = response.into();
/// let observers = build_observers!(response_observer);
///
/// // create a StatusCodeDecider with a status code of 200 and a closure
/// // that will provide the 'how' of the decision making process
/// let mut decider = StatusCodeDecider::new(200, |status, observed, _state| {
///     if status == observed {
///         Action::Keep
///     } else {
///         Action::Discard
///     }
/// });
///
/// // finally, make the call to .post_send_hook and receive the answer in the form of
/// // an Action to take
/// let action = decider.post_send_hook(&mut state, &observers, Some(Action::Keep), LogicOperation::Or);
///
/// assert_eq!(action, Some(Action::Keep));
/// # Result::<(), FeroxFuzzError>::Ok(())
/// # })
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct StatusCodeDecider<F>
where
    F: Fn(u16, u16, &SharedState) -> Action,
{
    comparator: F,
    status_code: u16,
}

impl<F> StatusCodeDecider<F>
where
    F: Fn(u16, u16, &SharedState) -> Action,
{
    /// create a new `StatusCodeDecider` that calls `comparator` in its
    /// `post_send_hook` method
    pub const fn new(status_code: u16, comparator: F) -> Self {
        Self {
            comparator,
            status_code,
        }
    }
}

impl<O, R, F> DeciderHooks<O, R> for StatusCodeDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(u16, u16, &SharedState) -> Action + Sync + Send + Clone,
{
}

impl<O, R, F> Decider<O, R> for StatusCodeDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(u16, u16, &SharedState) -> Action + Clone,
{
    fn decide_with_observers(&mut self, state: &SharedState, observers: &O) -> Option<Action> {
        // there's an implicit expectation that there is only a single ResponseObserver in the
        // list of given Observers
        if let Some(observer) = observers.match_name::<ResponseObserver<R>>("ResponseObserver") {
            // get the observed status code
            let observed_status = observer.status_code();

            // call the comparator to arrive at a decided action
            return Some((self.comparator)(self.status_code, observed_status, state));
        }

        None
    }
}
