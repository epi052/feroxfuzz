use super::{Decider, DeciderHooks};
use crate::actions::Action;
use crate::metadata::AsAny;
use crate::observers::{Observers, ResponseObserver};
use crate::responses::Response;
use crate::state::SharedState;
use crate::std_ext::tuple::Named;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Decide upon an [`Action`] based on a [`ResponseObserver`]'s content-length
///
/// # Examples
///
/// While the example below works, the normal use-case for this struct is to pass
/// it, and any other [`Deciders`] to the [`build_deciders`] macro, and pass
/// the result of that call to your chosen [`Fuzzer`] implementation.
///
/// [`build_deciders`]: crate::build_deciders
/// [`Fuzzer`]: crate::fuzzers::Fuzzer
/// [`Deciders`]: crate::deciders::Deciders
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
/// # use feroxfuzz::deciders::ContentLengthDecider;
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
/// let reqwest_response = http::response::Builder::new().body("0123456789").unwrap();
/// let id = RequestId::new(0);
/// let elapsed = Duration::from_secs(1);
/// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
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
/// // create a ContentLengthDecider with a size of 10 and a closure
/// // that will provide the 'how' of the decision making process
/// let mut decider = ContentLengthDecider::new(10, |length, observed, _state| {
///     if length == observed {
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
///
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct ContentLengthDecider<F>
where
    F: Fn(usize, usize, &SharedState) -> Action + 'static,
{
    comparator: F,
    content_length: usize,
}

impl<F> ContentLengthDecider<F>
where
    F: Fn(usize, usize, &SharedState) -> Action + 'static,
{
    /// create a new `ContentLengthDecider` that calls `comparator` in its
    /// `post_send_hook` method
    pub const fn new(content_length: usize, comparator: F) -> Self {
        Self {
            comparator,
            content_length,
        }
    }
}

impl<O, R, F> DeciderHooks<O, R> for ContentLengthDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(usize, usize, &SharedState) -> Action + Sync + Send + Clone + 'static,
{
}

impl<O, R, F> Decider<O, R> for ContentLengthDecider<F>
where
    O: Observers<R>,
    R: Response,
    F: Fn(usize, usize, &SharedState) -> Action + Clone + 'static,
{
    fn decide_with_observers(&mut self, state: &SharedState, observers: &O) -> Option<Action> {
        // there's an implicit expectation that there is only a single ResponseObserver in the
        // list of given Observers
        if let Some(observer) = observers.match_name::<ResponseObserver<R>>("ResponseObserver") {
            // get the observed content length
            let observed_content_length = observer.content_length();

            // call the comparator to arrive at a decided action
            return Some((self.comparator)(
                self.content_length,
                observed_content_length,
                state,
            ));
        }

        None
    }
}

impl<F> AsAny for ContentLengthDecider<F>
where
    F: Fn(usize, usize, &SharedState) -> Action + 'static,
{
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl<F> Named for ContentLengthDecider<F>
where
    F: Fn(usize, usize, &SharedState) -> Action,
{
    fn name(&self) -> &'static str {
        "ContentLengthDecider"
    }
}
