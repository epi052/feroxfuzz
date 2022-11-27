use super::ProcessorHooks;

use crate::actions::Action;
use crate::requests::Request;
use crate::state::SharedState;
use crate::std_ext::tuple::Named;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// a `RequestProcessor` provides access to the fuzzer's mutated [`Request`] that
/// is about to be sent to the target, as well as the [`Action`] returned
/// from calling the analogous hook on [`Deciders`]. Those two objects may
/// be used to produce side-effects, such as printing, logging, etc...
///
/// # Examples
///
/// While the example below works, the normal use-case for this struct is to pass
/// it, and any other [`Processors`] to the [`build_processors`] macro, and pass
/// the result of that call to your chosen [`Fuzzer`] implementation.
///
/// [`Fuzzer`]: crate::fuzzers::Fuzzer
/// [`Deciders`]: crate::deciders::Deciders
/// [`Processors`]: crate::processors::Processors
/// [`build_processors`]: crate::build_processors
///
/// ```
/// # use feroxfuzz::prelude::*;
/// # use feroxfuzz::processors::{RequestProcessor, ProcessorHooks};
/// # use feroxfuzz::corpora::RangeCorpus;
/// # use feroxfuzz::actions::Action;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// // normally this would be passed to the Mutators before processing
/// let mut request = Request::from_url("http://localhost:8080", None)?;
///
/// // also not relevant to the current example, but it's needed to make the call to the hook
/// let mut state = SharedState::with_corpus(RangeCorpus::with_stop(3).name("range").build()?);
///
///
/// // create a RequestProcessor that executes the provided closure before
/// // the client has sent the mutated request. Within the closure,
/// // access to the fuzzer's current mutated Request is provided
/// let mut request_checker = RequestProcessor::new(|request, action, _state| {
///     if let Some(inner) = action {
///         if matches!(inner, Action::Discard) {
///             // the action shown here came is the result of any
///             // request Deciders that ran on this particular
///             // request
///             println!("skipping {:?}", request)
///         }
///     }
/// });
///
/// // finally, make the call to `pre_send_hook`, allowing the side-effect to take place
/// request_checker.pre_send_hook(&mut state, &mut request, None);
///
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState),
{
    processor: F,
}

impl<F> RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState),
{
    /// create a new `RequestProcessor` that calls `processor` in
    /// its `pre_send_hook` method. Since `processor` receives a
    /// [`Request`] as input, the implication is that it
    /// only makes sense to make `pre_send_hook` available.
    pub const fn new(processor: F) -> Self {
        Self { processor }
    }
}

impl<F> ProcessorHooks for RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState),
{
    #[instrument(skip_all, fields(?action), level = "trace")]
    fn pre_send_hook(
        &mut self,
        state: &SharedState,
        request: &mut Request,
        action: Option<&Action>,
    ) {
        (self.processor)(request, action, state);
    }
}

impl Named for RequestProcessor<()> {
    fn name(&self) -> &str {
        "RequestProcessor"
    }
}