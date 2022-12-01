use std::any::Any;

use super::{Processor, ProcessorHooks};

use crate::actions::Action;
use crate::metadata::AsAny;
use crate::observers::Observers;
use crate::requests::Request;
use crate::responses::Response;
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
/// [`Deciders`]: crate::deciders::Deciders
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + 'static,
{
    processor: F,
}

impl<F> RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + 'static,
{
    /// create a new `RequestProcessor` that calls `processor` in
    /// its `pre_send_hook` method. Since `processor` receives a
    /// [`Request`] as input, the implication is that it
    /// only makes sense to make `pre_send_hook` available.
    pub const fn new(processor: F) -> Self {
        Self { processor }
    }
}

impl<F> Processor for RequestProcessor<F> where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + Sync + Send + Clone + 'static
{
}

impl<F, O, R> ProcessorHooks<O, R> for RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + Sync + Send + Clone + 'static,
    O: Observers<R>,
    R: Response,
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

impl<F> Named for RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + 'static,
{
    fn name(&self) -> &str {
        "RequestProcessor"
    }
}

impl<F> AsAny for RequestProcessor<F>
where
    F: Fn(&mut Request, Option<&Action>, &SharedState) + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }
}
