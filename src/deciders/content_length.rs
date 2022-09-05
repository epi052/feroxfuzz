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

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[allow(clippy::derive_partial_eq_without_eq)] // known false-positive introduced in 1.63.0
pub struct ContentLengthDecider<F>
    where
        F: Fn(usize, usize, &SharedState) -> Action,
{
    comparator: F,
    content_length: usize,
}

impl<F> ContentLengthDecider<F>
    where
        F: Fn(usize, usize, &SharedState) -> Action,
{
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
        F: Fn(usize, usize, &SharedState) -> Action,
{
}

impl<O, R, F> Decider<O, R> for ContentLengthDecider<F>
    where
        O: Observers<R>,
        R: Response,
        F: Fn(usize, usize, &SharedState) -> Action,
{
    fn decide_with_observers(&mut self, state: &SharedState, observers: &O) -> Option<Action> {
        // there's an implicit expectation that there is only a single ResponseObserver in the
        // list of given Observers
        if let Some(observer) = observers.match_name::<ResponseObserver<R>>("ResponseObserver") {
            // get the observed content length
            let observed_content_length = observer.content_length();

            // call the comparator to arrive at a decided action
            return Some((self.comparator)(self.content_length, observed_content_length, state));
        }

        None
    }
}