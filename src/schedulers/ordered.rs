#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{set_states_corpus_index, CorpusIndex, Scheduler};
use crate::error::FeroxFuzzError;
use crate::state::SharedState;
use crate::std_ext::ops::Len;

use tracing::{error, instrument, trace};

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::corpora::Corpus;
    }
}

/// In-order access of the associated [`Corpus`]
///
/// # Examples
///
/// if you have a corpus with the following entries:
///
/// `FUZZ_USER`: ["user1", "user2", "user3"]
/// `FUZZ_PASS`: ["pass1", "pass2", "pass3"]
///
/// and a fuzzable url defined as
///
/// `http://example.com/login?username=FUZZ_USER&password=FUZZ_PASS`
///
///
/// then the resultant `OrderedScheduler` scheduling of the two corpora would be:
///
/// `http://example.com/login?username=user1&password=pass1`
/// `http://example.com/login?username=user2&password=pass2`
/// `http://example.com/login?username=user3&password=pass3`
///
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OrderedScheduler {
    current: usize,
    indices: Vec<CorpusIndex>,

    #[cfg_attr(feature = "serde", serde(skip))]
    state: SharedState,
}

impl Scheduler for OrderedScheduler {
    #[instrument(skip(self), fields(%self.current, ?self.indices), level = "trace")]
    fn next(&mut self) -> Result<(), FeroxFuzzError> {
        // iterate through the indices and increment the current index
        for index in &mut self.indices {
            if self.current > 0 && index.should_reset(self.current) {
                // once any of the indices reaches the end of its loop, the entire
                // scheduler has run to completion
                trace!("scheduler has run to completion");
                return Err(FeroxFuzzError::IterationStopped);
            }

            set_states_corpus_index(&self.state, index.name(), index.current())?;

            index.next()?;
        }

        self.current += 1; // update the total number of times .next has been called

        Ok(())
    }

    /// resets all indexes that are tracked by the scheduler as well as their associated atomic
    /// indexes in the [`SharedState`] instance
    #[instrument(skip(self), level = "trace")]
    fn reset(&mut self) {
        self.current = 0;

        self.indices.iter_mut().for_each(|index| {
            // first, we get the corpus associated with the current corpus_index
            let corpus = self.state.corpus_by_name(index.name()).unwrap();

            // and then get its length
            let len = corpus.len();

            // if any items were added to the corpus, we'll need to update the length/expected iterations
            // accordingly
            index.update_length(len);
            index.update_iterations(len);

            // we'll also reset the current index as well
            index.reset();

            // finally, we get the SharedState's view of the index in sync with the Scheduler's
            //
            // i.e. at this point, the state and local indices should all be 0, and any items
            // added to the corpus should be reflected in each index's length/iterations
            set_states_corpus_index(&self.state, index.name(), 0).unwrap();
        });

        trace!("scheduler has been reset");
    }
}

impl OrderedScheduler {
    /// create a new `OrderedScheduler`
    ///
    /// # Errors
    ///
    /// This function will return an error if any corpus found in the `SharedState`'s
    /// `corpora` map is empty, or if the `SharedState`'s `corpora` map is empty.
    ///
    /// # Examples
    ///
    /// see `examples/cartesian-product.rs` for a more robust example
    /// and explanation
    ///
    /// ```
    /// use feroxfuzz::schedulers::{Scheduler, ProductScheduler};
    /// use feroxfuzz::prelude::*;
    /// use feroxfuzz::corpora::{RangeCorpus, Wordlist};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // create two corpora, one with a set of user names, and one with a range of ids
    /// // where only even ids are considered
    /// let users = Wordlist::new().word("user").word("admin").name("users").build();
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    ///
    /// let state = SharedState::with_corpora([ids, users]);
    ///
    /// let order = ["users", "ids"];
    /// let mut scheduler = ProductScheduler::new(order, state.clone())?;
    ///
    /// let mut counter = 0;
    ///
    /// while Scheduler::next(&mut scheduler).is_ok() {
    ///     counter += 1;
    /// }
    ///
    /// // users.len() * ids.len() = 2 * 5 = 10
    /// assert_eq!(counter, 10);
    ///
    /// # Ok(())
    /// # }
    #[inline]
    #[instrument(skip_all, level = "trace")]
    pub fn new(state: SharedState) -> Result<Self, FeroxFuzzError> {
        let corpora = state.corpora();

        let mut indices = Vec::with_capacity(corpora.len());

        for (name, corpus) in corpora.iter() {
            let length = corpus.len();

            if length == 0 {
                // one of the corpora was empty
                error!(%name, "corpus is empty");

                return Err(FeroxFuzzError::EmptyCorpus {
                    name: name.to_string(),
                });
            }

            // the total number of expected iterations per corpus is simply
            // the length of the corpus
            indices.push(CorpusIndex::new(name, length, length));
        }

        if indices.is_empty() {
            // empty iterator passed in
            error!("no corpora were found");
            return Err(FeroxFuzzError::EmptyCorpusMap);
        }

        Ok(Self {
            state,
            indices,
            current: 0,
        })
    }
}

#[allow(clippy::copy_iterator)]
impl Iterator for OrderedScheduler {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        <Self as Scheduler>::next(self).ok()
    }
}
