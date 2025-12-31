#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{set_states_corpus_index, CorpusIndex, Scheduler};
use crate::error::FeroxFuzzError;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::tuple::Named;
use tracing::{error, instrument, trace};

/// Random access of the associated [`Corpus`]
///
/// [`Corpus`]: crate::corpora::Corpus
///
/// # Note
///
/// This scheduler will iterate as many times as the longest
/// provided corpus. Meaning that if you have a corpus with 2 entries
/// and another corpus with 10 entries, the scheduler will iterate 10 times,
/// providing a random index for each corpus on each iteration.
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
/// the scheduler will select a random index for the `FUZZ_USER` corpus
/// from 0-2 and a random index for the `FUZZ_PASS` corpus from 0-2. It
/// will do this 3 times before it stops.
#[allow(clippy::doc_link_with_quotes)]
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RandomScheduler {
    current: usize,
    indices: Vec<CorpusIndex>,
    longest_corpus: usize,

    #[cfg_attr(feature = "serde", serde(skip))]
    state: SharedState,
}

impl Scheduler for RandomScheduler {
    #[instrument(skip(self), fields(%self.current, %self.longest_corpus, ?self.indices), level = "trace")]
    fn next(&mut self) -> Result<(), FeroxFuzzError> {
        if self.current >= self.longest_corpus {
            // random scheduler has run to completion once it
            // has iterated the number of times as the longest
            // given corpus
            trace!("scheduler has run to completion");
            return Err(FeroxFuzzError::IterationStopped);
        }

        // iterate through the indices and increment the current index
        for index in &mut self.indices {
            let length = index.len();
            let random_idx = self.state.rng_mut().below(length);

            set_states_corpus_index(&self.state, index.name(), random_idx)?;

            // don't care about keeping track of each index's current index, so no index.next()
        }

        self.current += 1; // update the total number of times .next has been called

        Ok(())
    }

    /// resets all indexes that are tracked by the scheduler as well as their associated atomic
    /// indexes in the [`SharedState`] instance
    fn reset(&mut self) {
        self.current = 0;

        for index in &mut self.indices {
            // first, we get the corpus associated with the current corpus_index
            let corpus = self.state.corpus_by_name(index.name()).unwrap();

            // and then get its length
            let len = corpus.len();

            // update the longest corpus if the current corpus is longer, since this is what's used
            // to determine when the scheduler has run to completion
            if len > self.longest_corpus {
                self.longest_corpus = len;
            }

            // update the length of the current corpus_index, which is used to determine the
            // upper bound of the RNG for producing a random index
            index.update_length(len);

            // purposely not resetting the current index, since we don't keep track of them in random scheduling

            // finally, we get the SharedState's view of the index in sync with the Scheduler's
            set_states_corpus_index(&self.state, index.name(), 0).unwrap();
        }

        trace!("scheduler has been reset");
    }

    fn update_length(&mut self) {
        for index in &mut self.indices {
            // first, we get the corpus associated with the current corpus_index
            let corpus = self.state.corpus_by_name(index.name()).unwrap();

            // and then get its length
            let len = corpus.len();

            // update the longest corpus if the current corpus is longer, since this is what's used
            // to determine when the scheduler has run to completion
            if len > self.longest_corpus {
                self.longest_corpus = len;
            }

            // update the length of the current corpus_index, which is used to determine the
            // upper bound of the RNG for producing a random index
            index.update_length(len);
        }
    }
}

impl RandomScheduler {
    /// create a new `RandomScheduler`
    ///
    /// # Errors
    ///
    /// This function will return an error if any corpus found in the `SharedState`'s
    /// `corpora` map is empty, or if the `SharedState`'s `corpora` map is empty.
    ///
    /// # Examples
    ///
    /// see `examples/random-scheduler.rs` for a more robust example
    /// and explanation
    ///
    /// ```
    /// use feroxfuzz::schedulers::{Scheduler, RandomScheduler};
    /// use feroxfuzz::prelude::*;
    /// use feroxfuzz::corpora::{RangeCorpus, Wordlist};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // create two corpora, one with a set of user names, and one with a range of ids
    /// // where only even ids are considered
    /// let users = Wordlist::new().words(["user", "admin"]).name("users").build();
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    ///
    /// let state = SharedState::with_corpora([ids, users]);
    ///
    /// let order = ["users", "ids"];
    /// let mut scheduler = RandomScheduler::new(state.clone())?;
    ///
    /// let mut counter = 0;
    ///
    /// while Scheduler::next(&mut scheduler).is_ok() {
    ///     counter += 1;
    /// }
    ///
    /// // length of the longest corpus passed to the scheduler
    /// assert_eq!(counter, 5);
    ///
    /// # Ok(())
    /// # }
    #[inline]
    #[instrument(skip_all, level = "trace")]
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    pub fn new(state: SharedState) -> Result<Self, FeroxFuzzError> {
        let corpora = state.corpora();
        let mut longest_corpus = 0;

        let mut indices = Vec::with_capacity(corpora.len());

        let mut current = state
            .stats()
            .read()
            .map_or(0, |stats| stats.requests() as usize);

        for (name, corpus) in &*corpora {
            let length = corpus.len();

            if length == 0 {
                // one of the corpora was empty
                error!(%name, "corpus is empty");

                return Err(FeroxFuzzError::EmptyCorpus { name: name.clone() });
            }

            if length > longest_corpus {
                longest_corpus = length;
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

        let mut scheduler = Self {
            longest_corpus,
            state,
            indices,
            current: 0,
        };

        while current > 0 {
            Scheduler::next(&mut scheduler)?;
            current -= 1;
        }

        Ok(scheduler)
    }

    /// by default, the [`RandomScheduler`] will iterate through *every* corpus
    /// and update their next index with a randomly chosen value within a
    /// valid range.
    ///
    /// This function allows you to specify which corpora will be updated by the
    /// scheduler. This is useful if you want to only update a subset of corpora
    /// at a time, instead of all of them.
    #[instrument(skip(self), level = "trace")]
    pub fn limit_to_corpora(&mut self, corpora: &[&str]) {
        self.indices.retain(|index| corpora.contains(&index.name()));
    }
}

#[allow(clippy::copy_iterator)]
impl Iterator for RandomScheduler {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        Scheduler::next(self).ok()
    }
}

impl Named for RandomScheduler {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "RandomScheduler"
    }
}
