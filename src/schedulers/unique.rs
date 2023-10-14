use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{set_states_corpus_index, CorpusIndex, ProductScheduler, Scheduler};
use crate::error::FeroxFuzzError;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::tuple::Named;

use tracing::{error, instrument, trace};

/// Cartesian product of multiple [`Corpus`] entries, where each entry is
/// only scheduled once.
///
/// This scheduler is useful when paired with multiple corpora that may
/// be altered at runtime. For example, if you have a corpus of usernames
/// and a corpus of passwords, and are gathering new entries for both
/// corpora as you fuzz, you can use this scheduler to ensure that
/// each username is paired with each password exactly once.
///
/// roughly equivalent to nested for-loops without any repeated
/// scheduling of entries
///
/// # notes
///
/// - this is the least efficient scheduler, but is the most robust
/// in terms of ensuring that each entry is scheduled exactly once and
/// that adding entries at runtime still results in all new entries
/// being scheduled along with any existing entries/fuzzable field
/// combinations.
/// - in between calls to `fuzzer.fuzz_once()`, if the corpora length
/// changes, you must call `scheduler.update_length()` to ensure that
/// the scheduler is aware of the new length. After that, you must
/// call `fuzzer.fuzz_once()` again to allow the scheduler to continue
/// scheduling new entries.
/// - this scheduler DOES NOT prevent duplicate entries from being
/// added to the corpus/scheduled. if you want to prevent duplicate
/// entries from being added to the corpus, use the `.unique()` method
/// during corpus construction.
/// - this scheduler DOES prevent scheduling of the same corpus entries
/// more than once.
///
/// [`Corpus`]: crate::corpora::Corpus
///
/// # Examples
///
/// if you have a corpus with the following entries:
///
/// Users: ["user1", "user2", "user3"]
/// Passwords: ["pass1", "pass2", "pass3"]
///
/// the scheduler will ensure that each user is paired with each password
/// by maintaining a set of all scheduled combinations.
///
///   Users\[0\] Passwords\[0\] -> scheduled
///   Users\[0\] Passwords\[1\] -> scheduled
///   Users\[0\] Passwords\[2\] -> scheduled
///   Users\[1\] Passwords\[0\] -> scheduled
///   Users\[1\] Passwords\[1\] -> scheduled
///   Users\[1\] Passwords\[2\] -> scheduled
///   Users\[2\] Passwords\[0\] -> scheduled
///   Users\[2\] Passwords\[1\] -> scheduled
///   Users\[2\] Passwords\[2\] -> scheduled
///
/// If you add a new user to the corpus, the scheduler will ensure that
/// the new user is paired with each password, and that each existing
/// user is paired with the new password.
///
/// Users: ["user1", "user2", "user3", "user4"]  <- new user added
/// `fuzzer.scheduler.update_length()`;  <- update the scheduler to reflect the new length
/// `fuzzer.fuzz_once()`;  <- allow the scheduler to schedule the new user
///
///   Users\[3\] Passwords\[0\] -> scheduled
///   Users\[3\] Passwords\[1\] -> scheduled
///   Users\[3\] Passwords\[2\] -> scheduled
///
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UniqueProductScheduler {
    current: usize,
    indices: Vec<CorpusIndex>,
    scheduled: HashSet<Vec<usize>>, // todo optimize this to a vec of tuples

    #[cfg_attr(feature = "serde", serde(skip))]
    state: SharedState,
}

impl std::fmt::Debug for UniqueProductScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UniqueProductScheduler")
            .field("current", &self.current)
            .field("indices", &self.indices)
            .finish_non_exhaustive() // purposely skip state
    }
}

impl Scheduler for UniqueProductScheduler {
    #[instrument(skip(self), fields(%self.current, ?self.indices), level = "trace")]
    fn next(&mut self) -> Result<(), FeroxFuzzError> {
        // structurally, this is the same as the `ProductScheduler`, but
        // we need to keep track of which entries have been scheduled
        // and skip them if they've already been scheduled. For a more detailed
        // explanation of the algorithm, see the `ProductScheduler` comments/docs.
        let num_indices = self.indices.len();

        // shadow copy of the current indices; done this way since we typically have a mutable
        // reference to self.inidices, and we need to be able to grab all the current indices'
        // when storing the current indices in the `scheduled` set. The mutable/immutable
        // reference rules prevent us from doing this in without a shadow copy.
        let mut indices_copy: Vec<_> = self.indices.iter().map(CorpusIndex::current).collect();

        // this shouldn't ever error, since we have at least one corpus; at worst, inner and outer
        // are the same corpus
        let outermost = self.indices.last().ok_or_else(|| {
            error!("scheduler has no associated CorpusIndex");
            FeroxFuzzError::EmptyCorpusIndices
        })?;

        if self.current > 0 && outermost.should_reset(self.current) {
            // when the outermost loop reaches the end of its loop, the entire
            // nested loop structure has run to completion
            trace!("scheduler has run to completion");
            return Err(FeroxFuzzError::IterationStopped);
        }

        let innermost = &mut self.indices[0];

        innermost.next()?; // increment the innermost loop
        indices_copy[0] = innermost.current(); // update the shadow copy to reflect the new index

        if self.scheduled.contains(&indices_copy) {
            // if the current combination has already been scheduled, skip it
            trace!("skipped scheduled item: {:?}", indices_copy);
            return Err(FeroxFuzzError::SkipScheduledItem);
        }

        // if we have a single entry, we're done, just need to set the state's view
        // of the current index to what was calculated here
        if num_indices == 1 {
            set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

            // insert returns true if the item was newly inserted, false if it was already present
            let newly_inserted = self.scheduled.insert(indices_copy.clone());

            if newly_inserted {
                // update the total number of times .next has been called
                // this is done here since we only want to increment the current
                // counter if we're actually going to schedule the item
                self.current += 1;
                return Ok(());
            }

            trace!("skipped scheduled item: {:?}", indices_copy);
            return Err(FeroxFuzzError::SkipScheduledItem);
        }

        if innermost.current() != innermost.length && self.current != 0 {
            // if the current scheduler.next iteration is not a modulo value
            // for the innermost loop, we don't need to progress any further
            //
            // i.e. if the innermost loop has 3 entries, we need to increment
            // innermost until it reaches 3, then reset it to 0 before moving
            // on to the next outer loop
            set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

            let newly_inserted = self.scheduled.insert(indices_copy.clone());

            if newly_inserted {
                // only increment the current counter if we're actually going to schedule the item
                self.current += 1;
                return Ok(());
            }

            trace!("skipped scheduled item: {:?}", indices_copy);
            return Err(FeroxFuzzError::SkipScheduledItem);
        }

        // innermost loop has completed a full iteration, so we need to reset
        innermost.reset();
        indices_copy[0] = innermost.current();
        set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

        // the for loop below iterates over an unknown number of corpora lengths
        // and increments each scheduled index if their previous index's modulo
        // value was 0. In the case of the first index, this will always be true
        // since we just determined the innermost loop's modulo value above.

        // The pattern is that when an index reaches its modulo value, it is
        // reset to 0 and the next greater loop is incremented.
        for (i, index) in self.indices.iter_mut().enumerate().skip(1) {
            index.next()?;
            indices_copy[i] = index.current();

            // if the current index doesn't equal its length,
            // continue to the next iteration, since it's not time to
            // increment any further indices.
            //
            // this if check differs from the `ProductScheduler` because
            // we need to allow the scheduler to reach `index.iterations`
            // values at unknown/random times. This check is more relaxed
            // and allows us to have the robustness to handle multiple
            // runtime additions to multiple corpora.
            if index.current() != index.length && self.current != 0 {
                // recall that the innermost loop is the first index in the vec
                // and the outermost loop is the last index in the vec. so we
                // only progress to each outer-more loop when the current inner-more
                // loop has completed a full iteration.
                break;
            }

            index.reset();
            indices_copy[i] = index.current();
        }

        let newly_inserted = self.scheduled.insert(indices_copy.clone());

        self.indices.iter_mut().for_each(|index| {
            // the for loop above has the potential to call next/reset on an unknown
            // number of indexes, so we need to update the state's view of the current
            // index for each index
            set_states_corpus_index(&self.state, index.name(), index.current()).unwrap();
        });

        if newly_inserted {
            self.current += 1;
            Ok(())
        } else {
            trace!("skipped scheduled item: {:?}", indices_copy);
            Err(FeroxFuzzError::SkipScheduledItem)
        }
    }

    /// resets all indexes that are tracked by the scheduler as well as their associated atomic
    /// indexes in the [`SharedState`] instance
    #[instrument(skip(self), level = "trace")]
    fn reset(&mut self) {
        self.current = 0;
        self.scheduled.clear(); // clear the set of scheduled items; only diff from ProductScheduler

        let mut total_iterations = 1;

        self.indices.iter_mut().for_each(|index| {
            // first, we get the corpus associated with the current corpus_index
            let corpus = self.state.corpus_by_name(index.name()).unwrap();

            // and then get its length
            let len = corpus.len();

            // if any items were added to the corpus, we'll need to update the length/expected iterations
            // accordingly
            //
            // note: self.indices is in the same order as what ::new() produced initially, so
            // we can use the same strategy to update the total_iterations here, in the event
            // that we add items to any of the corpora
            total_iterations *= len;

            index.update_length(len);
            index.update_iterations(total_iterations);

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

    fn update_length(&mut self) {
        // with the exception of resetting `scheduled` and `current`, the logic needed here is the same as `reset`
        let current = self.current;
        let scheduled = self.scheduled.clone();

        self.reset();

        self.scheduled = scheduled;
        self.current = current;

        trace!("updated corpora length in scheduler: {:#?}", self);
    }
}

impl UniqueProductScheduler {
    /// create a new `UniqueProductScheduler` scheduler
    ///
    /// # Errors
    ///
    /// This function will return an error for the following reasons
    /// - if the `corpus_order` parameter is empty
    /// - if any of the corpora in the `corpus_order` parameter is not found in the `SharedState`'s `corpora` map
    /// - if any of the found corpora found in the `SharedState`'s `corpora` map are empty
    ///
    /// # Examples
    ///
    /// see `examples/cartesian-product.rs` for a more robust example
    /// and explanation
    ///
    /// ```
    /// use feroxfuzz::schedulers::{Scheduler, UniqueProductScheduler};
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
    /// let mut scheduler = UniqueProductScheduler::new(order, state.clone())?;
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
    #[instrument(skip(state), level = "trace")]
    pub fn new<'a, I>(corpus_order: I, state: SharedState) -> Result<Self, FeroxFuzzError>
    where
        I: IntoIterator<Item = &'a str> + std::fmt::Debug,
    {
        let product_scheduler = ProductScheduler::new(corpus_order, state)?;

        Ok(product_scheduler.into())
    }
}

#[allow(clippy::copy_iterator)]
impl Iterator for UniqueProductScheduler {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        Scheduler::next(self).ok()
    }
}

impl Named for UniqueProductScheduler {
    fn name(&self) -> &str {
        "UniqueProductScheduler"
    }
}

impl From<ProductScheduler> for UniqueProductScheduler {
    fn from(scheduler: ProductScheduler) -> Self {
        let indices = scheduler.indices;
        let state = scheduler.state;
        let current = scheduler.current;

        Self {
            current,
            indices,
            scheduled: HashSet::new(),
            state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpora::{RangeCorpus, Wordlist};
    use crate::requests::{Request, ShouldFuzz};

    /// test that the iterator works as expected
    #[test]
    fn test_product_iterator() {
        let users = Wordlist::new()
            .words(["user", "admin"])
            .name("users")
            .build();
        let ids = RangeCorpus::with_stop(5).name("ids").build().unwrap();

        let state = SharedState::with_corpora([ids, users]);

        let order = ["users", "ids"];
        let mut scheduler = UniqueProductScheduler::new(order, state).unwrap();

        let mut counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // users.len() * ids.len() = 2 * 5 = 10
        assert_eq!(counter, 10);
    }

    /// test that the iterator works as expected when there is only one corpus
    #[test]
    fn test_product_iterator_with_single_corpus() {
        let users = Wordlist::new()
            .words(["user", "admin"])
            .name("users")
            .build();

        let state = SharedState::with_corpus(users);

        let order = ["users"];
        let mut scheduler = UniqueProductScheduler::new(order, state).unwrap();

        let mut counter = 0;

        while Iterator::next(&mut scheduler).is_some() {
            counter += 1;
        }

        // users.len() == 2
        assert_eq!(counter, 2);

        scheduler.reset();
    }

    /// test that the iterator works as expected when a corpus has an entry added to it
    #[test]
    fn test_product_iterator_with_add_to_corpus() {
        let users = Wordlist::new()
            .words(["user", "admin"])
            .name("users")
            .build();

        let ids = RangeCorpus::with_stop(5).name("ids").build().unwrap();

        let state = SharedState::with_corpora([ids, users]);

        let order = ["users", "ids"];
        let mut scheduler = UniqueProductScheduler::new(order, state.clone()).unwrap();

        let mut counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // users.len() * ids.len() = 2 * 5 = 10
        assert_eq!(counter, 10);

        // request with a fuzzable field, that should propogate to the corpus as an additional entry
        let request = Request::from_url(
            "http://localhost",
            Some(&[ShouldFuzz::RequestBody(b"administrator")]),
        )
        .unwrap();

        state
            .add_request_fields_to_corpus("users", &request)
            .unwrap();

        let users_corpus = state.corpus_by_name("users").unwrap();
        assert_eq!(users_corpus.len(), 3); // new user made it to the corpus

        scheduler.reset();

        counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // users.len() * ids.len() = 3 * 5 = 15
        assert_eq!(counter, 15);

        // try it again with both corpora having an entry added to them

        state.add_request_fields_to_corpus("ids", &request).unwrap();
        state
            .add_request_fields_to_corpus("users", &request)
            .unwrap();

        let ids_corpus = state.corpus_by_name("ids").unwrap();

        assert_eq!(users_corpus.len(), 4);
        assert_eq!(ids_corpus.len(), 6);

        scheduler.reset();

        counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // users.len() * ids.len() = 4 * 6 = 24
        assert_eq!(counter, 24);
    }

    /// test that the iterator works as expected when a corpus has an entry added to it
    ///
    /// differs from teh test above in that we'll use the set of values i used to build
    /// the product scheduler
    ///
    /// given the corpus lengths `[4, 3, 3, 3]`, and a `UniqueProductScheduler`, the
    /// expected iterations would be `[4, 12, 36, 108]`
    #[test]
    fn test_product_iterator_with_add_to_corpus_complex() {
        let outer = RangeCorpus::with_stop(2).name("outer").build().unwrap();
        let first_middle = RangeCorpus::with_stop(1)
            .name("first_middle")
            .build()
            .unwrap();
        let second_middle = RangeCorpus::with_stop(1)
            .name("second_middle")
            .build()
            .unwrap();
        let inner = RangeCorpus::with_stop(1).name("inner").build().unwrap();

        assert_eq!(outer.len(), 2);
        assert_eq!(first_middle.len(), 1);
        assert_eq!(second_middle.len(), 1);
        assert_eq!(inner.len(), 1);

        let state = SharedState::with_corpora([outer, first_middle, second_middle, inner]);

        let order = ["outer", "first_middle", "second_middle", "inner"];
        let mut scheduler = UniqueProductScheduler::new(order, state.clone()).unwrap();

        let mut counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // 2 * 1 * 1 * 1 = 1
        assert_eq!(counter, 2);

        // request with 2 fuzzable fields
        let request = Request::from_url(
            "http://localhost/admin",
            Some(&[
                ShouldFuzz::RequestBody(b"administrator"),
                ShouldFuzz::URLPath,
            ]),
        )
        .unwrap();

        // when added to each corpus their legnth should increase by 2
        for name in order {
            state.add_request_fields_to_corpus(name, &request).unwrap();
        }

        assert_eq!(state.corpus_by_name("outer").unwrap().len(), 4);
        assert_eq!(state.corpus_by_name("first_middle").unwrap().len(), 3);
        assert_eq!(state.corpus_by_name("second_middle").unwrap().len(), 3);
        assert_eq!(state.corpus_by_name("inner").unwrap().len(), 3);

        scheduler.reset();

        counter = 0;

        while Scheduler::next(&mut scheduler).is_ok() {
            counter += 1;
        }

        // 4 * 3 * 3 * 3 = 108
        assert_eq!(counter, 108);
    }
}
