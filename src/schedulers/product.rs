use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::{set_states_corpus_index, CorpusIndex, Scheduler};
use crate::error::FeroxFuzzError;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::tuple::Named;

use tracing::{error, instrument, trace, warn};

/// Cartesian product of multiple [`Corpus`] entries
///
/// [`Corpus`]: crate::corpora::Corpus
///
/// roughly equivalent to nested for-loops
///
/// # Examples
///
/// if you have a corpus with the following entries:
///
/// Users: ["user1", "user2", "user3"]
/// Passwords: ["pass1", "pass2", "pass3"]
///
/// then the Cartesian product of the two corpora would be:
///
///   user1: pass1
///   user1: pass2
///   user1: pass3
///   user2: pass1
///   user2: pass2
///   user2: pass3
///   user3: pass1
///   user3: pass2
///   user3: pass3
///
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProductScheduler {
    current: AtomicUsize,
    indices: Arc<Mutex<Vec<CorpusIndex>>>,

    #[cfg_attr(feature = "serde", serde(skip))]
    state: SharedState,
}

impl Clone for ProductScheduler {
    fn clone(&self) -> Self {
        Self {
            current: AtomicUsize::new(self.current.load(Ordering::Relaxed)),
            indices: self.indices.clone(),
            state: self.state.clone(),
        }
    }
}

impl Scheduler for ProductScheduler {
    #[instrument(skip(self), fields(?self.current, ?self.indices), level = "trace")]
    fn next(&mut self) -> Result<(), FeroxFuzzError> {
        if let Ok(mut guard) = self.indices.lock() {
            // increment the zeroth index on every call to scheduler.next(); the zeroth
            // index is the innermost loop (since we reversed the vec) and should be
            // incremented every time.
            //
            // raises an error if the zeroth index has reached the total number of
            // expected iterations
            //
            // since we check the length of the incoming corpus iterator in the
            // constructor, we know we have at least one entry in `self.indices`
            let num_indices = guard.len();

            // this shouldn't ever error, since we have at least one corpus; at worst, inner and outer
            // are the same corpus
            let outermost = guard.last().ok_or_else(|| {
                error!("scheduler has no associated CorpusIndex");
                FeroxFuzzError::EmptyCorpusIndices
            })?;

            let current = self.current.load(Ordering::SeqCst);

            if current > 0 && outermost.should_reset(current) {
                // when the outermost loop reaches the end of its loop, the entire
                // nested loop structure has run to completion
                trace!("scheduler has run to completion");
                return Err(FeroxFuzzError::IterationStopped);
            }

            let innermost = &mut guard[0];

            innermost.next()?;

            // if we have a single entry, we're done, just need to set the state's view
            // of the current index to what was calculated here
            if num_indices == 1 {
                set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

                self.current.fetch_add(1, Ordering::Relaxed); // update the total number of times .next has been called

                return Ok(());
            }

            if !innermost.should_reset(self.current.load(Ordering::SeqCst)) {
                // if the current scheduler.next iteration is not a modulo value
                // for the innermost loop, we don't need to progress any further
                set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

                self.current.fetch_add(1, Ordering::Relaxed); // update the total number of times .next has been called

                return Ok(());
            }

            // innermost loop has completed a full iteration, so we need to reset
            innermost.reset();

            set_states_corpus_index(&self.state, innermost.name(), innermost.current())?;

            // the for loop below iterates over an unknown number of corpora lengths
            // and increments each scheduled index if their previous index's modulo
            // value was 0. In the case of the first index, this will always be true
            // since we just determined the innermost loop's modulo value above.

            // The pattern is that when an index reaches its modulo value, it is
            // reset to 0 and the next greater loop is incremented.
            for index in guard[1..].iter_mut() {
                // due to len==1 check above, the slice is ok
                index.next()?;

                if !index.should_reset(self.current.load(Ordering::SeqCst)) {
                    // if the current index is not yet at its modulo value,
                    // continue to the next iteration, since it's not time to
                    // increment any further indices
                    //
                    // recall that the innermost loop is the first index in the vec
                    // and the outermost loop is the last index in the vec. so we
                    // only progress to each outer-more loop when the current inner-more
                    // loop has completed a full iteration.
                    set_states_corpus_index(&self.state, index.name(), index.current())?;
                    break;
                }

                index.reset();

                set_states_corpus_index(&self.state, index.name(), index.current())?;
            }

            self.current.fetch_add(1, Ordering::Relaxed); // update the total number of times .next has been called
        } else {
            warn!("failed to acquire Scheduler lock; cannot advance iterator");
        };

        Ok(())
    }

    /// resets all indexes that are tracked by the scheduler as well as their associated atomic
    /// indexes in the [`SharedState`] instance
    #[instrument(skip(self), level = "trace")]
    fn reset(&mut self) {
        self.current.store(0, Ordering::Relaxed);

        let mut total_iterations = 1;

        if let Ok(mut guard) = self.indices.lock() {
            guard.iter_mut().for_each(|index| {
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
        } else {
            warn!("failed to acquire Scheduler lock; cannot reset iterator");
        };
    }

    fn update_length(&mut self) {
        // basically the same logic as reset, but we don't need to reset the index, nor reset
        // the state's view of the index
        let mut total_iterations = 1;

        if let Ok(mut guard) = self.indices.lock() {
            guard.iter_mut().for_each(|index| {
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
            });
        } else {
            warn!("failed to acquire Scheduler lock; cannot update Scheduler length");
        }
    }
}

impl ProductScheduler {
    /// create a new `ProductScheduler` scheduler
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
    /// use feroxfuzz::schedulers::{Scheduler, ProductScheduler};
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
    #[instrument(skip(state), level = "trace")]
    pub fn new<'a, I>(corpus_order: I, state: SharedState) -> Result<Self, FeroxFuzzError>
    where
        I: IntoIterator<Item = &'a str> + std::fmt::Debug,
    {
        let corpora = state.corpora();

        let mut lengths = Vec::with_capacity(corpora.len());

        for name in corpus_order {
            let corpus = state.corpus_by_name(name)?;

            let length = corpus.len();

            if length == 0 {
                // one of the corpora was empty
                error!(%name, "corpus is empty");

                return Err(FeroxFuzzError::EmptyCorpus {
                    name: name.to_string(),
                });
            }

            lengths.push((name, length));
        }

        if lengths.is_empty() {
            // empty iterator passed in
            error!("no corpora were found");
            return Err(FeroxFuzzError::EmptyCorpusMap);
        }

        let mut indices = Vec::with_capacity(lengths.len());
        let mut total_iterations = 1;

        for (name, length) in lengths.iter().rev() {
            // iterate over the lengths of the corpora, in reverse, in order to
            // determine the modulo value for each outer loop. the modulo value
            // determines when the index should be reset to 0.
            //
            // when the outermost loop reaches its modulo value, the entire
            // nested loop structure has run to completion
            total_iterations *= *length;
            indices.push(CorpusIndex::new(name, *length, total_iterations));
        }

        Ok(Self {
            indices: Arc::new(Mutex::new(indices)),
            state,
            current: AtomicUsize::new(0),
        })
    }
}

#[allow(clippy::copy_iterator)]
impl Iterator for ProductScheduler {
    type Item = ();

    fn next(&mut self) -> Option<Self::Item> {
        Scheduler::next(self).ok()
    }
}

impl Named for ProductScheduler {
    fn name(&self) -> &str {
        "ProductScheduler"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atomic_load;
    use crate::corpora::{RangeCorpus, Wordlist};
    use crate::requests::{Request, ShouldFuzz};
    use std::sync::atomic::Ordering;

    /// test that the call to `set_states_corpus_index` behaves as expected
    #[test]
    fn test_corpus_index_is_set_in_state() {
        let users = Wordlist::new()
            .name("users")
            .word("user")
            .word("admin")
            .build();
        let state = SharedState::with_corpus(users);

        set_states_corpus_index(&state, "users", 1).unwrap();
        assert_eq!(
            atomic_load!(state.corpus_index_by_name("users").unwrap()),
            1
        );

        assert!(set_states_corpus_index(&state, "non-existent", 1).is_err());

        set_states_corpus_index(&state, "users", 43278).unwrap();
        assert_eq!(
            atomic_load!(state.corpus_index_by_name("users").unwrap()),
            43278
        );
    }

    /// test that a non-existent corpus name returns an error when passed as the ordering iterable
    #[test]
    fn test_product_with_non_existent_corpus() {
        let users = Wordlist::new()
            .name("users")
            .words(["user", "admin"])
            .build();

        let state = SharedState::with_corpus(users);

        let result = ProductScheduler::new(["derp"], state);

        assert!(result.is_err());
    }

    /// test that an empty corpus returns an error when passed to the constructor
    #[test]
    fn test_product_with_empty_corpus() {
        let range = RangeCorpus::with_stop(0).name("range").build();
        assert!(range.is_err());

        let state = SharedState::with_corpus(
            Wordlist::with_words(Vec::<String>::new())
                .name("empty")
                .build(),
        );

        let result = ProductScheduler::new(["range"], state);
        assert!(result.is_err());
    }

    /// test that an empty set of corpora returns an error when passed to the constructor
    #[test]
    fn test_product_with_empty_corpora() {
        let state = SharedState::with_corpora([]);

        let result = ProductScheduler::new(["users"], state);

        assert!(result.is_err());
    }

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
        let mut scheduler = ProductScheduler::new(order, state).unwrap();

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
        let mut scheduler = ProductScheduler::new(order, state).unwrap();

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
        let mut scheduler = ProductScheduler::new(order, state.clone()).unwrap();

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
    /// given the corpus lengths `[4, 3, 3, 3]`, and a `ProductScheduler`, the
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
        let mut scheduler = ProductScheduler::new(order, state.clone()).unwrap();

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
