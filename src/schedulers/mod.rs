//! scheduled access to corpus entries

use crate::atomic_store;
use crate::error::FeroxFuzzError;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::tuple::Named;

use std::sync::atomic::Ordering;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod ordered;
mod product;
mod random;

pub use ordered::OrderedScheduler;
pub use product::ProductScheduler;
pub use random::RandomScheduler;

/// manages how the fuzzer gets entries from the corpus
pub trait Scheduler: Named {
    /// get the next entry from the corpus
    ///
    /// # Errors
    ///
    /// implementors may return an error if the next entry cannot be retrieved
    fn next(&mut self) -> Result<(), FeroxFuzzError>;

    /// reset the internal state of the `Scheduler`, typically called by the [`Fuzzer`]
    /// once a full iteration of the [`Corpus`] is complete
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    /// [`Fuzzer`]: crate::fuzzers::Fuzzer
    fn reset(&mut self);
}

// simple private helper that gets the atomic index from corpus_indices
// and then stores the given value in the index
fn set_states_corpus_index(
    state: &SharedState,
    corpus_name: &str,
    value: usize,
) -> Result<(), FeroxFuzzError> {
    let atomic_index = state.corpus_index_by_name(corpus_name)?;
    atomic_store!(atomic_index, value);
    Ok(())
}

/// private implementation detail of [`Scheduler`] algorithms
#[derive(Clone, Debug, Default, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct CorpusIndex {
    name: String,
    current: usize,

    // the overall length of the corpus, i.e. value returned by `corpus.len()`
    length: usize,

    // total number of iterations that this particular
    // index is expected to make in order to make one full circuit of its
    // associated corpus
    //
    // example:
    //
    // given the corpus lengths `[4, 3, 3, 3]`, and a ProductScheduler, the
    // expected iterations would be `[4, 12, 36, 108]`
    iterations: usize,
}

impl CorpusIndex {
    fn new(name: &str, length: usize, iterations: usize) -> Self {
        Self {
            name: name.to_owned(),
            current: 0,
            length,
            iterations,
        }
    }

    #[inline]
    const fn should_reset(&self, total_iterations: usize) -> bool {
        total_iterations % self.iterations == 0
    }

    #[inline]
    fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    fn next(&mut self) -> Result<(), FeroxFuzzError> {
        if self.current == self.length {
            return Err(FeroxFuzzError::IterationStopped);
        }

        self.current += 1;

        Ok(())
    }

    #[inline]
    const fn current(&self) -> usize {
        self.current
    }

    #[inline]
    fn reset(&mut self) {
        self.current = 0;
    }

    #[inline]
    fn update_length(&mut self, length: usize) {
        self.length = length;
    }

    #[inline]
    fn update_iterations(&mut self, iterations: usize) {
        self.iterations = iterations;
    }
}

impl Len for CorpusIndex {
    fn len(&self) -> usize {
        self.length
    }
}
