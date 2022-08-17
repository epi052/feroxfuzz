//! re-exports some of libafl's mutators after implementing the [`Mutator`] trait
#![allow(clippy::use_self)] // clippy false-positive
#![allow(clippy::cast_possible_truncation)] // we'll be okay with this one
use std::cmp::min;
use std::sync::atomic::Ordering;

use super::Mutator;
use crate::corpora::Corpus;
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::{atomic_load, AsBytes};

use libafl::bolts::rands::Rand;
use libafl::inputs::HasBytesVec;
use libafl::mutators::mutations::{buffer_copy, buffer_self_copy};
use libafl::state::{HasMaxSize, HasRand};
use tracing::{debug, error, instrument};

pub use libafl::mutators::mutations::{
    BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesDeleteMutator,
    BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator, BytesRandInsertMutator,
    BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordAddMutator,
    DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
};

/// An enum wrapper for libafl mutators that facilitates static dispatch
#[derive(Debug)]
#[non_exhaustive]
pub enum LibAflMutator {
    /// wrapper around the BitFlipMutator from libafl
    BitFlipMutator(BitFlipMutator),

    /// wrapper around the ByteAddMutator from libafl
    ByteAddMutator(ByteAddMutator),

    /// wrapper around the ByteDecMutator from libafl
    ByteDecMutator(ByteDecMutator),

    /// wrapper around the ByteFlipMutator from libafl
    ByteFlipMutator(ByteFlipMutator),

    /// wrapper around the ByteIncMutator from libafl
    ByteIncMutator(ByteIncMutator),

    /// wrapper around the ByteInterestingMutator from libafl
    ByteInterestingMutator(ByteInterestingMutator),

    /// wrapper around the ByteNegMutator from libafl
    ByteNegMutator(ByteNegMutator),

    /// wrapper around the ByteRandMutator from libafl
    ByteRandMutator(ByteRandMutator),

    /// wrapper around the BytesCopyMutator from libafl
    BytesCopyMutator(BytesCopyMutator),

    /// wrapper around the BytesDeleteMutator from libafl
    BytesDeleteMutator(BytesDeleteMutator),

    /// wrapper around the BytesExpandMutator from libafl
    BytesExpandMutator(BytesExpandMutator),

    /// wrapper around the BytesInsertCopyMutator from libafl
    BytesInsertCopyMutator(BytesInsertCopyMutator),

    /// wrapper around the BytesInsertMutator from libafl
    BytesInsertMutator(BytesInsertMutator),

    /// wrapper around the BytesRandInsertMutator from libafl
    BytesRandInsertMutator(BytesRandInsertMutator),

    /// wrapper around the BytesRandSetMutator from libafl
    BytesRandSetMutator(BytesRandSetMutator),

    /// wrapper around the BytesSetMutator from libafl
    BytesSetMutator(BytesSetMutator),

    /// wrapper around the BytesSwapMutator from libafl
    BytesSwapMutator(BytesSwapMutator),

    /// wrapper around the CrossoverInsertMutator from libafl
    CrossoverInsertMutator(CrossoverInsertMutator),

    /// wrapper around the CrossoverReplaceMutator from libafl
    CrossoverReplaceMutator(CrossoverReplaceMutator),

    /// wrapper around the DwordAddMutator from libafl
    DwordAddMutator(DwordAddMutator),

    /// wrapper around the DwordInterestingMutator from libafl
    DwordInterestingMutator(DwordInterestingMutator),

    /// wrapper around the QwordAddMutator from libafl
    QwordAddMutator(QwordAddMutator),

    /// wrapper around the WordAddMutator from libafl
    WordAddMutator(WordAddMutator),

    /// wrapper around the WordInterestingMutator from libafl
    WordInterestingMutator(WordInterestingMutator),
}

impl Mutator for LibAflMutator {
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        match self {
            LibAflMutator::BitFlipMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteAddMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteDecMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteFlipMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteIncMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteInterestingMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteNegMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::ByteRandMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesCopyMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesDeleteMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesExpandMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesInsertCopyMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesInsertMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesRandInsertMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesRandSetMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesSetMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::BytesSwapMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::CrossoverInsertMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::CrossoverReplaceMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::DwordAddMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::DwordInterestingMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::QwordAddMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::WordAddMutator(mutator) => mutator.mutate(input, state),
            LibAflMutator::WordInterestingMutator(mutator) => mutator.mutate(input, state),
        }
    }
}

macro_rules! impl_libafl_mutation {
    // mutation_type is the type of the libafl mutator, e.g. BitFlipMutator
    ($mutation_type:ty) => {
        impl Mutator for $mutation_type {
            #[instrument(skip_all, level = "trace")]
            fn mutate(
                &mut self,
                input: &mut Data,
                state: &mut SharedState,
            ) -> Result<(), FeroxFuzzError> {
                if input.is_fuzzable() {
                    // data is fuzzable, need to mutate it

                    // create a new libafl mutator, BitFlipMutator, etc...
                    let mut mutator = <$mutation_type>::new();

                    // need to use the fully qualified name here to avoid the trait clash between libafl's and ferox's Mutator
                    <$mutation_type as libafl::mutators::Mutator<_, _>>::mutate(
                        &mut mutator,
                        state,
                        input,
                        0, // none of these mutators use a corpus index, so we can simply pass a dummy value here
                    )
                    .map_err(|source| {
                        error!("LibAFL mutator failed: {}", source);
                        FeroxFuzzError::FailedMutation { source }
                    })?;
                }

                Ok(())
            }
        }
    };
}

// call impl_libafl_mutation! for each of the libafl mutation types
impl_libafl_mutation!(BitFlipMutator);
impl_libafl_mutation!(ByteAddMutator);
impl_libafl_mutation!(ByteDecMutator);
impl_libafl_mutation!(ByteFlipMutator);
impl_libafl_mutation!(ByteIncMutator);
impl_libafl_mutation!(ByteInterestingMutator);
impl_libafl_mutation!(ByteNegMutator);
impl_libafl_mutation!(ByteRandMutator);
impl_libafl_mutation!(BytesCopyMutator);
impl_libafl_mutation!(BytesDeleteMutator);
impl_libafl_mutation!(BytesExpandMutator);
impl_libafl_mutation!(BytesInsertCopyMutator);
impl_libafl_mutation!(BytesInsertMutator);
impl_libafl_mutation!(BytesRandInsertMutator);
impl_libafl_mutation!(BytesRandSetMutator);
impl_libafl_mutation!(BytesSetMutator);
impl_libafl_mutation!(BytesSwapMutator);
impl_libafl_mutation!(DwordAddMutator);
impl_libafl_mutation!(DwordInterestingMutator);
impl_libafl_mutation!(QwordAddMutator);
impl_libafl_mutation!(WordAddMutator);
impl_libafl_mutation!(WordInterestingMutator);

// the following are the libafl mutation types that can't be implemented with the macro above
// this is because they use splicing from one corpus entry to another, which is not supported
// by the macro. We'll need to hand-roll the splicing impls ourselves. I attempted to do this
// by implementing the required libafl traits for state/corpus (HasCorpus et al), but the
// async code from feroxfuzz doesn't jive with parts of libafl.
//
// to be clear, when i say hand-rolled, i mean that i copied the contents of the libafl
// mutators in question, and then tweaked them to work with feroxfuzz's idea of state/corpus.
//
// libafl commit from which i pulled the below impls: 253c6b5bdc2e05ecff687eea630849dc45a956d4

/// Crossover insert mutation for inputs with a bytes vector
///
/// ported from libafl's `CrossoverInsertMutator`
#[derive(Default, Debug)]
pub struct CrossoverInsertMutator {
    corpus_name: String,
}

impl CrossoverInsertMutator {
    /// Create a new [`CrossoverInsertMutator`]
    #[must_use]
    pub fn new(corpus_name: &str) -> Self {
        Self {
            corpus_name: corpus_name.to_owned(),
        }
    }
}

impl Mutator for CrossoverInsertMutator {
    #[instrument(skip_all, fields(%self.corpus_name), level = "trace")]
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        let corpus = state.corpus_by_name(&self.corpus_name)?;

        // size of the current Data object
        let size = input.bytes().len();

        // size of the corpus, used to grab a random entry from the corpus
        let count = corpus.len();
        let random_index = state.rand_mut().below(count as u64) as usize;

        let scheduled_idx = state.corpus_index_by_name(&self.corpus_name)?;

        // if the random index is the same as the current index, we'll just return
        // as we don't want to splice with ourselves
        if random_index == atomic_load!(scheduled_idx) {
            return Ok(());
        }

        if let Ok(guard) = corpus.read() {
            let result = guard.get(random_index);

            if result.is_none() {
                // using is_none with a return instead of a map_err because the
                // guard can't be borrowed twice in order to get the .name() of the corpus
                error!(name=guard.name(), index=%random_index, "corpus entry not found");

                return Err(FeroxFuzzError::CorpusEntryNotFound {
                    name: guard.name().to_string(),
                    index: random_index,
                });
            }

            let other_entry = result.unwrap();

            let other_size = other_entry.as_bytes().len();

            if other_size < 2 {
                // other entry is too small to splice with, so we'll just return
                return Ok(());
            }

            // compute size bounds for the splice
            let max_size = state.max_size();
            let from = state.rand_mut().below(other_size as u64) as usize;
            let to = state.rand_mut().below(size as u64) as usize;
            let mut len = 1 + state.rand_mut().below((other_size - from) as u64) as usize;

            if size + len > max_size {
                if max_size > size {
                    len = max_size - size;
                } else {
                    // exceeded maximum size, so we'll just return
                    debug!(%size, %max_size, "exceeded maximum size; skipping mutation");
                    return Ok(());
                }
            }

            // perform the actual mutation
            input.bytes_mut().resize(size + len, 0);
            buffer_self_copy(input.bytes_mut(), to, to + len, size - to);
            buffer_copy(input.bytes_mut(), other_entry.as_bytes(), from, to, len);
        }

        Ok(())
    }
}

/// Crossover replace mutation for inputs with a bytes vector
///
/// ported from libafl's `CrossoverReplaceMutator`

#[derive(Default, Debug)]
pub struct CrossoverReplaceMutator {
    corpus_name: String,
}

impl CrossoverReplaceMutator {
    /// Creates a new [`CrossoverReplaceMutator`].
    #[must_use]
    pub fn new(corpus_name: &str) -> Self {
        Self {
            corpus_name: corpus_name.to_owned(),
        }
    }
}

impl Mutator for CrossoverReplaceMutator {
    #[instrument(skip_all, fields(%self.corpus_name), level = "trace")]
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        // size of the current Data object
        let size = input.bytes().len();

        if size == 0 {
            return Ok(());
        }

        let corpus = state.corpus_by_name(&self.corpus_name)?;

        // size of the corpus, used to grab a random entry from the corpus
        let count = corpus.len();
        let random_index = state.rand_mut().below(count as u64) as usize;

        let scheduled_idx = state.corpus_index_by_name(&self.corpus_name)?;

        // if the random index is the same as the current index, we'll just return
        // as we don't want to splice with ourselves
        if random_index == atomic_load!(scheduled_idx) {
            return Ok(());
        }

        if let Ok(guard) = corpus.read() {
            let result = guard.get(random_index);

            if result.is_none() {
                // using is_none with a return instead of a map_err because the
                // guard can't be borrowed twice in order to get the .name() of the corpus
                error!(name=guard.name(), index=%random_index, "corpus entry not found");

                return Err(FeroxFuzzError::CorpusEntryNotFound {
                    name: guard.name().to_string(),
                    index: random_index,
                });
            }

            let other_entry = result.unwrap();

            let other_size = other_entry.as_bytes().len();

            if other_size < 2 {
                // other entry is too small to splice with, so we'll just return
                return Ok(());
            }

            // compute size bounds for the splice
            let from = state.rand_mut().below(other_size as u64) as usize;
            let len = state.rand_mut().below(min(other_size - from, size) as u64) as usize;
            let to = state.rand_mut().below((size - len) as u64) as usize;

            buffer_copy(input.bytes_mut(), other_entry.as_bytes(), from, to, len);
        }

        Ok(())
    }
}
