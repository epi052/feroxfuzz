//! re-exports some of libafl's mutators after implementing the [`Mutator`] trait
#![allow(clippy::use_self)] // clippy false-positive
#![allow(clippy::cast_possible_truncation)] // we'll be okay with this one
use std::any::Any;
use std::cmp::min;
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::Ordering;

use super::Mutator;
use crate::corpora::Corpus;
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::metadata::AsAny;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::tuple::Named;
use crate::{atomic_load, AsBytes};

use libafl::inputs::HasBytesVec;
use libafl::state::{HasMaxSize, HasRand};
use libafl_bolts::rands::Rand;
#[cfg(feature = "serde")]
use serde::{
    de::{self, Deserialize, Deserializer, MapAccess, Visitor},
    ser::{Serialize, Serializer},
};
use tracing::{debug, error, instrument};

pub use libafl::mutators::mutations::{
    BitFlipMutator, ByteAddMutator, ByteDecMutator, ByteFlipMutator, ByteIncMutator,
    ByteInterestingMutator, ByteNegMutator, ByteRandMutator, BytesCopyMutator, BytesDeleteMutator,
    BytesExpandMutator, BytesInsertCopyMutator, BytesInsertMutator, BytesRandInsertMutator,
    BytesRandSetMutator, BytesSetMutator, BytesSwapMutator, DwordAddMutator,
    DwordInterestingMutator, QwordAddMutator, WordAddMutator, WordInterestingMutator,
};

// note: the following two functions are from libafl, they were a part of the public api
// and then were later made private. there wasn't a public replacement, so in the interest
// of time, they're copied here

/// Mem move in the own vec
#[inline]
pub fn buffer_self_copy<T>(data: &mut [T], from: usize, to: usize, len: usize) {
    debug_assert!(!data.is_empty());
    debug_assert!(from + len <= data.len());
    debug_assert!(to + len <= data.len());
    if len != 0 && from != to {
        let ptr = data.as_mut_ptr();
        unsafe {
            core::ptr::copy(ptr.add(from), ptr.add(to), len);
        }
    }
}

/// Mem move between vecs
#[inline]
pub fn buffer_copy<T>(dst: &mut [T], src: &[T], from: usize, to: usize, len: usize) {
    debug_assert!(!dst.is_empty());
    debug_assert!(!src.is_empty());
    debug_assert!(from + len <= src.len());
    debug_assert!(to + len <= dst.len());
    let dst_ptr = dst.as_mut_ptr();
    let src_ptr = src.as_ptr();
    if len != 0 {
        unsafe {
            core::ptr::copy(src_ptr.add(from), dst_ptr.add(to), len);
        }
    }
}

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

#[allow(clippy::too_many_lines)] // excuse the heck outta me, clippy
impl Mutator for LibAflMutator {
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        if !input.is_fuzzable() {
            // we can't mutate non-fuzzable data
            return Ok(());
        }

        match self {
            LibAflMutator::BitFlipMutator(mutator) => {
                <BitFlipMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteAddMutator(mutator) => {
                <ByteAddMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteDecMutator(mutator) => {
                <ByteDecMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteFlipMutator(mutator) => {
                <ByteFlipMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteIncMutator(mutator) => {
                <ByteIncMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteInterestingMutator(mutator) => {
                <ByteInterestingMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteNegMutator(mutator) => {
                <ByteNegMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::ByteRandMutator(mutator) => {
                <ByteRandMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesCopyMutator(mutator) => {
                <BytesCopyMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesDeleteMutator(mutator) => {
                <BytesDeleteMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesExpandMutator(mutator) => {
                <BytesExpandMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesInsertCopyMutator(mutator) => {
                <BytesInsertCopyMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesInsertMutator(mutator) => {
                <BytesInsertMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesRandInsertMutator(mutator) => {
                <BytesRandInsertMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesRandSetMutator(mutator) => {
                <BytesRandSetMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesSetMutator(mutator) => {
                <BytesSetMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::BytesSwapMutator(mutator) => {
                <BytesSwapMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::CrossoverInsertMutator(mutator) => return mutator.mutate(input, state),
            LibAflMutator::CrossoverReplaceMutator(mutator) => return mutator.mutate(input, state),
            LibAflMutator::DwordAddMutator(mutator) => {
                <DwordAddMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::DwordInterestingMutator(mutator) => {
                <DwordInterestingMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::QwordAddMutator(mutator) => {
                <QwordAddMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::WordAddMutator(mutator) => {
                <WordAddMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
            LibAflMutator::WordInterestingMutator(mutator) => {
                <WordInterestingMutator as libafl::mutators::Mutator<_, _>>::mutate(
                    mutator, state, input, 0,
                )
            }
        }
        .map_err(|source| {
            error!("LibAFL mutator failed: {}", source);
            FeroxFuzzError::MutationError { source }
        })?;

        Ok(())
    }
}

impl Named for LibAflMutator {
    fn name(&self) -> &str {
        match self {
            LibAflMutator::BitFlipMutator(mutator) => mutator.name(),
            LibAflMutator::ByteAddMutator(mutator) => mutator.name(),
            LibAflMutator::ByteDecMutator(mutator) => mutator.name(),
            LibAflMutator::ByteFlipMutator(mutator) => mutator.name(),
            LibAflMutator::ByteIncMutator(mutator) => mutator.name(),
            LibAflMutator::ByteInterestingMutator(mutator) => mutator.name(),
            LibAflMutator::ByteNegMutator(mutator) => mutator.name(),
            LibAflMutator::ByteRandMutator(mutator) => mutator.name(),
            LibAflMutator::BytesCopyMutator(mutator) => mutator.name(),
            LibAflMutator::BytesDeleteMutator(mutator) => mutator.name(),
            LibAflMutator::BytesExpandMutator(mutator) => mutator.name(),
            LibAflMutator::BytesInsertCopyMutator(mutator) => mutator.name(),
            LibAflMutator::BytesInsertMutator(mutator) => mutator.name(),
            LibAflMutator::BytesRandInsertMutator(mutator) => mutator.name(),
            LibAflMutator::BytesRandSetMutator(mutator) => mutator.name(),
            LibAflMutator::BytesSetMutator(mutator) => mutator.name(),
            LibAflMutator::BytesSwapMutator(mutator) => mutator.name(),
            LibAflMutator::CrossoverInsertMutator(mutator) => mutator.name(),
            LibAflMutator::CrossoverReplaceMutator(mutator) => mutator.name(),
            LibAflMutator::DwordAddMutator(mutator) => mutator.name(),
            LibAflMutator::DwordInterestingMutator(mutator) => mutator.name(),
            LibAflMutator::QwordAddMutator(mutator) => mutator.name(),
            LibAflMutator::WordAddMutator(mutator) => mutator.name(),
            LibAflMutator::WordInterestingMutator(mutator) => mutator.name(),
        }
    }
}

impl AsAny for LibAflMutator {
    fn as_any(&self) -> &dyn Any {
        match self {
            LibAflMutator::BitFlipMutator(mutator) => mutator,
            LibAflMutator::ByteAddMutator(mutator) => mutator,
            LibAflMutator::ByteDecMutator(mutator) => mutator,
            LibAflMutator::ByteFlipMutator(mutator) => mutator,
            LibAflMutator::ByteIncMutator(mutator) => mutator,
            LibAflMutator::ByteInterestingMutator(mutator) => mutator,
            LibAflMutator::ByteNegMutator(mutator) => mutator,
            LibAflMutator::ByteRandMutator(mutator) => mutator,
            LibAflMutator::BytesCopyMutator(mutator) => mutator,
            LibAflMutator::BytesDeleteMutator(mutator) => mutator,
            LibAflMutator::BytesExpandMutator(mutator) => mutator,
            LibAflMutator::BytesInsertCopyMutator(mutator) => mutator,
            LibAflMutator::BytesInsertMutator(mutator) => mutator,
            LibAflMutator::BytesRandInsertMutator(mutator) => mutator,
            LibAflMutator::BytesRandSetMutator(mutator) => mutator,
            LibAflMutator::BytesSetMutator(mutator) => mutator,
            LibAflMutator::BytesSwapMutator(mutator) => mutator,
            LibAflMutator::CrossoverInsertMutator(mutator) => mutator,
            LibAflMutator::CrossoverReplaceMutator(mutator) => mutator,
            LibAflMutator::DwordAddMutator(mutator) => mutator,
            LibAflMutator::DwordInterestingMutator(mutator) => mutator,
            LibAflMutator::QwordAddMutator(mutator) => mutator,
            LibAflMutator::WordAddMutator(mutator) => mutator,
            LibAflMutator::WordInterestingMutator(mutator) => mutator,
        }
    }
}

impl Clone for LibAflMutator {
    fn clone(&self) -> Self {
        match self {
            LibAflMutator::BitFlipMutator(_mutator) => {
                LibAflMutator::BitFlipMutator(BitFlipMutator::new())
            }
            LibAflMutator::ByteAddMutator(_mutator) => {
                LibAflMutator::ByteAddMutator(ByteAddMutator::new())
            }
            LibAflMutator::ByteDecMutator(_mutator) => {
                LibAflMutator::ByteDecMutator(ByteDecMutator::new())
            }
            LibAflMutator::ByteFlipMutator(_mutator) => {
                LibAflMutator::ByteFlipMutator(ByteFlipMutator::new())
            }
            LibAflMutator::ByteIncMutator(_mutator) => {
                LibAflMutator::ByteIncMutator(ByteIncMutator::new())
            }
            LibAflMutator::ByteInterestingMutator(_mutator) => {
                LibAflMutator::ByteInterestingMutator(ByteInterestingMutator::new())
            }
            LibAflMutator::ByteNegMutator(_mutator) => {
                LibAflMutator::ByteNegMutator(ByteNegMutator::new())
            }
            LibAflMutator::ByteRandMutator(_mutator) => {
                LibAflMutator::ByteRandMutator(ByteRandMutator::new())
            }
            LibAflMutator::BytesCopyMutator(_mutator) => {
                LibAflMutator::BytesCopyMutator(BytesCopyMutator::new())
            }
            LibAflMutator::BytesDeleteMutator(_mutator) => {
                LibAflMutator::BytesDeleteMutator(BytesDeleteMutator::new())
            }
            LibAflMutator::BytesExpandMutator(_mutator) => {
                LibAflMutator::BytesExpandMutator(BytesExpandMutator::new())
            }
            LibAflMutator::BytesInsertCopyMutator(_mutator) => {
                LibAflMutator::BytesInsertCopyMutator(BytesInsertCopyMutator::new())
            }
            LibAflMutator::BytesInsertMutator(_mutator) => {
                LibAflMutator::BytesInsertMutator(BytesInsertMutator::new())
            }
            LibAflMutator::BytesRandInsertMutator(_mutator) => {
                LibAflMutator::BytesRandInsertMutator(BytesRandInsertMutator::new())
            }
            LibAflMutator::BytesRandSetMutator(_mutator) => {
                LibAflMutator::BytesRandSetMutator(BytesRandSetMutator::new())
            }
            LibAflMutator::BytesSetMutator(_mutator) => {
                LibAflMutator::BytesSetMutator(BytesSetMutator::new())
            }
            LibAflMutator::BytesSwapMutator(_mutator) => {
                LibAflMutator::BytesSwapMutator(BytesSwapMutator::new())
            }
            LibAflMutator::CrossoverInsertMutator(mutator) => {
                LibAflMutator::CrossoverInsertMutator(CrossoverInsertMutator::new(
                    &mutator.corpus_name,
                ))
            }
            LibAflMutator::CrossoverReplaceMutator(mutator) => {
                LibAflMutator::CrossoverReplaceMutator(CrossoverReplaceMutator::new(
                    &mutator.corpus_name,
                ))
            }
            LibAflMutator::DwordAddMutator(_mutator) => {
                LibAflMutator::DwordAddMutator(DwordAddMutator::new())
            }
            LibAflMutator::DwordInterestingMutator(_mutator) => {
                LibAflMutator::DwordInterestingMutator(DwordInterestingMutator::new())
            }
            LibAflMutator::QwordAddMutator(_mutator) => {
                LibAflMutator::QwordAddMutator(QwordAddMutator::new())
            }
            LibAflMutator::WordAddMutator(_mutator) => {
                LibAflMutator::WordAddMutator(WordAddMutator::new())
            }
            LibAflMutator::WordInterestingMutator(_mutator) => {
                LibAflMutator::WordInterestingMutator(WordInterestingMutator::new())
            }
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for LibAflMutator {
    /// Function that handles serialization of Stats
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            LibAflMutator::BitFlipMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 0, "BitFlipMutator", "")
            }
            LibAflMutator::ByteAddMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 1, "ByteAddMutator", "")
            }
            LibAflMutator::ByteDecMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 2, "ByteDecMutator", "")
            }
            LibAflMutator::ByteFlipMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 3, "ByteFlipMutator", "")
            }
            LibAflMutator::ByteIncMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 4, "ByteIncMutator", "")
            }
            LibAflMutator::ByteInterestingMutator(_mutator) => serializer
                .serialize_newtype_variant("LibAflMutator", 5, "ByteInterestingMutator", ""),
            LibAflMutator::ByteNegMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 6, "ByteNegMutator", "")
            }
            LibAflMutator::ByteRandMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 7, "ByteRandMutator", "")
            }
            LibAflMutator::BytesCopyMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 8, "BytesCopyMutator", "")
            }
            LibAflMutator::BytesDeleteMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 9, "BytesDeleteMutator", "")
            }
            LibAflMutator::BytesExpandMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 10, "BytesExpandMutator", "")
            }
            LibAflMutator::BytesInsertCopyMutator(_mutator) => serializer
                .serialize_newtype_variant("LibAflMutator", 11, "BytesInsertCopyMutator", ""),
            LibAflMutator::BytesInsertMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 12, "BytesInsertMutator", "")
            }
            LibAflMutator::BytesRandInsertMutator(_mutator) => serializer
                .serialize_newtype_variant("LibAflMutator", 13, "BytesRandInsertMutator", ""),
            LibAflMutator::BytesRandSetMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 14, "BytesRandSetMutator", "")
            }
            LibAflMutator::BytesSetMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 15, "BytesSetMutator", "")
            }
            LibAflMutator::BytesSwapMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 16, "BytesSwapMutator", "")
            }
            LibAflMutator::CrossoverInsertMutator(mutator) => serializer.serialize_newtype_variant(
                "LibAflMutator",
                17,
                "CrossoverInsertMutator",
                &mutator.corpus_name,
            ),
            LibAflMutator::CrossoverReplaceMutator(mutator) => serializer
                .serialize_newtype_variant(
                    "LibAflMutator",
                    18,
                    "CrossoverReplaceMutator",
                    &mutator.corpus_name,
                ),
            LibAflMutator::DwordAddMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 19, "DwordAddMutator", "")
            }
            LibAflMutator::DwordInterestingMutator(_mutator) => serializer
                .serialize_newtype_variant("LibAflMutator", 20, "DwordInterestingMutator", ""),
            LibAflMutator::QwordAddMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 21, "QwordAddMutator", "")
            }
            LibAflMutator::WordAddMutator(_mutator) => {
                serializer.serialize_newtype_variant("LibAflMutator", 22, "WordAddMutator", "")
            }
            LibAflMutator::WordInterestingMutator(_mutator) => serializer
                .serialize_newtype_variant("LibAflMutator", 23, "WordInterestingMutator", ""),
        }
    }
}

macro_rules! impl_libafl_mutation {
    // mutation_type is the type of the libafl mutator, e.g. BitFlipMutator
    ($mutation_type:ty) => {
        impl AsAny for $mutation_type {
            fn as_any(&self) -> &dyn Any {
                self
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
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl Named for CrossoverInsertMutator {
    fn name(&self) -> &str {
        "CrossoverInsertMutator"
    }
}

impl AsAny for CrossoverInsertMutator {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Crossover replace mutation for inputs with a bytes vector
///
/// ported from libafl's `CrossoverReplaceMutator`

#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl Named for CrossoverReplaceMutator {
    fn name(&self) -> &str {
        "CrossoverReplaceMutator"
    }
}

impl AsAny for CrossoverReplaceMutator {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(feature = "serde")]
struct LibAflMutatorVisitor<K, V> {
    _k: PhantomData<K>,
    _v: PhantomData<V>,
}

#[cfg(feature = "serde")]
impl<K, V> LibAflMutatorVisitor<K, V> {
    const fn new() -> Self {
        Self {
            _k: PhantomData,
            _v: PhantomData,
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for LibAflMutatorVisitor<String, String> {
    // The type that our Visitor is going to produce.
    type Value = LibAflMutator;

    // Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a LibAflMutator")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if let Some((key, value)) = map.next_entry::<String, String>()? {
            return match key.as_str() {
                "BitFlipMutator" => Ok(LibAflMutator::BitFlipMutator(BitFlipMutator::new())),
                "ByteAddMutator" => Ok(LibAflMutator::ByteAddMutator(ByteAddMutator::new())),
                "ByteDecMutator" => Ok(LibAflMutator::ByteDecMutator(ByteDecMutator::new())),
                "ByteFlipMutator" => Ok(LibAflMutator::ByteFlipMutator(ByteFlipMutator::new())),
                "ByteIncMutator" => Ok(LibAflMutator::ByteIncMutator(ByteIncMutator::new())),
                "ByteInterestingMutator" => Ok(LibAflMutator::ByteInterestingMutator(
                    ByteInterestingMutator::new(),
                )),
                "ByteNegMutator" => Ok(LibAflMutator::ByteNegMutator(ByteNegMutator::new())),
                "ByteRandMutator" => Ok(LibAflMutator::ByteRandMutator(ByteRandMutator::new())),
                "BytesCopyMutator" => Ok(LibAflMutator::BytesCopyMutator(BytesCopyMutator::new())),
                "BytesDeleteMutator" => {
                    Ok(LibAflMutator::BytesDeleteMutator(BytesDeleteMutator::new()))
                }
                "BytesExpandMutator" => {
                    Ok(LibAflMutator::BytesExpandMutator(BytesExpandMutator::new()))
                }
                "BytesInsertCopyMutator" => Ok(LibAflMutator::BytesInsertCopyMutator(
                    BytesInsertCopyMutator::new(),
                )),
                "BytesInsertMutator" => {
                    Ok(LibAflMutator::BytesInsertMutator(BytesInsertMutator::new()))
                }
                "BytesRandInsertMutator" => Ok(LibAflMutator::BytesRandInsertMutator(
                    BytesRandInsertMutator::new(),
                )),
                "BytesRandSetMutator" => Ok(LibAflMutator::BytesRandSetMutator(
                    BytesRandSetMutator::new(),
                )),
                "BytesSetMutator" => Ok(LibAflMutator::BytesSetMutator(BytesSetMutator::new())),
                "BytesSwapMutator" => Ok(LibAflMutator::BytesSwapMutator(BytesSwapMutator::new())),
                "CrossoverInsertMutator" => Ok(LibAflMutator::CrossoverInsertMutator(
                    CrossoverInsertMutator::new(&value),
                )),
                "CrossoverReplaceMutator" => Ok(LibAflMutator::CrossoverReplaceMutator(
                    CrossoverReplaceMutator::new(&value),
                )),
                "DwordAddMutator" => Ok(LibAflMutator::DwordAddMutator(DwordAddMutator::new())),
                "DwordInterestingMutator" => Ok(LibAflMutator::DwordInterestingMutator(
                    DwordInterestingMutator::new(),
                )),
                "QwordAddMutator" => Ok(LibAflMutator::QwordAddMutator(QwordAddMutator::new())),
                "WordAddMutator" => Ok(LibAflMutator::WordAddMutator(WordAddMutator::new())),
                "WordInterestingMutator" => Ok(LibAflMutator::WordInterestingMutator(
                    WordInterestingMutator::new(),
                )),
                _ => Err(de::Error::custom(format!(
                    "unknown LibAflMutator variant: {key}:{value}",
                ))),
            };
        }
        Err(de::Error::custom("unknown LibAflMutator variant"))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for LibAflMutator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mutator = deserializer.deserialize_any(LibAflMutatorVisitor::<String, String>::new())?;

        Ok(mutator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // test serialization of the BitFlipMutator
    fn test_de_ser_smoke_test() {
        let mutators = &[
            LibAflMutator::BitFlipMutator(BitFlipMutator::new()),
            LibAflMutator::ByteAddMutator(ByteAddMutator::new()),
            LibAflMutator::ByteDecMutator(ByteDecMutator::new()),
            LibAflMutator::ByteFlipMutator(ByteFlipMutator::new()),
            LibAflMutator::ByteIncMutator(ByteIncMutator::new()),
            LibAflMutator::ByteInterestingMutator(ByteInterestingMutator::new()),
            LibAflMutator::ByteNegMutator(ByteNegMutator::new()),
            LibAflMutator::ByteRandMutator(ByteRandMutator::new()),
            LibAflMutator::BytesCopyMutator(BytesCopyMutator::new()),
            LibAflMutator::BytesDeleteMutator(BytesDeleteMutator::new()),
            LibAflMutator::BytesExpandMutator(BytesExpandMutator::new()),
            LibAflMutator::BytesInsertCopyMutator(BytesInsertCopyMutator::new()),
            LibAflMutator::BytesInsertMutator(BytesInsertMutator::new()),
            LibAflMutator::BytesRandInsertMutator(BytesRandInsertMutator::new()),
            LibAflMutator::BytesRandSetMutator(BytesRandSetMutator::new()),
            LibAflMutator::BytesSetMutator(BytesSetMutator::new()),
            LibAflMutator::BytesSwapMutator(BytesSwapMutator::new()),
            LibAflMutator::DwordAddMutator(DwordAddMutator::new()),
            LibAflMutator::DwordInterestingMutator(DwordInterestingMutator::new()),
            LibAflMutator::QwordAddMutator(QwordAddMutator::new()),
            LibAflMutator::WordAddMutator(WordAddMutator::new()),
            LibAflMutator::WordInterestingMutator(WordInterestingMutator::new()),
        ];

        for mutator in mutators {
            // calling unwrap to panic on error
            let serialized = serde_json::to_string(&mutator).unwrap();
            let _deserialized: LibAflMutator = serde_json::from_str(&serialized).unwrap();
        }
    }
}
