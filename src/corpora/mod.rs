//! Corpora modeled around how the test cases are generated, i.e. from a file/folder etc...
#![allow(clippy::use_self)] // clippy false-positive on CorpusItemType, doesn't want to apply directly to the enums that derive Serialize
mod directory;
mod http_methods;
mod range;
mod wordlist;

use crate::input::Data;
use crate::std_ext::ops::Len;

// re-exported trait, to be available as top-level `corpora` module import for users
//
// the reason is that the Named trait was brought in because of the tuple_list stuff
// but most users will interact with the corpora module and its corpus types directly
// way more often than the tuple_list machinery. Knowing that, we want to make it
// easy to import the Named trait from where they'd likely expect to find it.
pub use crate::std_ext::tuple::Named;

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::instrument;

// re-exports
pub use self::directory::DirCorpus;
pub use self::http_methods::HttpMethodsCorpus;
pub use self::range::RangeCorpus;
pub use self::wordlist::Wordlist;

/// typedef of the `SharedState`'s `corpora` field
pub type CorpusMap = Arc<HashMap<String, Arc<RwLock<CorpusType>>>>;

/// typedef of the `SharedState`'s `corpus_indices` field
pub type CorpusIndices = Arc<HashMap<String, AtomicUsize>>;

/// Used to inform the [`Fuzzer`] of the type of corpus item that should
/// be added to the corpus when using [`Action::AddToCorpus`].
///
/// [`Fuzzer`]: crate::fuzzers::Fuzzer
/// [`Action::AddToCorpus`]: crate::actions::Action::AddToCorpus
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum CorpusItemType {
    /// When the corpus item type is [`CorpusItemType::Request`], all fields marked
    /// fuzzable will be added to the corpus.
    #[default]
    Request,

    /// When the corpus item type is [`CorpusItemType::Data`], the [`Data`] value
    /// associated with the key will be added to the corpus.
    ///
    /// # Note
    ///
    /// There are a lot of [`From`] implementations for [`Data`]. When creating
    /// a [`CorpusItemType::Data`] item, you can probably just use `.into`:
    ///
    /// ```
    /// # use feroxfuzz::corpora::CorpusItemType;
    /// CorpusItemType::Data("something".into());
    /// ```
    ///
    /// [`Data`]: crate::input::Data
    Data(Data),

    /// When the corpus item type is [`CorpusItemType::LotsOfData`], all [`Data`]
    /// values associated with the key will be added to the corpus.
    ///
    /// # Note
    ///
    /// There are a lot of [`From`] implementations for [`Data`]. When creating
    /// a [`CorpusItemType::Data`] item, you can probably just use `.into`:
    ///
    /// ```
    /// # use feroxfuzz::corpora::CorpusItemType;
    /// CorpusItemType::LotsOfData(vec!["something".into()]);
    /// ```
    ///
    /// [`Data`]: crate::input::Data
    LotsOfData(Vec<Data>),
}

/// Collection of all current test cases
pub trait Corpus: Named {
    /// adds a [`Data`] item to the corpus
    fn add(&mut self, value: Data);

    /// get a reference to a corpus entry by index
    fn get(&self, index: usize) -> Option<&Data>;

    /// get a reference to the inner collection of corpus items
    #[must_use]
    fn items(&self) -> &[Data];
}

/// [`Corpus`] wrapper enum to facilitate static dispatch of [`Corpus`] methods
///
/// most of the methods/traits implemented by the underlying [`Corpus`] types
/// are implemented here as well. Meaning, you should be able to use the
/// underlying [`Corpus`] types seamlessly through this wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum CorpusType {
    /// [`Wordlist`] wrapper
    Wordlist(Wordlist),

    /// [`DirCorpus`] wrapper
    Dir(DirCorpus),

    /// [`RangeCorpus`] wrapper
    Range(RangeCorpus),

    /// [`HttpMethodsCorpus`] wrapper
    HttpMethods(HttpMethodsCorpus),
}

/// [`Corpus`] implementation for [`CorpusType`] enum
impl Corpus for CorpusType {
    #[instrument(skip_all, level = "trace")]
    fn add(&mut self, value: Data) {
        match self {
            Self::Wordlist(corpus) => corpus.add(value),
            Self::Dir(corpus) => corpus.add(value),
            Self::Range(corpus) => corpus.add(value),
            Self::HttpMethods(corpus) => corpus.add(value),
        }
    }

    #[instrument(skip(self), level = "trace")]
    fn get(&self, index: usize) -> Option<&Data> {
        match self {
            Self::Wordlist(corpus) => corpus.get(index),
            Self::Dir(corpus) => corpus.get(index),
            Self::Range(corpus) => corpus.get(index),
            Self::HttpMethods(corpus) => corpus.get(index),
        }
    }

    #[instrument(skip_all, level = "trace")]
    fn items(&self) -> &[Data] {
        match self {
            Self::Wordlist(corpus) => corpus.items(),
            Self::Dir(corpus) => corpus.items(),
            Self::Range(corpus) => corpus.items(),
            Self::HttpMethods(corpus) => corpus.items(),
        }
    }
}

impl Named for CorpusType {
    fn name(&self) -> &str {
        match self {
            Self::Wordlist(corpus) => corpus.name(),
            Self::Dir(corpus) => corpus.name(),
            Self::Range(corpus) => corpus.name(),
            Self::HttpMethods(corpus) => corpus.name(),
        }
    }
}

/// [`Len`] implementation for [`CorpusType`] enum
impl Len for CorpusType {
    fn len(&self) -> usize {
        match self {
            Self::Wordlist(corpus) => corpus.len(),
            Self::Dir(corpus) => corpus.len(),
            Self::Range(corpus) => corpus.len(),
            Self::HttpMethods(corpus) => corpus.len(),
        }
    }
}

impl<'i> IntoIterator for &'i mut CorpusType {
    /// the type of the elements being iterated over
    type Item = <&'i mut [Data] as IntoIterator>::Item;

    /// the kind of iterator we're turning the given corpus into
    type IntoIter = <&'i mut [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from the given corpus
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            CorpusType::Wordlist(corpus) => corpus.into_iter(),
            CorpusType::Dir(corpus) => corpus.into_iter(),
            CorpusType::HttpMethods(corpus) => corpus.into_iter(),
            CorpusType::Range(_) => panic!("into_iter not implemented for CorpusType::Range"),
        }
    }
}

impl IntoIterator for CorpusType {
    /// the type of the elements being iterated over
    type Item = <Vec<Data> as IntoIterator>::Item;

    /// the kind of iterator we're turning the given corpus into
    type IntoIter = <Vec<Data> as IntoIterator>::IntoIter;

    /// creates an iterator from the given corpus
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Wordlist(corpus) => corpus.into_iter(),
            Self::Dir(corpus) => corpus.into_iter(),
            Self::HttpMethods(corpus) => corpus.into_iter(),
            Self::Range(_) => panic!("into_iter not implemented for CorpusType::Range"),
        }
    }
}

impl<'i> IntoIterator for &'i CorpusType {
    /// the type of the elements being iterated over
    type Item = <&'i [Data] as IntoIterator>::Item;

    /// the kind of iterator we're turning the given corpus into
    type IntoIter = <&'i [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from the given corpus
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            CorpusType::Wordlist(corpus) => corpus.into_iter(),
            CorpusType::Dir(corpus) => corpus.into_iter(),
            CorpusType::HttpMethods(corpus) => corpus.into_iter(),
            CorpusType::Range(_) => panic!("into_iter not implemented for CorpusType::Range"),
        }
    }
}

impl Deref for CorpusType {
    type Target = dyn Corpus;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Wordlist(corpus) => corpus,
            Self::Dir(corpus) => corpus,
            Self::Range(corpus) => corpus,
            Self::HttpMethods(corpus) => corpus,
        }
    }
}

impl DerefMut for CorpusType {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Wordlist(corpus) => corpus,
            Self::Dir(corpus) => corpus,
            Self::Range(corpus) => corpus,
            Self::HttpMethods(corpus) => corpus,
        }
    }
}

impl Display for CorpusType {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Wordlist(corpus) => corpus.fmt(f),
            Self::Dir(corpus) => corpus.fmt(f),
            Self::Range(corpus) => corpus.fmt(f),
            Self::HttpMethods(corpus) => corpus.fmt(f),
        }
    }
}

mod typestate {
    // typestate information for the different corpus builders; not useful for anything else
    pub trait CorpusBuildState {}
    pub struct NoItems;
    pub struct NoName;
    pub struct NotUnique;
    pub struct HasItems;
    pub struct HasName;
    pub struct Unique;
    impl CorpusBuildState for NoItems {}
    impl CorpusBuildState for NoName {}
    impl CorpusBuildState for NotUnique {}
    impl CorpusBuildState for HasItems {}
    impl CorpusBuildState for HasName {}
    impl CorpusBuildState for Unique {}
}
