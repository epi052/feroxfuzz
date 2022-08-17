#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize
use std::fmt::{self, Debug, Display, Formatter};
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};

use super::typestate::NoItems;
use super::{Corpus, CorpusType, Named};
use crate::corpora::typestate::{CorpusBuildState, HasItems, HasName, NoName};
use crate::input::Data;
use crate::std_ext::fmt::DisplayExt;
use crate::std_ext::ops::Len;
use crate::AsInner;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents logical groupings of HTTP methods.
///
/// All method groupings were taken from [RFC 7231](https://tools.ietf.org/html/rfc7231#section-4.2)
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
enum HttpMethodGroup {
    /// Represents HTTP methods that are deemed 'safe', i.e. it doesn't alter the state of the server
    ///
    /// members of this group are: GET, HEAD, OPTIONS, and TRACE
    #[default]
    Safe,

    /// Represents HTTP methods that are deemed 'idempotent', i.e. an identical request
    /// can be made once or several times in a row with the same effect while leaving
    /// the server in the same state
    ///
    /// members of this group are: GET, HEAD, OPTIONS, TRACE, PUT, and DELETE
    Idempotent,

    /// Represents HTTP methods that indicate responses to them are allowed to
    /// be stored for future reuse
    ///
    /// members of this group are: GET and HEAD
    Cacheable,

    /// Represents all HTTP methods
    All,
}

/// corpus consisting of http verbs (GET, POST, etc)
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::HttpMethodsCorpus;
/// # use feroxfuzz::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// // create a Corpus of all HTTP methods
/// let corpus = HttpMethodsCorpus::all().name("corpus").build();
///
/// let expected = vec![
///     "GET",
///     "HEAD",
///     "POST",
///     "PUT",
///     "DELETE",
///     "CONNECT",
///     "OPTIONS",
///     "TRACE",
///     "PATCH",
/// ];
///
/// // resulting HttpMethodsCorpus has 9 entries
/// assert_eq!(corpus.len(), 9);
/// assert_eq!(corpus.items(), &expected);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HttpMethodsCorpus {
    items: Vec<Data>,
    corpus_name: String,
}

impl Corpus for HttpMethodsCorpus {
    fn add(&mut self, value: Data) {
        self.items.push(value);
    }

    fn get(&self, index: usize) -> Option<&Data> {
        self.items.get(index)
    }

    #[inline]
    fn items(&self) -> &[Data] {
        &self.items
    }
}

impl Named for HttpMethodsCorpus {
    fn name(&self) -> &str {
        &self.corpus_name
    }
}

impl HttpMethodsCorpus {
    /// create a default (empty) `HttpMethodsBuilder` consisting of http methods that are
    /// deemed 'safe', i.e. it doesn't alter the state of the server
    ///
    /// # Note
    ///
    /// `HttpMethodsBuilder::build` can only be called after `HttpMethodsBuilder::name` and
    /// `HttpMethodsBuilder::method` have been called.
    ///
    /// There are other constructors to immediately provide the corpus items, if desired.
    ///
    /// - [`HttpMethodsCorpus::all`]
    /// - [`HttpMethodsCorpus::safe`]
    /// - [`HttpMethodsCorpus::idempotent`]
    /// - [`HttpMethodsCorpus::cacheable`]
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub const fn new() -> HttpMethodsBuilder<NoItems, NoName> {
        HttpMethodsBuilder {
            items: None,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new [`Corpus`] consisting of all http methods
    ///
    /// members of this group are: GET, HEAD, POST, PUT, DELETE, CONNECT,
    /// OPTIONS, TRACE, and PATCH
    #[must_use]
    pub fn all() -> HttpMethodsBuilder<HasItems, NoName> {
        HttpMethodsBuilder {
            items: Some(Self::from_group(HttpMethodGroup::All)),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new [`Corpus`] consisting of HTTP methods that are
    /// deemed 'safe', i.e. it doesn't alter the state of the server
    ///
    /// members of this group are: GET, HEAD, OPTIONS, and TRACE
    #[must_use]
    pub fn safe() -> HttpMethodsBuilder<HasItems, NoName> {
        HttpMethodsBuilder {
            items: Some(Self::from_group(HttpMethodGroup::Safe)),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new [`Corpus`] consisting of HTTP methods that are
    /// deemed 'idempotent', i.e. an identical request can be made
    /// once or several times in a row with the same effect while leaving
    /// the server in the same state
    ///
    /// members of this group are: GET, HEAD, OPTIONS, TRACE, PUT, and DELETE
    #[must_use]
    pub fn idempotent() -> HttpMethodsBuilder<HasItems, NoName> {
        HttpMethodsBuilder {
            items: Some(Self::from_group(HttpMethodGroup::Idempotent)),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new [`Corpus`] consisting of HTTP methods that  
    /// indicate responses to them are allowed to be stored for
    /// future reuse
    ///
    /// members of this group are: GET and HEAD
    #[must_use]
    pub fn cacheable() -> HttpMethodsBuilder<HasItems, NoName> {
        HttpMethodsBuilder {
            items: Some(Self::from_group(HttpMethodGroup::Cacheable)),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new [`Corpus`] of HTTP methods from the given [`HttpMethodGroup`]
    #[must_use]
    fn from_group(group: HttpMethodGroup) -> Vec<Data> {
        let mut items = Vec::new();

        match group {
            HttpMethodGroup::Safe => {
                items.push("GET".into());
                items.push("HEAD".into());
                items.push("OPTIONS".into());
                items.push("TRACE".into());
            }
            HttpMethodGroup::Idempotent => {
                items.push("GET".into());
                items.push("HEAD".into());
                items.push("OPTIONS".into());
                items.push("TRACE".into());
                items.push("PUT".into());
                items.push("DELETE".into());
            }
            HttpMethodGroup::Cacheable => {
                items.push("GET".into());
                items.push("HEAD".into());
            }
            HttpMethodGroup::All => {
                items.push("GET".into());
                items.push("HEAD".into());
                items.push("POST".into());
                items.push("PUT".into());
                items.push("DELETE".into());
                items.push("CONNECT".into());
                items.push("OPTIONS".into());
                items.push("TRACE".into());
                items.push("PATCH".into());
            }
        }

        items
    }

    /// get a mutable reference to the inner collection of corpus items
    #[must_use]
    #[inline]
    pub fn items_mut(&mut self) -> &mut [Data] {
        &mut self.items
    }
}

impl Len for HttpMethodsCorpus {
    #[inline]
    #[must_use]
    fn len(&self) -> usize {
        self.items.len()
    }
}

impl AsInner for HttpMethodsCorpus {
    type Type = Vec<Data>;

    fn inner(&self) -> &Self::Type {
        &self.items
    }
}

impl Display for HttpMethodsCorpus {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_top(3))
    }
}

impl Index<usize> for HttpMethodsCorpus {
    type Output = Data;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items()[index]
    }
}

impl IndexMut<usize> for HttpMethodsCorpus {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items_mut()[index]
    }
}

/// non-consuming mutable iterator over `HttpMethodsCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::HttpMethodsCorpus;
/// # use feroxfuzz::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// // create a Corpus of safe HTTP methods
/// let mut corpus = HttpMethodsCorpus::safe().name("corpus").build();
///
/// let expected = Data::from("a");
///
/// // resulting HttpMethodsCorpus has 4 entries
/// assert_eq!(corpus.len(), 4);
///
/// for item in &mut corpus {
///     // not useful, just showing that we can mutate the items
///     *item = "a".into();
/// }
///
/// for item in &corpus {
///     assert_eq!(&expected, item);
/// }
/// # Ok(())
/// # }
/// ```
///
impl<'i> IntoIterator for &'i mut HttpMethodsCorpus {
    /// the type of the elements being iterated over
    type Item = &'i mut Data;

    /// the kind of iterator we're turning `HttpMethodsCorpus` into
    type IntoIter = <&'i mut [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `HttpMethodsCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter_mut()
    }
}

/// consuming iterator over `HttpMethodsCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::HttpMethodsCorpus;
/// # use feroxfuzz::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// // create a Corpus of idempotent HTTP methods
/// let corpus = HttpMethodsCorpus::idempotent().name("corpus").build();
///
/// let expected = corpus.clone();
///
/// // resulting HttpMethodsCorpus has 6 entries
/// assert_eq!(corpus.len(), 6);
///
/// let mut gathered = vec![];
///
/// for item in corpus {
///     gathered.push(item);
/// }
///
/// assert_eq!(gathered, expected.items());
/// # Ok(())
/// # }
/// ```
///
impl IntoIterator for HttpMethodsCorpus {
    /// the type of the elements being iterated over
    type Item = Data;

    /// the kind of iterator we're turning `HttpMethodsCorpus` into
    type IntoIter = <Vec<Data> as IntoIterator>::IntoIter;

    /// creates an iterator from `HttpMethodsCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// non-consuming iterator over `HttpMethodsCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::HttpMethodsCorpus;
/// # use feroxfuzz::prelude::*;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
///
/// // create a Corpus of cacheable HTTP methods
/// let corpus = HttpMethodsCorpus::cacheable().name("corpus").build();
///
/// // resulting HttpMethodsCorpus has 2 entries
/// assert_eq!(corpus.len(), 2);
///
/// let mut gathered = vec![];
///
/// for item in &corpus {
///     gathered.push(item);
/// }
///
/// assert_eq!(gathered, corpus.items());
/// # Ok(())
/// # }
/// ```
impl<'i> IntoIterator for &'i HttpMethodsCorpus {
    /// the type of the elements being iterated over
    type Item = &'i Data;

    /// the kind of iterator we're turning `HttpMethodsCorpus` into
    type IntoIter = <&'i [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `HttpMethodsCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

pub struct HttpMethodsBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    items: Option<Vec<Data>>,
    corpus_name: Option<String>,
    _item_state: PhantomData<IS>,
    _name_state: PhantomData<NS>,
}

impl<IS> HttpMethodsBuilder<IS, NoName>
where
    IS: CorpusBuildState,
{
    pub fn name(self, corpus_name: &str) -> HttpMethodsBuilder<IS, HasName> {
        HttpMethodsBuilder {
            items: self.items,
            corpus_name: Some(corpus_name.to_string()),
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl<IS, NS> HttpMethodsBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    pub fn method<T>(self, http_method: T) -> Self
    where
        Data: From<T>,
    {
        let mut items = self.items.unwrap_or_default();
        items.push(http_method.into());

        Self {
            items: Some(items),
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl HttpMethodsBuilder<HasItems, HasName> {
    pub fn build(self) -> CorpusType {
        CorpusType::HttpMethods(HttpMethodsCorpus {
            items: self.items.unwrap(),
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}
