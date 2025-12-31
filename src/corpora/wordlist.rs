use std::collections::HashSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::ops::{Index, IndexMut};
use std::path::Path;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::{error, instrument};

use super::{Corpus, CorpusType, Named};
use crate::corpora::typestate::{
    CorpusBuildState, HasItems, HasName, NoItems, NoName, NotUnique, Unique,
};
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::std_ext::convert::AsInner;
use crate::std_ext::fmt::DisplayExt;
use crate::std_ext::ops::Len;

/// generic container representing a wordlist
///
/// # Examples
///
/// ## Normal wordlist
///
/// items may repeat in a normal wordlist
///
/// ```
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::corpora::Corpus;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::Len;
/// let wordlist = Wordlist::new().word("1").word("2").name("words").build();
///
/// assert_eq!(wordlist.len(), 2);
/// ```
///
/// ## Unique wordlist
///
/// ### Note
///
/// There are two primary considerations when choosing to use a unique wordlist:
/// - A hashset is used to store the unique items alongside a Vec, so the memory footprint will be doubled
/// - The original order of the items will be lost
///
/// ```
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::corpora::Corpus;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::Len;
/// let wordlist = Wordlist::new()
///    .words(["one", "two", "three", "one", "two", "three"])
///    .name("words")
///    .unique()
///    .build();
///
/// assert_eq!(wordlist.len(), 3);
/// ```
///
#[derive(Clone, Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Wordlist {
    items: Vec<Data>,
    unique_items: Option<HashSet<Data>>,
    corpus_name: String,
}

/// non-consuming iterator over Wordlist
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::state::SharedState;
/// let expected = vec!["1", "2", "3"];
/// let wordlist = Wordlist::with_words(expected.clone()).name("words").build();
///
/// let mut gathered = vec![];
///
/// for i in &wordlist {
///     gathered.push(i.clone());
/// }
///
/// assert_eq!(gathered, expected);
/// ```
impl<'i> IntoIterator for &'i Wordlist {
    /// the type of the elements being iterated over
    type Item = <&'i [Data] as IntoIterator>::Item;

    /// the kind of iterator we're turning `Wordlist` into
    type IntoIter = <&'i [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `Wordlist.words`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

/// non-consuming mutable iterator over Wordlist
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::{Wordlist, Corpus};
/// # use feroxfuzz::state::SharedState;
/// let mut wordlist = Wordlist::new().words(["1", "2", "3"]).name("words").build();
///
/// for i in &mut wordlist {
///     *i = "4".into();
/// }
///
/// assert_eq!(wordlist.items(), &["4", "4", "4"]);
/// ```
///
impl<'i> IntoIterator for &'i mut Wordlist {
    /// the type of the elements being iterated over
    type Item = <&'i mut [Data] as IntoIterator>::Item;

    /// the kind of iterator we're turning `Wordlist` into
    type IntoIter = <&'i mut [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `Wordlist.words`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter_mut()
    }
}

/// consuming iterator over Wordlist
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::state::SharedState;
/// let expected = vec!["1", "2", "3"];
/// let wordlist = Wordlist::with_words(expected.clone()).name("words").build();
///
/// let mut gathered = vec![];
///
/// for i in wordlist {
///     gathered.push(i.clone());
/// }
///
/// assert_eq!(gathered, expected);
/// ```
///
impl IntoIterator for Wordlist {
    /// the type of the elements being iterated over
    type Item = <Vec<Data> as IntoIterator>::Item;

    /// the kind of iterator we're turning `Wordlist` into
    type IntoIter = <Vec<Data> as IntoIterator>::IntoIter;

    /// creates an iterator from `Wordlist.words`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// general `Wordlist` implementation
impl Wordlist {
    /// create a default (empty) `WordlistBuilder`
    ///
    /// # Note
    ///
    /// `WordlistBuilder::build` can only be called after `WordlistBuilder::name` and
    /// `WordlistBuilder::word` or `WordlistBuilder::words` have been called.
    ///
    /// There are other constructors to immediately provide the corpus items, if desired.
    ///
    /// - [`Wordlist::with_words`]
    /// - [`Wordlist::from_file`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::corpora::Wordlist;
    /// let wordlist = Wordlist::new().word("1").name("smol").build();
    /// ```
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub const fn new() -> WordlistBuilder<NoItems, NoName, NotUnique> {
        WordlistBuilder {
            items: Vec::new(),
            corpus_name: None,
            unique_items: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }

    /// given a collection of items, create a new `WordlistBuilder`
    ///
    /// # Note
    ///
    /// `WordlistBuilder::build` can only be called after `WordlistBuilder::name` and
    /// `WordlistBuilder::word` or `WordlistBuilder::words` have been called.
    ///
    /// In addtion to this function, the [`Wordlist::from_file`] constructor can be used
    /// to immediately provide the corpus items, if desired.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::corpora::Wordlist;
    /// let wordlist = Wordlist::with_words(["1", "2", "3"]).name("words").build();
    /// ```
    #[inline]
    pub fn with_words<I, T>(words: I) -> WordlistBuilder<HasItems, NoName, NotUnique>
    where
        Data: From<T>,
        I: IntoIterator<Item = T>,
    {
        WordlistBuilder {
            items: words.into_iter().map(Data::from).collect(),
            corpus_name: None,
            unique_items: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }

    /// Populates `Wordlist` with test cases out of the file with the path given by `file_path`
    ///
    /// # Note
    ///
    /// `WordlistBuilder::build` can only be called after `WordlistBuilder::name` and
    /// `WordlistBuilder::word` or `WordlistBuilder::words` have been called.
    ///
    /// In addtion to this function, the [`Wordlist::with_words`] constructor can be used
    /// to immediately provide the corpus items, if desired.
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O error, an error
    /// variant will be returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # use feroxfuzz::corpora::Wordlist;
    /// # use feroxfuzz::prelude::*;
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let file_name = "smol-wordlist.txt";
    /// let words = "one\ntwo\n\n\n#three\nfour\n";
    /// fs::write(file_name, words);
    ///
    /// let wordlist = Wordlist::from_file(file_name)?.name("words").build();
    ///
    /// fs::remove_file(file_name);
    ///
    /// assert_eq!(wordlist.len(), 3);
    /// assert_eq!(wordlist.items(), &["one", "two", "four"]);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip_all, level = "trace")]
    pub fn from_file<P>(
        file_path: P,
    ) -> Result<WordlistBuilder<HasItems, NoName, NotUnique>, FeroxFuzzError>
    where
        P: AsRef<Path>,
        Self: Corpus,
    {
        let file = File::open(&file_path).map_err(|source| {
            error!(
                file = file_path.as_ref().to_string_lossy().to_string(),
                "could not open file while populating the corpus: {}", source
            );

            FeroxFuzzError::CorpusFileOpenError {
                source,
                path: file_path.as_ref().to_string_lossy().to_string(),
            }
        })?;

        let reader = BufReader::new(file);

        let mut items = Vec::new();

        for line in reader.lines().map_while(Result::ok) {
            if line.is_empty() || line.starts_with('#') {
                // skip empty lines and comments
                continue;
            }

            items.push(line.into());
        }

        Ok(WordlistBuilder {
            items,
            unique_items: None,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        })
    }

    /// get mutable reference to inner `words` collection
    #[inline]
    pub fn items_mut(&mut self) -> &mut [Data] {
        &mut self.items
    }

    /// Returns a mutable iterator over the items in the corpus.
    #[must_use]
    pub fn iter_mut(&mut self) -> <&mut [Data] as IntoIterator>::IntoIter {
        <&mut Self as IntoIterator>::into_iter(self)
    }

    /// Returns an iterator over the items in the corpus.
    #[must_use]
    pub fn iter(&self) -> <&[Data] as IntoIterator>::IntoIter {
        <&Self as IntoIterator>::into_iter(self)
    }
}

impl AsInner for Wordlist {
    type Type = Vec<Data>;

    fn inner(&self) -> &Self::Type {
        &self.items
    }
}

impl Display for Wordlist {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_top(3))
    }
}

/// `Corpus` implementation for `Wordlist` with an inner `Vec`
impl Corpus for Wordlist {
    #[inline]
    fn add(&mut self, value: Data) {
        if let Some(ref mut unique_items) = self.unique_items {
            // if unique_items is Some, then we are only adding unique items, meaning
            // we can return early if the item is already in the set
            if unique_items.contains(&value) {
                return;
            }

            // item is not in the set, so we can insert it
            unique_items.insert(value.clone());
        }

        // if we made it here, then we know that either we don't care about unique items
        // or the item is unique, so, either way, we can push it onto the vector
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

impl Named for Wordlist {
    #[inline]
    fn name(&self) -> &str {
        &self.corpus_name
    }
}

impl Index<usize> for Wordlist {
    type Output = Data;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items()[index]
    }
}

impl IndexMut<usize> for Wordlist {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items_mut()[index]
    }
}

impl Len for Wordlist {
    #[inline]
    fn len(&self) -> usize {
        self.items.len()
    }
}

pub struct WordlistBuilder<ItemState, NameState, UniqueNess>
where
    ItemState: CorpusBuildState,
    NameState: CorpusBuildState,
    UniqueNess: CorpusBuildState,
{
    items: Vec<Data>,
    unique_items: Option<HashSet<Data>>,
    corpus_name: Option<String>,
    _item_state: PhantomData<ItemState>,
    _name_state: PhantomData<NameState>,
    _unique_state: PhantomData<UniqueNess>,
}

impl<ItemState, UniqueNess> WordlistBuilder<ItemState, NoName, UniqueNess>
where
    ItemState: CorpusBuildState,
    UniqueNess: CorpusBuildState,
{
    pub fn name(self, corpus_name: &str) -> WordlistBuilder<ItemState, HasName, UniqueNess> {
        WordlistBuilder {
            items: self.items,
            unique_items: self.unique_items,
            corpus_name: Some(corpus_name.to_string()),
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }
}

impl<ItemState, NameState> WordlistBuilder<ItemState, NameState, NotUnique>
where
    ItemState: CorpusBuildState,
    NameState: CorpusBuildState,
{
    // false positive; clippy thinks this should be a const fn, but it can't be
    #[allow(clippy::missing_const_for_fn)]
    pub fn unique(self) -> WordlistBuilder<ItemState, NameState, Unique> {
        WordlistBuilder {
            items: self.items,
            unique_items: self.unique_items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }
}

impl<ItemState, NameState, UniqueNess> WordlistBuilder<ItemState, NameState, UniqueNess>
where
    ItemState: CorpusBuildState,
    NameState: CorpusBuildState,
    UniqueNess: CorpusBuildState,
{
    pub fn word<T>(mut self, word: T) -> WordlistBuilder<HasItems, NameState, UniqueNess>
    where
        Data: From<T>,
    {
        self.items.push(word.into());

        WordlistBuilder {
            items: self.items,
            unique_items: self.unique_items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }

    pub fn words<I, T>(mut self, words: I) -> WordlistBuilder<HasItems, NameState, UniqueNess>
    where
        Data: From<T>,
        I: IntoIterator<Item = T>,
    {
        self.items.extend(words.into_iter().map(Data::from));

        WordlistBuilder {
            items: self.items,
            unique_items: self.unique_items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
            _unique_state: PhantomData,
        }
    }
}

impl WordlistBuilder<HasItems, HasName, Unique> {
    pub fn build(mut self) -> CorpusType {
        // remove duplicates from the vector
        self.items.sort_unstable();
        self.items.dedup();

        let mut unique_items = HashSet::with_capacity(self.items.len());
        unique_items.extend(self.items.iter().cloned());

        CorpusType::Wordlist(Wordlist {
            items: self.items,
            unique_items: Some(unique_items),
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}

impl WordlistBuilder<HasItems, HasName, NotUnique> {
    pub fn build(self) -> CorpusType {
        CorpusType::Wordlist(Wordlist {
            items: self.items,
            unique_items: None,
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}

impl WordlistBuilder<NoItems, HasName, Unique> {
    pub fn build(self) -> CorpusType {
        CorpusType::Wordlist(Wordlist {
            items: Vec::new(),
            unique_items: Some(HashSet::new()),
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}

impl WordlistBuilder<NoItems, HasName, NotUnique> {
    pub fn build(self) -> CorpusType {
        CorpusType::Wordlist(Wordlist {
            items: Vec::new(),
            unique_items: None,
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_builder_with_single_word() {
        let wordlist = Wordlist::new()
            .word("one")
            .word("two")
            .word("three")
            .name("words")
            .words(["four", "five", "six"])
            .build();

        assert_eq!(wordlist.len(), 6);
        assert_eq!(
            wordlist.items(),
            &["one", "two", "three", "four", "five", "six"]
        );
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_wordlist_builder_with_both_word_methods() {
        let wordlist = Wordlist::new()
            .words(["one", "two", "three"])
            .word("four")
            .name("words")
            .build();

        assert_eq!(wordlist.len(), 4);
        assert_eq!(wordlist.items(), &["one", "two", "three", "four"]);
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_wordlist_builder_with_name_first() {
        let wordlist = Wordlist::new()
            .name("words")
            .words(["one", "two", "three"])
            .word("four")
            .build();

        assert_eq!(wordlist.len(), 4);
        assert_eq!(wordlist.items(), &["one", "two", "three", "four"]);
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_wordlist_with_unique_items_first() {
        let wordlist = Wordlist::new()
            .words(["one", "two", "three", "one", "two", "three"])
            .name("words")
            .unique()
            .build();

        assert_eq!(wordlist.len(), 3);
        for item in wordlist.items() {
            assert!([Data::from("one"), Data::from("two"), Data::from("three")].contains(item));
        }
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_wordlist_with_unique_items_second() {
        let wordlist = Wordlist::new()
            .words(["one", "two", "three", "one", "two", "three"])
            .unique()
            .name("words")
            .build();

        assert_eq!(wordlist.len(), 3);
        for item in wordlist.items() {
            assert!([Data::from("one"), Data::from("two"), Data::from("three")].contains(item));
        }
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_wordlist_with_unique_items_last() {
        let wordlist = Wordlist::new()
            .words(["one", "two", "three", "one", "two", "three"])
            .name("words")
            .unique()
            .build();

        assert_eq!(wordlist.len(), 3);
        for item in wordlist.items() {
            assert!([Data::from("one"), Data::from("two"), Data::from("three")].contains(item));
        }
        assert_eq!(wordlist.name(), "words");
    }

    #[test]
    fn test_unique_wordlist_remains_unique_after_using_corpus_add() {
        let mut wordlist = Wordlist::new()
            .words(["one", "two"])
            .name("words")
            .unique()
            .build();

        wordlist.add("one".into());
        wordlist.add("two".into());
        wordlist.add("three".into());
        wordlist.add("three".into());

        assert_eq!(wordlist.len(), 3);
        for item in wordlist.items() {
            assert!([Data::from("one"), Data::from("two"), Data::from("three"),].contains(item));
        }
        assert_eq!(wordlist.name(), "words");
    }
}
