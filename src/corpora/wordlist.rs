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
use crate::corpora::typestate::{CorpusBuildState, HasItems, HasName, NoItems, NoName};
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::std_ext::convert::AsInner;
use crate::std_ext::fmt::DisplayExt;
use crate::std_ext::ops::Len;

/// generic container representing a wordlist
///
/// # Examples
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
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Wordlist {
    items: Vec<Data>,
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
    pub const fn new() -> WordlistBuilder<NoItems, NoName> {
        WordlistBuilder {
            items: Vec::new(),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
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
    pub fn with_words<I, T>(words: I) -> WordlistBuilder<HasItems, NoName>
    where
        Data: From<T>,
        I: IntoIterator<Item = T>,
    {
        WordlistBuilder {
            items: words.into_iter().map(Data::from).collect(),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
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
    pub fn from_file<P>(file_path: P) -> Result<WordlistBuilder<HasItems, NoName>, FeroxFuzzError>
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

        for line in reader.lines().flatten() {
            if line.is_empty() || line.starts_with('#') {
                // skip empty lines and comments
                continue;
            }

            if let Ok(associated_type) = line.parse() {
                // since the associated type `Item` must implement FromStr
                // we can call .parse() to convert it into the expected
                // type before pushing it onto the container of type T
                items.push(associated_type);
            }
        }

        Ok(WordlistBuilder {
            items,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        })
    }

    /// get mutable reference to inner `words` collection
    #[inline]
    pub fn items_mut(&mut self) -> &mut [Data] {
        &mut self.items
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

pub struct WordlistBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    items: Vec<Data>,
    corpus_name: Option<String>,
    _item_state: PhantomData<IS>,
    _name_state: PhantomData<NS>,
}

impl<IS> WordlistBuilder<IS, NoName>
where
    IS: CorpusBuildState,
{
    pub fn name(self, corpus_name: &str) -> WordlistBuilder<IS, HasName> {
        WordlistBuilder {
            items: self.items,
            corpus_name: Some(corpus_name.to_string()),
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl<IS, NS> WordlistBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    pub fn word<T>(mut self, word: T) -> WordlistBuilder<HasItems, NS>
    where
        Data: From<T>,
    {
        self.items.push(word.into());

        WordlistBuilder {
            items: self.items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    pub fn words<I, T>(mut self, words: I) -> WordlistBuilder<HasItems, NS>
    where
        Data: From<T>,
        I: IntoIterator<Item = T>,
    {
        self.items.extend(words.into_iter().map(Data::from));

        WordlistBuilder {
            items: self.items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl WordlistBuilder<HasItems, HasName> {
    pub fn build(self) -> CorpusType {
        CorpusType::Wordlist(Wordlist {
            items: self.items,
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}

impl WordlistBuilder<NoItems, HasName> {
    pub fn build(self) -> CorpusType {
        CorpusType::Wordlist(Wordlist {
            items: Vec::new(),
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
}
