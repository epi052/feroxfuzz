use std::fmt::{self, Debug, Display, Formatter};
use std::fs::{self, File};
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
use crate::std_ext::fmt::DisplayExt;
use crate::std_ext::ops::Len;
use crate::AsInner;

/// corpus created from the contents of an entire directory (non-recursive)
///
/// each file is read line-by-line. each line becomes a single entry in
/// the corpus
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::DirCorpus;
/// # use feroxfuzz::corpora::Corpus;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::Len;
/// # use tempdir::TempDir;
/// # use std::fs::File;
/// # use std::io::Write;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // test setup:
/// // - temporary directory that contains 2 files
/// // - each file has 2 lines
/// let tmp_dir = TempDir::new("test-corpus")?;
///
/// let file_one = tmp_dir.path().join("test-file-one");
/// let mut tmp_file = File::create(file_one)?;
/// writeln!(tmp_file, "one")?;
/// writeln!(tmp_file, "two")?;
///
/// let file_two = tmp_dir.path().join("test-file-two");
/// tmp_file = File::create(file_two)?;
/// writeln!(tmp_file, "three")?;
/// writeln!(tmp_file, "four")?;
///
/// // create a Corpus from the given directory
/// let corpus = DirCorpus::from_directory(tmp_dir.path())?.name("corpus").build();
///
/// // resulting DirCorpus has 4 entries, one for each line found in the files above
/// assert_eq!(corpus.len(), 4);
/// # Ok(())
/// # }
/// ```
///
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DirCorpus {
    items: Vec<Data>,
    corpus_name: String,
}

impl Corpus for DirCorpus {
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

/// internal helper to support multiple corpus directories
fn from_directory<P>(directory: P) -> Result<Vec<Data>, FeroxFuzzError>
where
    P: AsRef<Path>,
{
    let mut items = Vec::new();

    for entry in fs::read_dir(directory)? {
        let entry = entry?; // directory entry
        let path = entry.path(); // converted to a PathBuf

        let metadata = fs::metadata(&path)?;

        if metadata.is_file() {
            let file = File::open(&path).map_err(|source| {
                error!(
                    ?path,
                    "could not open file while populating the corpus: {}", source
                );

                FeroxFuzzError::CorpusFileOpenError {
                    source,
                    path: path.to_string_lossy().to_string(),
                }
            })?;

            let reader = BufReader::new(file);

            for line in reader.lines().flatten() {
                if line.is_empty() || line.starts_with('#') {
                    // skip empty lines and comments
                    continue;
                }

                if let Ok(associated_type) = line.parse() {
                    // since the associated type `Item` must implement FromStr
                    // we can call .parse() to convert it into the expected
                    // type before pushing it onto the container
                    items.push(associated_type);
                }
            }
        }
    }

    Ok(items)
}

impl DirCorpus {
    /// create a new/empty `DirCorpusBuilder`
    ///
    /// # Note
    ///
    /// `DirCorpusBuilder::build` can only be called after `DirCorpusBuilder::name` and
    /// `DirCorpusBuilder::directory` have been called.
    ///
    /// The [`DirCorpus::from_directory`] constructor can be used to immediately provide
    /// the corpus items, if desired.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::corpora::DirCorpus;
    /// # use feroxfuzz::prelude::*;
    /// # use tempdir::TempDir;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // test setup:
    /// // - 2 temporary directories that contain 1 file each
    /// // - each file has 2 lines
    /// let tmp_dir = TempDir::new("test-corpus-1").unwrap();
    /// let tmp_dir2 = TempDir::new("test-corpus-2").unwrap();
    ///
    /// let file_one = tmp_dir.path().join("test-file-one");
    /// let mut tmp_file = File::create(file_one).unwrap();
    /// writeln!(tmp_file, "one").unwrap();
    /// writeln!(tmp_file, "two").unwrap();
    ///
    /// let file_two = tmp_dir2.path().join("test-file-two");
    /// tmp_file = File::create(file_two).unwrap();
    /// writeln!(tmp_file, "three").unwrap();
    /// writeln!(tmp_file, "four").unwrap();
    ///
    /// let expected = vec!["one", "two", "three", "four"];
    ///
    /// // create a Corpus of Strings from the given directory
    /// let corpus = DirCorpus::new()
    ///     .directory(tmp_dir.path())?
    ///     .directory(tmp_dir2.path())?
    ///     .name("corpus")
    ///     .build();
    ///
    /// assert_eq!(corpus.items(), expected);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[inline]
    #[allow(clippy::new_ret_no_self)]
    pub const fn new() -> DirCorpusBuilder<NoItems, NoName> {
        DirCorpusBuilder {
            items: Vec::new(),
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new `DirCorpusBuilder` from the contents of the given `directory` (non-recursive)
    ///
    /// # Errors
    ///
    /// If this function encounters any form of I/O error, an error
    /// variant will be returned.
    ///
    /// # Note
    ///
    /// `DirCorpusBuilder::build` can only be called after `DirCorpusBuilder::name` and
    /// `DirCorpusBuilder::directory` have been called.
    ///
    /// This constructor can be used to immediately provide the items, if desired.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::corpora::DirCorpus;
    /// # use feroxfuzz::prelude::*;
    /// # use tempdir::TempDir;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // test setup:
    /// // - temporary directory that contains 2 files
    /// // - each file has 2 lines
    /// let tmp_dir = TempDir::new("test-corpus")?;
    ///
    /// let file_one = tmp_dir.path().join("test-file-one");
    /// let mut tmp_file = File::create(file_one)?;
    /// writeln!(tmp_file, "one")?;
    /// writeln!(tmp_file, "two")?;
    ///
    /// let file_two = tmp_dir.path().join("test-file-two");
    /// tmp_file = File::create(file_two)?;
    /// writeln!(tmp_file, "three")?;
    /// writeln!(tmp_file, "four")?;
    ///
    /// // create a Corpus from the given directory
    /// let corpus = DirCorpus::from_directory(tmp_dir.path())?.name("corpus").build();
    ///
    /// // resulting DirCorpus has 4 entries, one for each line found in the files above
    /// assert_eq!(corpus.len(), 4);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip_all, level = "trace")]
    pub fn from_directory<P>(
        directory: P,
    ) -> Result<DirCorpusBuilder<HasItems, NoName>, FeroxFuzzError>
    where
        P: AsRef<Path>,
    {
        Ok(DirCorpusBuilder {
            items: from_directory(directory)?,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        })
    }

    /// get a reference to the inner collection of corpus items
    #[must_use]
    #[inline]
    pub fn items(&self) -> &[Data] {
        &self.items
    }

    /// get a mutable reference to the inner collection of corpus items
    #[must_use]
    #[inline]
    pub fn items_mut(&mut self) -> &mut [Data] {
        &mut self.items
    }
}

impl Named for DirCorpus {
    fn name(&self) -> &str {
        &self.corpus_name
    }
}

impl Len for DirCorpus {
    #[inline]
    #[must_use]
    fn len(&self) -> usize {
        self.items.len()
    }
}

impl AsInner for DirCorpus {
    type Type = Vec<Data>;

    fn inner(&self) -> &Self::Type {
        &self.items
    }
}

impl Display for DirCorpus {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_top(3))
    }
}

impl Index<usize> for DirCorpus {
    type Output = Data;

    fn index(&self, index: usize) -> &Self::Output {
        &self.items()[index]
    }
}

impl IndexMut<usize> for DirCorpus {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.items_mut()[index]
    }
}

/// non-consuming mutable iterator over `DirCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::DirCorpus;
/// # use feroxfuzz::prelude::*;
/// # use tempdir::TempDir;
/// # use std::fs::File;
/// # use std::io::Write;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // test setup:
/// // - temporary directory that contains 2 files
/// // - each file has 2 lines
/// let tmp_dir = TempDir::new("test-corpus")?;
///
/// let file_one = tmp_dir.path().join("test-file-one");
/// let mut tmp_file = File::create(file_one)?;
/// writeln!(tmp_file, "one")?;
/// writeln!(tmp_file, "two")?;
///
/// let file_two = tmp_dir.path().join("test-file-two");
/// tmp_file = File::create(file_two)?;
/// writeln!(tmp_file, "three")?;
/// writeln!(tmp_file, "four")?;
///
/// // the values we expect to procure during iteration
/// let expected = vec!["a", "a", "a", "a"];
///
/// // create a Corpus of Strings from the given directory
/// let mut corpus = DirCorpus::from_directory(tmp_dir.path())?.name("corpus").build();
///
/// for item in &mut corpus {
///     *item = "a".into();
/// }
///
/// assert_eq!(corpus.items(), expected);
/// # Ok(())
/// # }
/// ```
///
impl<'i> IntoIterator for &'i mut DirCorpus {
    /// the type of the elements being iterated over
    type Item = &'i mut Data;

    /// the kind of iterator we're turning `DirCorpus` into
    type IntoIter = <&'i mut [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `DirCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter_mut()
    }
}

/// consuming iterator over `DirCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::DirCorpus;
/// # use feroxfuzz::prelude::*;
/// # use tempdir::TempDir;
/// # use std::fs::File;
/// # use std::io::Write;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // test setup:
/// // - temporary directory that contains 2 files
/// // - each file has 2 lines
/// let tmp_dir = TempDir::new("test-corpus")?;
///
/// let file_one = tmp_dir.path().join("test-file-one");
/// let mut tmp_file = File::create(file_one)?;
/// writeln!(tmp_file, "one")?;
/// writeln!(tmp_file, "two")?;
///
/// let file_two = tmp_dir.path().join("test-file-two");
/// tmp_file = File::create(file_two)?;
/// writeln!(tmp_file, "three")?;
/// writeln!(tmp_file, "four")?;
///
/// // the values we expect to procure during iteration
/// let expected = vec!["one", "two", "three", "four"];
///
/// // create a Corpus of Strings from the given directory
/// let mut corpus = DirCorpus::from_directory(tmp_dir.path())?.name("corpus").build();
///
/// let mut gathered = vec![];
///
/// for item in corpus {
///     gathered.push(item);
/// }
///
/// for item in expected {
///    let data: Data = item.into();
///    assert!(gathered.contains(&data));
/// }
///
/// # Ok(())
/// # }
/// ```
///
impl IntoIterator for DirCorpus {
    /// the type of the elements being iterated over
    type Item = Data;

    /// the kind of iterator we're turning `DirCorpus` into
    type IntoIter = <Vec<Data> as IntoIterator>::IntoIter;

    /// creates an iterator from `DirCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

/// non-consuming iterator over `DirCorpus`
///
/// # Examples
///
/// ```
/// # use feroxfuzz::corpora::DirCorpus;
/// # use feroxfuzz::prelude::*;
/// # use tempdir::TempDir;
/// # use std::fs::File;
/// # use std::io::Write;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // test setup:
/// // - temporary directory that contains 2 files
/// // - each file has 2 lines
/// let tmp_dir = TempDir::new("test-corpus")?;
///
/// let file_one = tmp_dir.path().join("test-file-one");
/// let mut tmp_file = File::create(file_one)?;
/// writeln!(tmp_file, "one")?;
/// writeln!(tmp_file, "two")?;
///
/// let file_two = tmp_dir.path().join("test-file-two");
/// tmp_file = File::create(file_two)?;
/// writeln!(tmp_file, "three")?;
/// writeln!(tmp_file, "four")?;
///
/// // the values we expect to procure during iteration
/// let expected = vec!["one", "two", "three", "four"];
///
/// // create a Corpus of Strings from the given directory
/// let mut corpus = DirCorpus::from_directory(tmp_dir.path())?.name("corpus").build();
///
/// let mut gathered = vec![];
///
/// for item in &corpus {
///     gathered.push(item);
/// }
///
/// for item in expected {
///    let data: Data = item.into();
///    assert!(gathered.contains(&&data));
/// }
///
/// # Ok(())
/// # }
/// ```
impl<'i> IntoIterator for &'i DirCorpus {
    /// the type of the elements being iterated over
    type Item = &'i Data;

    /// the kind of iterator we're turning `DirCorpus` into
    type IntoIter = <&'i [Data] as IntoIterator>::IntoIter;

    /// creates an iterator from `DirCorpus.items`
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

pub struct DirCorpusBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    items: Vec<Data>,
    corpus_name: Option<String>,
    _item_state: PhantomData<IS>,
    _name_state: PhantomData<NS>,
}

impl<IS> DirCorpusBuilder<IS, NoName>
where
    IS: CorpusBuildState,
{
    pub fn name(self, corpus_name: &str) -> DirCorpusBuilder<IS, HasName> {
        DirCorpusBuilder {
            items: self.items,
            corpus_name: Some(corpus_name.to_string()),
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl<IS, NS> DirCorpusBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    pub fn directory<P>(
        mut self,
        directory: P,
    ) -> Result<DirCorpusBuilder<HasItems, NS>, FeroxFuzzError>
    where
        P: AsRef<Path>,
    {
        let new_items = from_directory(directory)?;

        self.items.extend(new_items);

        Ok(DirCorpusBuilder {
            items: self.items,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        })
    }
}

impl DirCorpusBuilder<HasItems, HasName> {
    pub fn build(self) -> CorpusType {
        CorpusType::Dir(DirCorpus {
            items: self.items,
            corpus_name: self.corpus_name.unwrap(),
        })
    }
}
