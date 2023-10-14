//! Find-and-replace user-defined tokens in fuzzable data using [`Corpus`] entries

use super::Mutator;
use crate::atomic_load;
use crate::corpora::Corpus;
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::metadata::AsAny;
use crate::state::SharedState;
use crate::std_ext::tuple::Named;
use crate::AsBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use std::any::Any;
use std::sync::atomic::Ordering;

use tracing::{error, instrument, trace};

/// Token-based mutator. Examines input [`Data`] for all instances of
/// its `keyword` and replaces those instances with an item
/// from the [`Corpus`]
///
/// # Examples
///
/// While the example below works, the normal use-case for this struct is to pass
/// it, and any other [`Mutators`] to the [`build_mutators`] macro, and pass
/// the result of that call to your chosen [`Fuzzer`] implementation.
///
/// [`Fuzzer`]: crate::fuzzers::Fuzzer
/// [`Mutators`]: crate::mutators::Mutators
/// [`build_mutators`]: crate::build_mutators
///
/// ```
/// # use feroxfuzz::corpora::Wordlist;
/// # use feroxfuzz::state::SharedState;
/// # use feroxfuzz::input::Data;
/// # use feroxfuzz::mutators::Mutator;
/// # use feroxfuzz::mutators::ReplaceKeyword;
/// # use feroxfuzz::error::FeroxFuzzError;
/// # fn main() -> Result<(), FeroxFuzzError> {
/// let words = vec![String::from("../../../../../etc/passwd")];
/// let corpus = Wordlist::with_words(words).name("corpus").build();
///
/// let mut state = SharedState::with_corpus(corpus);
///
/// let mut mutator = ReplaceKeyword::new(&"FUZZ", "corpus");
///
/// let mut to_mutate = Data::Fuzzable(b"/dir/path/FUZZ".to_vec());
///
/// mutator.mutate(&mut to_mutate, &mut state)?;
///
/// assert_eq!(to_mutate, Data::Fuzzable(b"/dir/path/../../../../../etc/passwd".to_vec()));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReplaceKeyword {
    keyword: Vec<u8>,
    corpus_name: String,
}

impl ReplaceKeyword {
    /// create a new `ReplaceKeyword` mutator with the given `keyword`
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::mutators::Mutator;
    /// # use feroxfuzz::mutators::ReplaceKeyword;
    /// let mutator = ReplaceKeyword::new("FUZZ", "associated-corpus-name");
    /// let mutator = ReplaceKeyword::new(&b"FUZZ".to_vec(), "associated-corpus-name");
    /// let mutator = ReplaceKeyword::new(&String::from("FUZZ"), "associated-corpus-name");
    /// let mutator = ReplaceKeyword::new(&vec![0x46_u8, 0x55, 0x5a, 0x5a], "associated-corpus-name");
    /// ```
    pub fn new<S>(keyword: &S, corpus_name: &str) -> Self
    where
        S: AsBytes + ?Sized,
    {
        Self {
            keyword: keyword.as_bytes().to_vec(),
            corpus_name: corpus_name.to_string(),
        }
    }
}

impl Mutator for ReplaceKeyword {
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[instrument(skip_all, fields(?self.keyword), level = "trace")]
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        if let Data::Fuzzable(data) = input {
            // data is fuzzable, need to mutate it
            let corpus = state.corpus_by_name(&self.corpus_name)?;
            let corpus_index = state.corpus_index_by_name(&self.corpus_name)?;

            if let Ok(guard) = corpus.read() {
                let fetched_idx = atomic_load!(corpus_index);

                let result = guard.get(fetched_idx);

                if result.is_none() {
                    // using is_none with a return instead of a map_err because the
                    // guard can't be borrowed twice in order to get the .name() of the corpus
                    error!(
                        name = guard.name(),
                        index = fetched_idx,
                        "could not find requested corpus entry"
                    );

                    return Err(FeroxFuzzError::CorpusEntryNotFound {
                        name: guard.name().to_string(),
                        index: fetched_idx,
                    });
                }

                let entry = result.unwrap();

                // this chain walks the fuzzable input, looking for the keyword
                // if one is found, it's collected into a vector of indices,
                // showing where each keyword begins
                let indices = data
                    .windows(self.keyword.len())
                    .enumerate()
                    .filter(|(_, window)| *window == self.keyword.as_slice())
                    .fold(Vec::new(), |mut acc, (idx, _)| {
                        acc.push(idx);
                        acc
                    });

                if indices.is_empty() {
                    // early return to avoid allocation if no indices found
                    trace!(
                        "keyword '{:?}' not found in data '{:?}'",
                        &self.keyword,
                        data
                    );
                    return Ok(());
                }

                // calculate the difference in byte-length between the keyword and
                // what will replace it. In the case of multiple keywords in a single
                // piece of data, the index gathered above will move by some amount.
                // the `step` value here is one piece of info necessary to calculate
                // how far the move is.
                let entry_length = i64::try_from(entry.len()).map_err(|source| {
                    tracing::error!(%source, "could not convert from {} to an i64", entry.len());

                    FeroxFuzzError::ConversionError {
                        value: format!("{}", entry.len()),
                        to: String::from("i64"),
                        from: String::from("usize"),
                    }
                })?;

                let keyword_length = i64::try_from(self.keyword.len()).map_err(|source| {
                    tracing::error!(%source, "could not convert from {} to an i64", self.keyword.len());

                    FeroxFuzzError::ConversionError {
                        value: format!("{}", self.keyword.len()),
                        to: String::from("i64"),
                        from: String::from("usize"),
                    }
                })?;

                let step = entry_length - keyword_length;

                indices.iter().enumerate().for_each(|(i, &idx)| {
                    // when the step is negative, we need to subtract the
                    // step from the index, otherwise, we'll need to add.
                    // the final offset increases for each additional keyword
                    // that gets replaced, so we also multiple the step
                    // by the current loop iteration
                    let offset = if step.is_negative() {
                        idx - (i * step.wrapping_abs() as usize)
                    } else {
                        idx + (i * step as usize)
                    };

                    // finally, we remove the old data and insert the new.
                    // lengths do not have to match
                    data.splice(
                        offset..offset + self.keyword.len(),
                        entry.as_bytes().iter().copied(),
                    );
                });
            };
        }

        Ok(())
    }
}

impl Named for ReplaceKeyword {
    fn name(&self) -> &str {
        "ReplaceKeyword"
    }
}

impl AsAny for ReplaceKeyword {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpora::Wordlist;

    fn keyword_mutator_test_helper(words: Vec<String>, to_replace: &mut Data) {
        let corpus = Wordlist::with_words(words).name("corpus").build();
        let mut state = SharedState::with_corpus(corpus);

        let mut replacer = ReplaceKeyword::new(&"FUZZ", "corpus");

        replacer.mutate(to_replace, &mut state).unwrap();
    }

    #[test]
    fn keyword_mutator_with_longer_replacement() {
        let words = vec![String::from("longer")];
        let mut to_replace = Data::Fuzzable(b"stFUFUZZZZackedFUZZ".to_vec());

        keyword_mutator_test_helper(words, &mut to_replace);

        assert_eq!(
            to_replace,
            Data::Fuzzable(b"stFUlongerZZackedlonger".to_vec())
        );
    }

    #[test]
    fn keyword_mutator_with_shorter_replacement() {
        let words = vec![String::from("st")];
        let mut to_replace = Data::Fuzzable(b"stFUFUZZZZackedFUZZ".to_vec());

        keyword_mutator_test_helper(words, &mut to_replace);

        assert_eq!(to_replace, Data::Fuzzable(b"stFUstZZackedst".to_vec()));
    }

    #[test]
    fn keyword_mutator_with_no_replacement() {
        let words = vec![String::from("st")];
        let mut to_replace = Data::Fuzzable(b"stacked".to_vec());

        keyword_mutator_test_helper(words, &mut to_replace);

        assert_eq!(to_replace, Data::Fuzzable(b"stacked".to_vec()));
    }

    #[test]
    fn keyword_mutator_with_static_data() {
        let words = vec![String::from("derp")];
        let mut to_replace = Data::Static(b"staFUZZcked".to_vec());

        keyword_mutator_test_helper(words, &mut to_replace);

        assert_eq!(to_replace, Data::Static(b"staFUZZcked".to_vec()));
    }

    #[test]
    fn keyword_mutator_with_empty_corpus() {
        let words: Vec<String> = vec![];
        let mut to_replace = Data::Fuzzable(b"staFUZZcked".to_vec());

        let corpus = Wordlist::with_words(words).name("corpus").build();
        let mut state = SharedState::with_corpus(corpus);

        let mut replacer = ReplaceKeyword::new(&"FUZZ", "corpus");

        assert!(replacer.mutate(&mut to_replace, &mut state).is_err());
    }
}
