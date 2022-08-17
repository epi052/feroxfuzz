use std::fmt::Display;
use std::marker::PhantomData;

use super::{Corpus, CorpusType, Named};
use crate::corpora::typestate::{CorpusBuildState, HasItems, HasName, NoItems, NoName};
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::std_ext::{convert::AsInner, ops::Len};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::error;

/// an implementor of the [`Corpus`] trait that creates a range of values suitable
/// for mutation.
#[derive(Clone, Debug, Default, PartialEq, PartialOrd, Ord, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RangeCorpus {
    start: i64,
    stop: i64,
    step: i64,
    items: Vec<Data>,
    corpus_name: String,
}

impl AsInner for RangeCorpus {
    type Type = Vec<Data>;

    fn inner(&self) -> &Self::Type {
        &self.items
    }
}

impl Display for RangeCorpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RangeCorpus::{{start={}, stop={}, step={}}}",
            self.start, self.stop, self.step
        )
    }
}

impl RangeCorpus {
    /// create a new/empty `RangeBuilder`
    ///
    /// # Note
    ///
    /// `RangeBuilder::build` can only be called after `RangeBuilder::name` and
    /// `RangeBuilder::stop` have been called.
    ///
    /// Optionally, `RangeBuilder::start` and `RangeBuilder::step` can be called
    /// to provide non-default values for the start and step of the range.
    ///
    /// The [`RangeCorpus::with_stop`] constructor can be used to immediately provide
    /// the stop value for the range, if desired.
    ///
    /// # Examples
    ///
    /// create a new [`RangeCorpus`] with the default `step` of `1` and the default
    /// `start` of `0`
    ///
    /// ```
    /// # use feroxfuzz::corpora::RangeCorpus;
    /// # use feroxfuzz::prelude::*;
    /// # use tempdir::TempDir;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let corpus = RangeCorpus::new().name("corpus").stop(10).build()?;
    ///
    /// assert_eq!(corpus.len(), 10);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[allow(clippy::new_ret_no_self)]
    pub const fn new() -> RangeBuilder<NoItems, NoName> {
        RangeBuilder {
            start: None,
            stop: None,
            step: None,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    /// create a new `RangeBuilder` with the given `stop` value
    ///
    /// # Examples
    ///
    /// create a new [`RangeCorpus`] with a `step` other than `1`
    ///
    /// ```
    /// # use feroxfuzz::corpora::RangeCorpus;
    /// # use feroxfuzz::prelude::*;
    /// # use tempdir::TempDir;
    /// # use std::fs::File;
    /// # use std::io::Write;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut corpus = RangeCorpus::with_stop(10).name("corpus").step(2).build()?;
    ///
    /// assert_eq!(corpus.len(), 5);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[allow(clippy::similar_names)]
    pub const fn with_stop(stop: i64) -> RangeBuilder<HasItems, NoName> {
        RangeBuilder {
            start: None,
            stop: Some(stop),
            step: None,
            corpus_name: None,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl Named for RangeCorpus {
    fn name(&self) -> &str {
        &self.corpus_name
    }
}

impl Corpus for RangeCorpus {
    fn add(&mut self, value: Data) {
        self.items.push(value);
    }

    fn get(&self, index: usize) -> Option<&Data> {
        self.items.get(index)
    }

    fn items(&self) -> &[Data] {
        &self.items
    }
}

impl Len for RangeCorpus {
    fn len(&self) -> usize {
        self.items.len()
    }
}

pub struct RangeBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    start: Option<i64>,
    stop: Option<i64>,
    step: Option<i64>,
    corpus_name: Option<String>,
    _item_state: PhantomData<IS>,
    _name_state: PhantomData<NS>,
}

impl<IS> RangeBuilder<IS, NoName>
where
    IS: CorpusBuildState,
{
    pub fn name(self, corpus_name: &str) -> RangeBuilder<IS, HasName> {
        RangeBuilder {
            start: self.start,
            stop: self.stop,
            step: self.step,
            corpus_name: Some(corpus_name.to_string()),
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl<IS, NS> RangeBuilder<IS, NS>
where
    IS: CorpusBuildState,
    NS: CorpusBuildState,
{
    #[allow(clippy::missing_const_for_fn)]
    pub fn start(self, start: i64) -> Self {
        Self {
            start: Some(start),
            stop: self.stop,
            step: self.step,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    pub fn stop(self, stop: i64) -> RangeBuilder<HasItems, NS> {
        RangeBuilder {
            start: self.start,
            stop: Some(stop),
            step: self.step,
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    pub fn step(self, step: i64) -> Self {
        Self {
            start: self.start,
            stop: self.stop,
            step: Some(step),
            corpus_name: self.corpus_name,
            _item_state: PhantomData,
            _name_state: PhantomData,
        }
    }
}

impl RangeBuilder<HasItems, HasName> {
    /// # Errors
    ///
    /// returns an error when
    /// - `start` and `stop` are equal values
    /// - `step` is 0
    /// - `step` is negative and `stop` is greater than `start` (i.e. would have to wrap around to reach `stop`)
    #[allow(clippy::similar_names)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn build(self) -> Result<CorpusType, FeroxFuzzError> {
        let start = self.start.unwrap_or(0);
        let stop = self.stop.unwrap(); // mandatory, can't get here without it being set
        let step = self.step.unwrap_or(1);

        if step == 0 {
            error!(%start, %stop, %step, "RangeCorpus step cannot be 0");

            return Err(FeroxFuzzError::InvalidParameter {
                param: step.to_string(),
                message: "RangeCorpus can't have a step of 0",
            });
        }

        if start == stop {
            error!(%start, %stop, %step, "RangeCorpus start and step cannot be equal");

            return Err(FeroxFuzzError::InvalidParameter {
                param: stop.to_string(),
                message: "RangeCorpus with equal start and stop values doesn't make any sense",
            });
        }

        if step.is_negative() && stop > start {
            // catches things like with_step(0, 100, -1)
            error!(%start, %stop, %step, "RangeCorpus can't have a negative step when `stop` is greater than `start`");

            return Err(FeroxFuzzError::InvalidParameter {
                param: step.to_string(),
                message:
                    "RangeCorpus can't have a negative step when `stop` is greater than `start`",
            });
        }

        // at this point, we know that either:
        // - start < stop and step > 0
        // - start > stop and step < 0
        assert!((start < stop && step > 0) || (start > stop && step < 0));

        let items = if step.is_negative() {
            (stop..=start)
                .rev()
                .step_by(step.unsigned_abs() as usize)
                .map(|i| i.to_string().into())
                .collect()
        } else {
            (start..stop)
                .step_by(step as usize)
                .map(|i| i.to_string().into())
                .collect()
        };

        let range = RangeCorpus {
            start,
            stop,
            step,
            items,
            corpus_name: self.corpus_name.unwrap(),
        };

        Ok(CorpusType::Range(range))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ensure that there's a single allocation per call to `.get`
    #[test]
    fn range_corpus_allocations_in_constructor_and_get() {
        let range: i64 = 10;
        let mut x = RangeCorpus::with_stop(range)
            .name("corpus")
            .build()
            .unwrap(); // temp to initialize

        let constructor_alloc = allocation_counter::count(|| {
            x = RangeCorpus::with_stop(range)
                .name("corpus")
                .build()
                .unwrap();
        });

        let get_alloc = allocation_counter::count(|| {
            x.get(3);
        });

        assert_eq!(constructor_alloc, 12); // corpus_name.to_string()
        assert_eq!(get_alloc, 0); // i64::to_string
    }

    /// hit the different ok/err branches of the `with_step` constructor
    #[test]
    fn range_corpus_with_variations_on_constructor() {
        assert!(RangeCorpus::new()
            .name("range")
            .stop(1)
            .step(0)
            .build()
            .is_err());
        assert!(RangeCorpus::new()
            .name("range")
            .stop(10)
            .step(-1)
            .build()
            .is_err());
        assert!(RangeCorpus::new()
            .name("range")
            .start(0)
            .stop(0)
            .step(1)
            .build()
            .is_err());

        let range = RangeCorpus::new()
            .start(0)
            .name("range")
            .stop(1)
            .step(1)
            .build()
            .unwrap();

        assert_eq!(range.len(), 1);
        assert_eq!(range.get(0).unwrap(), "0");
        assert!(range.get(1).is_none());
    }

    /// test negative values/steps etc all work correctly
    #[test]
    fn range_corpus_step_tests() {
        // two positives

        let mut range = RangeCorpus::new()
            .name("range")
            .start(100)
            .stop(0)
            .step(-1)
            .build()
            .unwrap();
        assert_eq!(range.get(0).unwrap(), "100");
        assert_eq!(range.get(10).unwrap(), "90");

        // positive/negative

        range = RangeCorpus::new()
            .name("range")
            .start(0)
            .stop(-100)
            .step(-2)
            .build()
            .unwrap();
        assert_eq!(range.get(0).unwrap(), "0");
        assert_eq!(range.get(10).unwrap(), "-20");

        // 2 negatives
        range = RangeCorpus::new()
            .name("range")
            .start(-100)
            .stop(-200)
            .step(-2)
            .build()
            .unwrap();
        assert_eq!(range.get(0).unwrap(), "-100");
        assert_eq!(range.get(10).unwrap(), "-120");

        // something different
        range = RangeCorpus::new()
            .name("range")
            .start(1234)
            .stop(4321)
            .step(10)
            .build()
            .unwrap();
        assert_eq!(range.get(0).unwrap(), "1234");
        assert_eq!(range.get(10).unwrap(), "1334");
    }

    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    #[test]
    fn range_corpus_len_tests() {
        let mut range = RangeCorpus::new().name("range").stop(100).build().unwrap();

        assert_eq!(range.len(), 100);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(2)
            .build()
            .unwrap();
        assert_eq!(range.len(), 50);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(3)
            .build()
            .unwrap();
        assert_eq!(range.len(), 34);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(4)
            .build()
            .unwrap();
        assert_eq!(range.len(), 25);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(5)
            .build()
            .unwrap();
        assert_eq!(range.len(), 20);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(6)
            .build()
            .unwrap();
        assert_eq!(range.len(), 17);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(7)
            .build()
            .unwrap();
        assert_eq!(range.len(), 15);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(8)
            .build()
            .unwrap();
        assert_eq!(range.len(), 13);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(9)
            .build()
            .unwrap();
        assert_eq!(range.len(), 12);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(10)
            .build()
            .unwrap();
        assert_eq!(range.len(), 10);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(11)
            .build()
            .unwrap();
        assert_eq!(range.len(), 10);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(12)
            .build()
            .unwrap();
        assert_eq!(range.len(), 9);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(13)
            .build()
            .unwrap();
        assert_eq!(range.len(), 8);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(14)
            .build()
            .unwrap();
        assert_eq!(range.len(), 8);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(15)
            .build()
            .unwrap();
        assert_eq!(range.len(), 7);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(16)
            .build()
            .unwrap();
        assert_eq!(range.len(), 7);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(17)
            .build()
            .unwrap();
        assert_eq!(range.len(), 6);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(18)
            .build()
            .unwrap();
        assert_eq!(range.len(), 6);

        range = RangeCorpus::new()
            .name("range")
            .stop(100)
            .step(19)
            .build()
            .unwrap();
        assert_eq!(range.len(), 6);

        // start testing the upper/lower bounds for ranges of values that have the same length
        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(20)
            .build()
            .unwrap();
        assert_eq!(range.len(), 5);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(24)
            .build()
            .unwrap();
        assert_eq!(range.len(), 5);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(25)
            .build()
            .unwrap();
        assert_eq!(range.len(), 4);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(33)
            .build()
            .unwrap();
        assert_eq!(range.len(), 4);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(34)
            .build()
            .unwrap();
        assert_eq!(range.len(), 3);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(49)
            .build()
            .unwrap();
        assert_eq!(range.len(), 3);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(50)
            .build()
            .unwrap();
        assert_eq!(range.len(), 2);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(99)
            .build()
            .unwrap();
        assert_eq!(range.len(), 2);

        range = RangeCorpus::with_stop(100)
            .name("range")
            .step(100)
            .build()
            .unwrap();
        assert_eq!(range.len(), 1);

        // anything with a step greater than its stop will still have a length of 1
    }
}
