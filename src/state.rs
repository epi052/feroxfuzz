//! fuzzer's runtime state information  
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

use tracing::{debug, error, instrument, warn};

use crate::corpora::{CorpusIndices, CorpusMap, CorpusType};
use crate::error::FeroxFuzzError;
use crate::metadata::{Metadata, MetadataMap};
use crate::observers::Observers;
use crate::requests::Request;
use crate::responses::{Response, Timed};
use crate::statistics::Statistics;
use crate::Len;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::corpora::Corpus;
        use crate::observers::{ResponseObserver, Observer};
        use crate::std_ext::tuple::Named;
        use crate::input::Data;
    }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use libafl::bolts::rands::RomuDuoJrRand;
use libafl::state::{HasMaxSize, HasRand, DEFAULT_MAX_SIZE};

/// fuzzer's current state
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SharedState {
    // the AsyncFuzzer and the BlockingFuzzer have wildly different ownership
    // requirements. Instead of having yet another blocking vs async
    // struct implementation, i decided to accept the overhead of Arc<RwLock>
    // in a blocking context. Since the primary use-case is asynchronous
    // fuzzing, coupled with the fact that the blocking fuzzer example
    // exhibits a very small slowdown, i decided to simply use Arc<RwLock>
    // for both blocking and async fuzzing.
    corpora: CorpusMap,
    statistics: Arc<RwLock<Statistics>>,

    // collection of user-supplied objects that implement the [`Metadata`] trait
    //
    // currently the only source of dynamic dispatch in the crate
    metadata: MetadataMap,

    // rng stuff, both of which are Copy
    seed: u64,
    rng: RomuDuoJrRand,

    // in order to facilitate more complex scheduling, we're going to use
    // a hashmap of corpus-names->atomicusize to track the current index
    // of the corpus. this is necessary to support multiple corpora with
    // more complex scheduling.
    corpus_indices: CorpusIndices,
}

impl SharedState {
    /// given a single implementor of [`Corpus`], create a new `SharedState` object
    ///
    /// # Note
    ///
    /// In order to have a seeded RNG, the `set_seed` method must be used after
    /// instantiation. If no seed is set, the default seed (`0x5eed`) will be used.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::corpora::{Corpus, Wordlist, RangeCorpus};
    /// # use feroxfuzz::state::SharedState;
    /// # use std::str::FromStr;
    /// # use feroxfuzz::prelude::Data;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    ///
    /// let state = SharedState::with_corpus(ids);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[instrument(skip_all, level = "trace")]
    pub fn with_corpus(corpus: CorpusType) -> Self {
        let statistics = Statistics::new();

        let seed = 0x5eed;

        let mut state_corpora = HashMap::new();
        let mut corpus_indices = HashMap::new();

        corpus_indices.insert(corpus.name().to_string(), AtomicUsize::new(0));

        state_corpora.insert(corpus.name().to_string(), Arc::new(RwLock::new(corpus)));

        debug!(%seed, num_corpora=state_corpora.len(), "created new SharedState");

        Self {
            corpora: Arc::new(state_corpora),
            statistics: Arc::new(RwLock::new(statistics)),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            seed,
            rng: RomuDuoJrRand::with_seed(seed),
            corpus_indices: Arc::new(corpus_indices),
        }
    }

    /// given a list of types implementing [`Corpus`], create a new `SharedState` object
    ///
    /// # Note
    ///
    /// In order to have a seeded RNG, the `set_seed` method must be used after
    /// instantiation. If no seed is set, the default seed (`0x5eed`) will be used.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::corpora::{Corpus, Wordlist, RangeCorpus};
    /// # use feroxfuzz::state::SharedState;
    /// # use std::str::FromStr;
    /// # use feroxfuzz::prelude::Data;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// // create as many corpora as necessary
    /// let names = Wordlist::with_words(["bob", "alice"])
    ///     .name("first_names")
    ///     .build();
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    ///
    /// let corpora = vec![names, ids];
    ///
    /// let state = SharedState::with_corpora(corpora);
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(corpora), level = "trace")]
    pub fn with_corpora<I>(corpora: I) -> Self
    where
        I: IntoIterator<Item = CorpusType>,
    {
        let statistics = Statistics::new();

        let seed = 0x5eed;

        let mut state_corpora = HashMap::new();
        let mut corpus_indices = HashMap::new();

        for corpus in corpora {
            state_corpora.insert(
                corpus.name().to_string(),
                Arc::new(RwLock::new(corpus.clone())),
            );
            corpus_indices.insert(corpus.name().to_string(), AtomicUsize::new(0));
        }

        debug!(%seed, ?corpus_indices, "created new SharedState");

        Self {
            corpora: Arc::new(state_corpora),
            statistics: Arc::new(RwLock::new(statistics)),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            seed,
            rng: RomuDuoJrRand::with_seed(seed),
            corpus_indices: Arc::new(corpus_indices),
        }
    }

    /// remove the default "0x5eed" PRNG from the state and replace
    /// it with a new one that uses the given seed
    #[instrument(level = "trace")]
    pub fn set_seed(&mut self, seed: u64) {
        self.seed = seed;
        self.rng = RomuDuoJrRand::with_seed(seed);
    }

    /// get corpora container
    #[must_use]
    pub fn corpora(&self) -> CorpusMap {
        self.corpora.clone()
    }

    /// get the statistics container
    #[must_use]
    pub fn stats(&self) -> Arc<RwLock<Statistics>> {
        self.statistics.clone()
    }

    /// get the mapping of corpus names to their current index
    #[must_use]
    pub fn corpus_indices(&self) -> CorpusIndices {
        self.corpus_indices.clone()
    }

    /// get the random number generator
    #[must_use]
    pub const fn rng(&self) -> &RomuDuoJrRand {
        &self.rng
    }

    /// get a mutable reference to the random number generator
    #[must_use]
    pub fn rng_mut(&mut self) -> &mut RomuDuoJrRand {
        &mut self.rng
    }

    /// lookup a [`Corpus`] by its associated name (key)
    ///
    /// # Errors
    ///
    /// If the key is not found, a [`FeroxFuzzError`] is returned.
    #[instrument(level = "trace")]
    pub fn corpus_by_name(&self, name: &str) -> Result<Arc<RwLock<CorpusType>>, FeroxFuzzError> {
        self.corpora
            .get(name)
            .ok_or_else(|| {
                error!(%name, "corpus not found");

                FeroxFuzzError::CorpusNotFound {
                    name: name.to_string(),
                }
            })
            .map(Clone::clone)
    }

    /// lookup a [`Corpus`] by its associated name (key) and return its current index
    ///
    /// # Errors
    ///
    /// If the key is not found, a [`FeroxFuzzError`] is returned.
    #[instrument(level = "trace")]
    pub fn corpus_index_by_name(&self, name: &str) -> Result<&AtomicUsize, FeroxFuzzError> {
        let atomic_index = self.corpus_indices.get(name).ok_or_else(|| {
            error!(%name, "corpus not found");

            FeroxFuzzError::CorpusIndexNotFound {
                name: name.to_string(),
            }
        })?;

        Ok(atomic_index)
    }

    /// given an [`Observers`] object with at least (and probably only) one
    /// [`ResponseObserver`], update the appropriate internal trackers
    ///
    /// # Errors
    ///
    /// `update` can fail if an expected [`Named`] [`Observer`] cannot be found
    /// in the [`Observers`] collection. `update` may also fail if the observed
    /// response's status code is outside of normal bounds (100-599)
    #[instrument(skip_all, level = "trace")]
    pub fn update<O, R>(&self, observers: &O) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        if let Ok(mut guard) = self.statistics.write() {
            guard.update(observers)?;
        }

        Ok(())
    }

    /// update the [`Statistics`] object with the given [`FeroxFuzzError`]
    ///
    /// # Errors
    ///
    /// `update_from_error` may fail if there is a status code associate with the response
    /// AND the status code is outside of normal bounds (100-599)
    #[instrument(skip_all, level = "trace")]
    pub fn update_from_error(&self, error: &FeroxFuzzError) -> Result<(), FeroxFuzzError> {
        if let Ok(mut guard) = self.statistics.write() {
            guard.update_from_error(error)?;
        }

        Ok(())
    }

    /// add given [`Request`]'s fuzzable [`Data`] fields to the given [`Corpus`]
    ///
    /// # Errors
    ///
    /// If the `corpus_name` is not found, a [`FeroxFuzzError`] is returned.
    #[instrument(skip(self, request), level = "trace")]
    pub fn add_to_corpus(
        &self,
        corpus_name: &str,
        request: &Request,
    ) -> Result<(), FeroxFuzzError> {
        let corpus = self.corpus_by_name(corpus_name)?;

        if let Ok(mut guard) = corpus.write() {
            // unlocked the corpus, so we can now add the data

            if request.scheme().is_fuzzable() {
                guard.add(request.scheme().clone());
            }

            if let Some(username) = request.username() {
                if username.is_fuzzable() {
                    guard.add(username.clone());
                }
            }

            if let Some(password) = request.password() {
                if password.is_fuzzable() {
                    guard.add(password.clone());
                }
            }

            if let Some(host) = request.host() {
                if host.is_fuzzable() {
                    guard.add(host.clone());
                }
            }

            if let Some(port) = request.port() {
                if port.is_fuzzable() {
                    guard.add(port.clone());
                }
            }

            if request.path().is_fuzzable() {
                guard.add(request.path().clone());
            }

            if let Some(fragment) = request.fragment() {
                if fragment.is_fuzzable() {
                    guard.add(fragment.clone());
                }
            }

            if request.method().is_fuzzable() {
                guard.add(request.method().clone());
            }

            if let Some(body) = request.body() {
                if body.is_fuzzable() {
                    guard.add(body.clone());
                }
            }

            if let Some(headers) = request.headers() {
                for (key, value) in headers.iter() {
                    if key.is_fuzzable() {
                        guard.add(key.clone());
                    }
                    if value.is_fuzzable() {
                        guard.add(value.clone());
                    }
                }
            }

            if let Some(params) = request.params() {
                for (key, value) in params.iter() {
                    if key.is_fuzzable() {
                        guard.add(key.clone());
                    }
                    if value.is_fuzzable() {
                        guard.add(value.clone());
                    }
                }
            }

            if let Some(user_agent) = request.user_agent() {
                if user_agent.is_fuzzable() {
                    guard.add(user_agent.clone());
                }
            }

            if request.version().is_fuzzable() {
                guard.add(request.version().clone());
            }
        }

        Ok(())
    }

    /// get the `[MetadataMap]`'
    #[must_use]
    pub fn metadata(&self) -> MetadataMap {
        self.metadata.clone()
    }

    /// add an implementor of [`Metadata`] to the `[MetadataMap]`
    pub fn add_metadata(&self, name: &str, metadata: impl Metadata + 'static) {
        if let Ok(mut guard) = self.metadata.write() {
            guard.insert(name.to_string(), Box::new(metadata));
        }
    }
}

impl Len for Arc<RwLock<CorpusType>> {
    fn len(&self) -> usize {
        if let Ok(guard) = self.read() {
            guard.len()
        } else {
            0
        }
    }
}

impl Display for SharedState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "SharedState::{{")?;
        writeln!(f, "  Seed={}", self.seed)?;
        writeln!(f, "  Rng={:?}", self.rng)?;

        for (key, corpus) in self.corpora.iter() {
            if let Ok(guard) = corpus.read() {
                writeln!(f, "  Corpus[{key}]={},", guard)?;
            }
        }

        if let Ok(guard) = self.stats().read() {
            writeln!(f, "  Statistics={}", guard)?;
        }

        writeln!(f, "}}")?;

        Ok(())
    }
}

// implement the HasRand and HasMaxSize traits from libafl so our
// state plays nicely with libafl mutators
impl HasRand for SharedState {
    type Rand = RomuDuoJrRand;

    fn rand(&self) -> &Self::Rand {
        &self.rng
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rng
    }
}

impl HasMaxSize for SharedState {
    fn max_size(&self) -> usize {
        DEFAULT_MAX_SIZE
    }

    fn set_max_size(&mut self, _max_size: usize) {
        // - pass -
        //
        // nothing calls this from libafl's code, and i don't see a
        // need for it in feroxfuzz
    }
}
