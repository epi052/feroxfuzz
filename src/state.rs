//! fuzzer's runtime state information  
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Once, RwLock};

use tracing::{debug, error, instrument, warn};

use crate::actions::Action;
use crate::corpora::{CorpusIndices, CorpusMap, CorpusType};
use crate::error::FeroxFuzzError;
use crate::events::{EventPublisher, ModifiedCorpus, Publisher};
use crate::input::Data;
use crate::metadata::{Metadata, MetadataMap};
use crate::observers::Observers;
use crate::requests::Request;
use crate::responses::{Response, Timed};
use crate::statistics::Statistics;
use crate::Len;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

// note: the following rng is from libafl. It was too heavy a solution to bring LibAFL
// along for a few traits and this rand implementation, so it's copied here instead.
// Full credit for the following rng implementation goes to the LibAFL authors.
use std::time::{SystemTime, UNIX_EPOCH};

/// Faster and almost unbiased alternative to `rand % n`.
///
/// For N-bit bound, probability of getting a biased value is 1/2^(64-N).
/// At least 2^2*(64-N) samples are required to detect this amount of bias.
///
/// See: [An optimal algorithm for bounded random integers](https://github.com/apple/swift/pull/39143).
#[allow(clippy::cast_possible_truncation)]
#[inline]
#[must_use]
pub fn fast_bound(rand: u64, n: usize) -> usize {
    debug_assert_ne!(n, 0);
    let mul = u128::from(rand).wrapping_mul(u128::from(n as u64));
    (mul >> 64) as usize
}

// https://prng.di.unimi.it/splitmix64.c
const fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// see <https://arxiv.org/pdf/2002.11331.pdf>
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct RomuDuoJrRand {
    x_state: u64,
    y_state: u64,
}

impl RomuDuoJrRand {
    /// Creates a rand instance, pre-seeded with the current time in nanoseconds.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub fn new() -> Self {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self::with_seed(current_time.as_nanos() as u64)
    }

    /// Creates a new `RomuDuoJrRand` with the given seed.
    #[must_use]
    pub const fn with_seed(seed: u64) -> Self {
        let mut rand = Self {
            x_state: 0,
            y_state: 0,
        };
        rand.set_seed(seed);
        rand
    }

    /// Sets the seed for the random number generator.
    pub const fn set_seed(&mut self, mut seed: u64) {
        self.x_state = splitmix64(&mut seed);
        self.y_state = splitmix64(&mut seed);
    }

    /// This method uses [`Iterator::size_hint`] for optimization. With an
    /// accurate hint and where [`Iterator::nth`] is a constant-time operation
    /// this method can offer `O(1)` performance. Where no size hint is
    /// available, complexity is `O(n)` where `n` is the iterator length.
    /// Partial hints (where `lower > 0`) also improve performance.
    ///
    /// Copy&paste from [`rand::IteratorRandom`](https://docs.rs/rand/0.8.5/rand/seq/trait.IteratorRandom.html#method.choose)
    pub fn choose<I>(&mut self, from: I) -> Option<I::Item>
    where
        I: IntoIterator,
    {
        let mut iter = from.into_iter();
        let (mut lower, mut upper) = iter.size_hint();
        let mut consumed = 0;
        let mut result = None;

        // Handling for this condition outside the loop allows the optimizer to eliminate the loop
        // when the Iterator is an ExactSizeIterator. This has a large performance impact on e.g.
        // seq_iter_choose_from_1000.
        if upper == Some(lower) {
            return if lower == 0 {
                None
            } else {
                iter.nth(self.below(lower))
            };
        }

        // Continue until the iterator is exhausted
        loop {
            if lower > 1 {
                let ix = self.below(lower + consumed);
                let skip = if ix < lower {
                    result = iter.nth(ix);
                    lower - (ix + 1)
                } else {
                    lower
                };
                if upper == Some(lower) {
                    return result;
                }
                consumed += lower;
                if skip > 0 {
                    iter.nth(skip - 1);
                }
            } else {
                let elem = iter.next();
                if elem.is_none() {
                    return result;
                }
                consumed += 1;
                if self.below(consumed) == 0 {
                    result = elem;
                }
            }

            let hint = iter.size_hint();
            lower = hint.0;
            upper = hint.1;
        }
    }

    /// Gets a value below the given bound (exclusive)
    #[inline]
    pub fn below(&mut self, upper_bound_excl: usize) -> usize {
        fast_bound(self.next().unwrap_or_default(), upper_bound_excl)
    }

    /// Generates the next random number in the sequence
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        let xp = self.x_state;
        self.x_state = 15_241_094_284_759_029_579_u64.wrapping_mul(self.y_state);
        self.y_state = self.y_state.wrapping_sub(xp).rotate_left(27);
        xp
    }
}

#[allow(clippy::copy_iterator)]
impl Iterator for RomuDuoJrRand {
    type Item = u64;

    /// Generates the next random number in the sequence.
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_u64())
    }
}

impl Default for RomuDuoJrRand {
    fn default() -> Self {
        Self::new()
    }
}

static mut HAS_LISTENERS: bool = false;
static INIT: Once = Once::new();

/// caches the answer to whether or not the publisher has any [`ModifiedCorpus`] listeners
///
/// [`ModifiedCorpus`]: crate::events::ModifiedCorpus
fn has_corpus_listeners(publisher: &Arc<RwLock<Publisher>>) -> bool {
    unsafe {
        INIT.call_once(|| {
            HAS_LISTENERS = publisher.has_listeners::<ModifiedCorpus>();
        });

        HAS_LISTENERS
    }
}

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

    // the publisher is the central event bus for the fuzzer. it's used
    // to publish events to all registered listeners.
    #[cfg_attr(feature = "serde", serde(skip))]
    publisher: Arc<RwLock<Publisher>>,
}

impl SharedState {
    /// given a single implementor of [`Corpus`], create a new `SharedState` object
    ///
    /// [`Corpus`]: crate::corpora::Corpus
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
            publisher: Arc::new(RwLock::new(Publisher::new())),
        }
    }

    /// given a list of types implementing [`Corpus`], create a new `SharedState` object
    ///
    /// [`Corpus`]: crate::corpora::Corpus
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
            publisher: Arc::new(RwLock::new(Publisher::new())),
        }
    }

    /// remove the default "0x5eed" PRNG from the state and replace
    /// it with a new one that uses the given seed
    #[instrument(level = "trace")]
    pub fn set_seed(&mut self, seed: u64) {
        self.seed = seed;
        self.rng = RomuDuoJrRand::with_seed(seed);
    }

    /// get the seed used to initialize the random number generator
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// given a single implementor of [`Corpus`], create a new `SharedState` object
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::corpora::{Corpus, Wordlist, RangeCorpus};
    /// # use feroxfuzz::state::SharedState;
    /// # use std::str::FromStr;
    /// # use feroxfuzz::prelude::Data;
    /// # use crate::feroxfuzz::Len;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    ///
    /// let mut state = SharedState::with_corpus(ids);
    ///
    /// state.add_corpus(Wordlist::with_words(["bob", "alice"]).name("first_names").build());
    ///
    /// assert_eq!(state.corpus_by_name("first_names").unwrap().len(), 2);
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip_all, fields(corpus_name = %corpus.name()), level = "trace")]
    pub fn add_corpus(&mut self, corpus: CorpusType) {
        let corpora_len = self.corpora.len();
        let indices_len = self.corpus_indices.len();

        if let Some(indices) = Arc::get_mut(&mut self.corpus_indices) {
            indices.insert(corpus.name().to_string(), AtomicUsize::new(0));
        } else {
            warn!("could not get mutable reference to Arc<CorpusIndices>");
        }

        if let Some(corpora) = Arc::get_mut(&mut self.corpora) {
            corpora.insert(corpus.name().to_string(), Arc::new(RwLock::new(corpus)));
        } else {
            warn!("could not get mutable reference to Arc<CorpusMap>");
        }

        if self.corpora.len() == corpora_len + 1 && self.corpus_indices.len() == indices_len + 1 {
            debug!(%corpora_len, %indices_len, "added new corpus to SharedState");
        } else {
            error!(%corpora_len, %indices_len, "failed to add new corpus to SharedState");
        }
    }

    /// get corpora container
    #[must_use]
    pub fn corpora(&self) -> CorpusMap {
        self.corpora.clone()
    }

    /// get the total length of all corpora
    ///
    /// i.e. the total number of elements in all corpora added together
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::corpora::{Corpus, Wordlist, RangeCorpus};
    /// # use feroxfuzz::state::SharedState;
    /// # use std::str::FromStr;
    /// # use feroxfuzz::prelude::Data;
    /// # use crate::feroxfuzz::Len;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// let ids = RangeCorpus::with_stop(5).name("ids").build()?;
    /// let names = Wordlist::with_words(["bob", "alice"]).name("names").build();
    ///
    /// let mut state = SharedState::with_corpora([ids, names]);
    ///
    /// assert_eq!(state.total_corpora_len(), 7);
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn total_corpora_len(&self) -> usize {
        self.corpora().values().map(Len::len).sum()
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

    /// get the mapping of corpus names to their current index
    #[must_use]
    pub const fn corpus_indices_mut(&mut self) -> &mut CorpusIndices {
        &mut self.corpus_indices
    }

    /// get the random number generator
    #[must_use]
    pub const fn rng(&self) -> &RomuDuoJrRand {
        &self.rng
    }

    /// get a mutable reference to the random number generator
    #[must_use]
    pub const fn rng_mut(&mut self) -> &mut RomuDuoJrRand {
        &mut self.rng
    }

    /// lookup a [`Corpus`] by its associated name (key)
    ///
    /// [`Corpus`]: crate::corpora::Corpus
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
    /// [`Corpus`]: crate::corpora::Corpus
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
    /// [`ResponseObserver`]: crate::observers::ResponseObserver
    /// [`Observers`]: crate::observers::Observers
    ///
    /// # Errors
    ///
    /// `update` can fail if an expected [`Named`] [`Observer`] cannot be found
    /// in the [`Observers`] collection. `update` may also fail if the observed
    /// response's status code is outside of normal bounds (100-599)
    ///
    /// [`Named`]: crate::Named
    /// [`Observer`]: crate::observers::Observer
    /// [`Observers`]: crate::observers::Observers
    #[instrument(skip_all, level = "trace")]
    pub fn update<O, R>(&self, observers: &O, action: Option<&Action>) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        if let Ok(mut guard) = self.statistics.write() {
            guard.update(observers, action)?;
        }

        Ok(())
    }

    /// update the [`Statistics`] object with the given [`FeroxFuzzError`]
    ///
    /// # Errors
    ///
    /// `update_from_error` may fail if there is a status code associate with the response
    /// AND the status code is outside of normal bounds (100-599)
    ///
    #[instrument(skip_all, level = "trace")]
    pub fn update_from_error(&self, error: &FeroxFuzzError) -> Result<(), FeroxFuzzError> {
        if let Ok(mut guard) = self.statistics.write() {
            guard.update_from_error(error)?;
        }

        Ok(())
    }

    /// update the [`Statistics`] object with the given [`Request`]
    #[instrument(skip_all, level = "trace")]
    pub fn update_from_request(&self, request: &Request) {
        if let Ok(mut guard) = self.statistics.write() {
            guard.update_from_request(request);
        }
    }

    /// simple wrapper around the process of publishing a message to any active
    /// listeners
    fn notify_listeners(
        &self,
        request: &Request,
        corpus_name: String,
        field: &'static str,
        entry: Data,
    ) {
        let has_listeners = has_corpus_listeners(&self.events());

        if has_listeners {
            // todo: this looks suspiciously like test/dev code, i think the fn is supposed to be generic?
            self.events().notify(ModifiedCorpus {
                id: request.id(),
                corpus: corpus_name,
                action: "add",
                from_field: field,
                entry,
            });
        }
    }

    /// add the given [`Data`] to the given [`Corpus`]
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    /// [`Data`]: crate::input::Data
    ///
    /// # Errors
    ///
    /// If the `corpus_name` is not found, a [`FeroxFuzzError`] is returned.
    #[instrument(skip(self, data), level = "trace")]
    pub fn add_data_to_corpus(&self, corpus_name: &str, data: Data) -> Result<(), FeroxFuzzError> {
        let corpus = self.corpus_by_name(corpus_name)?;

        if let Ok(mut guard) = corpus.write() {
            guard.add(data);
        }

        Ok(())
    }

    /// add given [`Request`]'s fuzzable [`Data`] fields to the given [`Corpus`]
    ///
    /// [`Corpus`]: crate::corpora::Corpus
    /// [`Data`]: crate::input::Data
    /// [`Request`]: crate::requests::Request
    ///
    /// # Errors
    ///
    /// If the `corpus_name` is not found, a [`FeroxFuzzError`] is returned.
    #[instrument(skip(self, request), level = "trace")]
    #[allow(clippy::too_many_lines)]
    pub fn add_request_fields_to_corpus(
        &self,
        corpus_name: &str,
        request: &Request,
    ) -> Result<(), FeroxFuzzError> {
        let corpus = self.corpus_by_name(corpus_name)?;

        if let Ok(mut guard) = corpus.write() {
            // unlocked the corpus, so we can now add the data

            if request.scheme().is_fuzzable() {
                guard.add(request.scheme().clone());

                self.notify_listeners(
                    request,
                    corpus_name.to_string(),
                    "scheme",
                    request.scheme().clone(),
                );
            }

            if let Some(username) = request.username() {
                if username.is_fuzzable() {
                    guard.add(username.clone());

                    self.notify_listeners(
                        request,
                        corpus_name.to_string(),
                        "username",
                        username.clone(),
                    );
                }
            }

            if let Some(password) = request.password() {
                if password.is_fuzzable() {
                    guard.add(password.clone());

                    self.notify_listeners(
                        request,
                        corpus_name.to_string(),
                        "password",
                        password.clone(),
                    );
                }
            }

            if let Some(host) = request.host() {
                if host.is_fuzzable() {
                    guard.add(host.clone());

                    self.notify_listeners(request, corpus_name.to_string(), "host", host.clone());
                }
            }

            if let Some(port) = request.port() {
                if port.is_fuzzable() {
                    guard.add(port.clone());

                    self.notify_listeners(request, corpus_name.to_string(), "port", port.clone());
                }
            }

            if request.path().is_fuzzable() {
                guard.add(request.path().clone());

                self.notify_listeners(
                    request,
                    corpus_name.to_string(),
                    "path",
                    request.path().clone(),
                );
            }

            if let Some(fragment) = request.fragment() {
                if fragment.is_fuzzable() {
                    guard.add(fragment.clone());

                    self.notify_listeners(
                        request,
                        corpus_name.to_string(),
                        "fragment",
                        fragment.clone(),
                    );
                }
            }

            if request.method().is_fuzzable() {
                guard.add(request.method().clone());

                self.notify_listeners(
                    request,
                    corpus_name.to_string(),
                    "method",
                    request.method().clone(),
                );
            }

            if let Some(body) = request.body() {
                if body.is_fuzzable() {
                    guard.add(body.clone());

                    self.notify_listeners(request, corpus_name.to_string(), "body", body.clone());
                }
            }

            if let Some(headers) = request.headers() {
                for (key, value) in headers {
                    if key.is_fuzzable() {
                        guard.add(key.clone());

                        self.notify_listeners(
                            request,
                            corpus_name.to_string(),
                            "header",
                            Data::Fuzzable(format!("{key}: {value}").into()),
                        );
                    }
                    if value.is_fuzzable() {
                        guard.add(value.clone());

                        self.notify_listeners(
                            request,
                            corpus_name.to_string(),
                            "header",
                            Data::Fuzzable(format!("{key}: {value}").into()),
                        );
                    }
                }
            }

            if let Some(params) = request.params() {
                for (key, value) in params {
                    if key.is_fuzzable() {
                        guard.add(key.clone());

                        self.notify_listeners(
                            request,
                            corpus_name.to_string(),
                            "parameter",
                            Data::Fuzzable(format!("{key}={value}").into()),
                        );
                    }
                    if value.is_fuzzable() {
                        guard.add(value.clone());

                        self.notify_listeners(
                            request,
                            corpus_name.to_string(),
                            "parameter",
                            Data::Fuzzable(format!("{key}={value}").into()),
                        );
                    }
                }
            }

            if let Some(user_agent) = request.user_agent() {
                if user_agent.is_fuzzable() {
                    guard.add(user_agent.clone());

                    self.notify_listeners(
                        request,
                        corpus_name.to_string(),
                        "user-agent",
                        user_agent.clone(),
                    );
                }
            }

            if request.version().is_fuzzable() {
                guard.add(request.version().clone());

                self.notify_listeners(
                    request,
                    corpus_name.to_string(),
                    "version",
                    request.version().clone(),
                );
            }
        }

        Ok(())
    }

    /// get the [`MetadataMap`]
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

    /// determine if the given key is in the [`MetadataMap`]
    #[must_use]
    pub fn has_metadata(&self, name: &str) -> bool {
        self.metadata
            .read()
            .is_ok_and(|guard| guard.contains_key(name))
    }

    /// add an implementor of [`Metadata`] to the `[MetadataMap]`
    #[must_use]
    pub fn events(&self) -> Arc<RwLock<Publisher>> {
        self.publisher.clone()
    }
}

impl Len for Arc<RwLock<CorpusType>> {
    fn len(&self) -> usize {
        self.read().map_or(0, |corpus| corpus.len())
    }
}

impl Display for SharedState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "SharedState::{{")?;
        writeln!(f, "  Seed={}", self.seed)?;
        writeln!(f, "  Rng={:?}", self.rng)?;

        for (key, corpus) in &*self.corpora {
            if let Ok(guard) = corpus.read() {
                writeln!(f, "  Corpus[{key}]={guard},")?;
            }
        }

        if let Ok(guard) = self.stats().read() {
            writeln!(f, "  Statistics={guard}")?;
        }

        if let Ok(guard) = self.metadata().read() {
            #[allow(clippy::significant_drop_in_scrutinee)] // doesn't appear to be an accurate lint
            for (key, value) in &*guard {
                writeln!(f, "  Metadata[{key}]={value:?}")?;
            }
        }

        writeln!(f, "}}")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpora::RangeCorpus;

    #[test]
    fn default_state_can_add_corpus_after_creation() {
        let mut state = SharedState::default();

        assert_eq!(state.corpora().len(), 0);
        assert_eq!(state.corpus_indices().len(), 0);

        state.add_corpus(RangeCorpus::new().name("corpus").stop(10).build().unwrap());

        assert_eq!(state.corpora().len(), 1);
        assert_eq!(state.corpus_indices().len(), 1);
    }
}
