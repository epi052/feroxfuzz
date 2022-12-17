//! [`Corpus`] based iterators of different flavors
//!
//! [`Corpus`]: crate::corpora::Corpus
use std::fmt::Debug;

use crate::actions::Action;
use crate::deciders::LogicOperation;
use crate::error::FeroxFuzzError;
use crate::events::{EventPublisher, FuzzForever, FuzzNTimes};
use crate::state::SharedState;

use async_trait::async_trait;
use cfg_if::cfg_if;
use tracing::instrument;

cfg_if! {
    if #[cfg(feature = "async")] {
        #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
        mod async_fuzzer;
        mod async_builder;
        pub use async_builder::AsyncFuzzerBuilder;
        pub use async_fuzzer::AsyncFuzzer;
    }
}
cfg_if! {
    if #[cfg(feature = "blocking")] {
        #[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
        mod blocking_fuzzer;
        mod blocking_builder;
        pub use blocking_builder::BlockingFuzzerBuilder;
        pub use blocking_fuzzer::BlockingFuzzer;
    }
}

/// the generic fuzzer trait; simply a marker trait used with [`BlockingFuzzer`] and [`AsyncFuzzer`]
///
/// [`BlockingFuzzer`]: crate::fuzzers::BlockingFuzzer
pub trait Fuzzer {
    /// return the default [`LogicOperation`] that joins [`Decider`]s while using
    /// a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn pre_send_logic(&self) -> LogicOperation;

    /// return the [`LogicOperation`] that joins [`Decider`]s while using
    /// a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn post_send_logic(&self) -> LogicOperation;

    /// return a mutable reference to the [`LogicOperation`] that joins
    /// [`Decider`]s while using a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn pre_send_logic_mut(&mut self) -> &mut LogicOperation;

    /// return a mutable reference to the [`LogicOperation`] that joins
    /// [`Decider`]s while using a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn post_send_logic_mut(&mut self) -> &mut LogicOperation;
}

/// trait representing a fuzzer that operates asynchronously, meaning that it executes
/// multiple fuzzcases at a time
///
/// designed to be used with an async [`HttpClient`]
///
/// [`HttpClient`]: crate::client::HttpClient
#[async_trait]
pub trait AsyncFuzzing: Fuzzer {
    /// fuzz forever
    ///
    /// # Errors
    ///
    /// see [`Fuzzer`]'s Errors section for more details
    async fn fuzz(&mut self, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        state.events().notify(FuzzForever);

        loop {
            if self.fuzz_once(state).await? == Some(Action::StopFuzzing) {
                break Ok(());
            }
        }
    }

    /// fuzz for one cycle, where a cycle is one full iteration of the corpus along
    /// with all fuzzer stages
    ///
    /// # Errors
    ///
    /// implementors of this function may return an error from any of the composable
    /// fuzzer components, as this is the primary driver function of any fuzzer
    async fn fuzz_once(
        &mut self,
        state: &mut SharedState,
    ) -> Result<Option<Action>, FeroxFuzzError>;

    /// fuzz for `n` cycles, where a cycle is one full iteration of the corpus along
    /// with all fuzzer stages
    ///
    /// # Errors
    ///
    /// see [`Fuzzer`]'s Errors section for more details
    #[instrument(skip(self, state), level = "trace")]
    async fn fuzz_n_iterations(
        &mut self,
        num_iterations: usize,
        state: &mut SharedState,
    ) -> Result<(), FeroxFuzzError> {
        state.events().notify(FuzzNTimes {
            iterations: num_iterations,
        });

        for _ in 0..num_iterations {
            if self.fuzz_once(state).await? == Some(Action::StopFuzzing) {
                return Ok(());
            }
        }

        Ok(())
    }
}

/// trait representing a fuzzer that operates in serial, meaning that it executes
/// a single fuzzcase at a time
///
/// designed to be used with a blocking [`HttpClient`]
///
/// [`HttpClient`]: crate::client::HttpClient
pub trait BlockingFuzzing: Fuzzer {
    /// fuzz forever
    ///
    /// # Errors
    ///
    /// see [`Fuzzer`]'s Errors section for more details
    fn fuzz(&mut self, state: &mut SharedState) -> Result<(), FeroxFuzzError> {
        state.events().notify(FuzzForever);

        loop {
            if self.fuzz_once(state)? == Some(Action::StopFuzzing) {
                break Ok(());
            }
        }
    }

    /// fuzz for one cycle, where a cycle is one full iteration of the corpus along
    /// with all fuzzer stages
    ///
    /// # Errors
    ///
    /// implementors of this function may return an error from any of the composable
    /// fuzzer components, as this is the primary driver function of any fuzzer
    fn fuzz_once(&mut self, state: &mut SharedState) -> Result<Option<Action>, FeroxFuzzError>;

    /// fuzz for `n` cycles, where a cycle is one full iteration of the corpus along
    /// with all fuzzer stages
    ///
    /// # Errors
    ///
    /// see [`Fuzzer`]'s Errors section for more details
    #[instrument(skip(self, state), level = "trace")]
    fn fuzz_n_iterations(
        &mut self,
        num_iterations: usize,
        state: &mut SharedState,
    ) -> Result<(), FeroxFuzzError> {
        state.events().notify(FuzzNTimes {
            iterations: num_iterations,
        });

        for _ in 0..num_iterations {
            if self.fuzz_once(state)? == Some(Action::StopFuzzing) {
                return Ok(());
            }
        }

        Ok(())
    }
}

/// a container for the hooks that execute before and after a single loop
/// of the fuzzer
#[derive(Clone)]
pub struct FuzzingLoopHook {
    callback: fn(&mut SharedState),
    called: usize,
}

impl FuzzingLoopHook {
    /// given a callback function, return a [`FuzzingLoopHook`]
    pub fn new(callback: fn(&mut SharedState)) -> Self {
        Self {
            callback,
            called: 0,
        }
    }
}

impl Debug for FuzzingLoopHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuzzingLoopHook")
            .field("called", &self.called)
            .finish()
    }
}

mod typestate {
    // typestate information for the different fuzzer builders; not useful for anything else
    pub trait FuzzerBuildState {}
    pub struct NoClient;
    pub struct NoRequest;
    pub struct NoScheduler;
    pub struct NoMutators;
    pub struct NoObservers;
    pub struct NoProcessors;
    pub struct NoDeciders;
    pub struct NoPreLoopHook;
    pub struct NoPostLoopHook;
    pub struct NoPreSendLogic;
    pub struct NoPostSendLogic;
    pub struct HasClient;
    pub struct HasRequest;
    pub struct HasScheduler;
    pub struct HasMutators;
    pub struct HasObservers;
    pub struct HasProcessors;
    pub struct HasDeciders;
    pub struct HasPreLoopHook;
    pub struct HasPostLoopHook;
    pub struct HasPreSendLogic;
    pub struct HasPostSendLogic;

    impl FuzzerBuildState for NoClient {}
    impl FuzzerBuildState for NoRequest {}
    impl FuzzerBuildState for NoScheduler {}
    impl FuzzerBuildState for NoMutators {}
    impl FuzzerBuildState for NoObservers {}
    impl FuzzerBuildState for NoProcessors {}
    impl FuzzerBuildState for NoDeciders {}
    impl FuzzerBuildState for NoPreLoopHook {}
    impl FuzzerBuildState for NoPostLoopHook {}
    impl FuzzerBuildState for NoPreSendLogic {}
    impl FuzzerBuildState for NoPostSendLogic {}
    impl FuzzerBuildState for HasClient {}
    impl FuzzerBuildState for HasRequest {}
    impl FuzzerBuildState for HasScheduler {}
    impl FuzzerBuildState for HasMutators {}
    impl FuzzerBuildState for HasObservers {}
    impl FuzzerBuildState for HasProcessors {}
    impl FuzzerBuildState for HasDeciders {}
    impl FuzzerBuildState for HasPreLoopHook {}
    impl FuzzerBuildState for HasPostLoopHook {}
    impl FuzzerBuildState for HasPreSendLogic {}
    impl FuzzerBuildState for HasPostSendLogic {}
}
