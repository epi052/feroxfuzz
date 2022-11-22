//! [`Corpus`] based iterators of different flavors
//!
//! [`Corpus`]: crate::corpora::Corpus
use crate::actions::Action;
use crate::deciders::LogicOperation;
use crate::error::FeroxFuzzError;
use crate::events::{EventPublisher, FuzzForever, FuzzNTimes, StopFuzzing};
use crate::state::SharedState;

use async_trait::async_trait;
use cfg_if::cfg_if;
use tracing::instrument;

cfg_if! {
    if #[cfg(feature = "async")] {
        #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
        mod async_fuzzer;
        pub use async_fuzzer::AsyncFuzzer;
    }
}
cfg_if! {
    if #[cfg(feature = "blocking")] {
        #[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
        mod blocking_fuzzer;
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
    fn pre_send_logic(&self) -> Option<LogicOperation>;

    /// return the [`LogicOperation`] that joins [`Decider`]s while using
    /// a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn post_send_logic(&self) -> Option<LogicOperation>;

    /// change the default [`LogicOperation`] that joins [`Decider`]s while using
    /// a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn set_pre_send_logic(&mut self, logic_operation: LogicOperation);

    /// change the default [`LogicOperation`] that joins [`Decider`]s while using
    /// a [`Fuzzer`]
    ///
    /// [`Decider`]: crate::deciders::Decider
    fn set_post_send_logic(&mut self, logic_operation: LogicOperation);
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
                state.events().notify(&StopFuzzing);
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
                state.events().notify(&StopFuzzing);
                return Ok(());
            }
        }

        Ok(())
    }
}
