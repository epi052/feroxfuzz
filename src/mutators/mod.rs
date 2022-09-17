//! actions taken against [`Data`] that change the underlying bytes in some way
mod afl;
mod havoc;
mod wordlist_token;

use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::metadata::AsAny;
use crate::requests::Request;
use crate::state::SharedState;
use crate::std_ext::tuple::Named;
use crate::MutatorsList;

pub use self::afl::*;
pub use self::havoc::HavocMutator;
pub use self::wordlist_token::ReplaceKeyword;

use cfg_if::cfg_if;
use dyn_clone::DynClone;
use tracing::instrument;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::observers::Observers;
    }
}

/// A trait to perform some type of mutation of the given fuzzable [`Data`]
pub trait Mutator: DynClone + AsAny + Named + Send + Sync {
    /// given the fuzzer's current [`SharedState`], mutate the given [`Data`] input
    ///
    /// # Errors
    ///
    /// implementors may return an error if the mutation fails
    fn mutate(&mut self, input: &mut Data, state: &mut SharedState) -> Result<(), FeroxFuzzError>;

    /// given a [`Request`] check all of its fields for [`Data::Fuzzable`] variants and
    /// perform mutations as necessary
    ///
    /// # Errors
    ///
    /// returns an error if a mutation fails
    #[instrument(skip_all, level = "trace")]
    fn mutate_fields(
        &mut self,
        state: &mut SharedState,
        mut request: Request,
    ) -> Result<Request, FeroxFuzzError> {
        if request.scheme.is_fuzzable() {
            self.mutate(&mut request.scheme, state)?;
        }

        if let Some(username) = request.username.as_mut() {
            if username.is_fuzzable() {
                self.mutate(username, state)?;
            }
        }

        if let Some(password) = request.password.as_mut() {
            if password.is_fuzzable() {
                self.mutate(password, state)?;
            }
        }

        if let Some(host) = request.host.as_mut() {
            if host.is_fuzzable() {
                self.mutate(host, state)?;
            }
        }

        if let Some(port) = request.port.as_mut() {
            if port.is_fuzzable() {
                self.mutate(port, state)?;
            }
        }

        if request.path.is_fuzzable() {
            self.mutate(&mut request.path, state)?;
        }

        if let Some(fragment) = request.fragment.as_mut() {
            if fragment.is_fuzzable() {
                self.mutate(fragment, state)?;
            }
        }

        if request.method.is_fuzzable() {
            self.mutate(&mut request.method, state)?;
        }

        if let Some(body) = request.body.as_mut() {
            if body.is_fuzzable() {
                self.mutate(body, state)?;
            }
        }

        if let Some(headers) = request.headers.as_mut() {
            for (key, value) in headers.iter_mut() {
                if key.is_fuzzable() {
                    self.mutate(key, state)?;
                }

                if value.is_fuzzable() {
                    self.mutate(value, state)?;
                }
            }
        }

        if let Some(params) = request.params.as_mut() {
            for (key, value) in params.iter_mut() {
                if key.is_fuzzable() {
                    self.mutate(key, state)?;
                }

                if value.is_fuzzable() {
                    self.mutate(value, state)?;
                }
            }
        }

        if let Some(user_agent) = request.user_agent.as_mut() {
            if user_agent.is_fuzzable() {
                self.mutate(user_agent, state)?;
            }
        }

        if request.version.is_fuzzable() {
            self.mutate(&mut request.version, state)?;
        }

        Ok(request)
    }
}

/// marker trait for a collection of implementors of [`Mutator`]
///
/// recursively calls [`Mutator::mutate`] on each member of the collection
pub trait Mutators {
    /// should be called before [`Observers::call_pre_send_hooks`] so that
    /// observations are made against the mutated request to be sent, instead
    /// of the un-mutated base request
    ///
    /// recursively calls [`Mutator::mutate`]
    ///
    /// # Errors
    ///
    /// if one of the [`Mutator::mutate`] calls fails, it will bubble up here
    fn call_mutate_hooks(
        &mut self,
        state: &mut SharedState,
        request: Request,
    ) -> Result<Request, FeroxFuzzError>;
}

impl Mutators for () {
    /// end recursive calls to `mutate_fields` on all [`Mutators`]
    fn call_mutate_hooks(
        &mut self,
        _state: &mut SharedState,
        request: Request,
    ) -> Result<Request, FeroxFuzzError> {
        Ok(request)
    }
}

impl<Head, Tail> Mutators for (Head, Tail)
where
    Head: Mutator,
    Tail: Mutators + MutatorsList,
{
    /// recursively call `mutate_fields` on all [`Mutators`], which in turn calls `mutate`
    fn call_mutate_hooks(
        &mut self,
        state: &mut SharedState,
        request: Request,
    ) -> Result<Request, FeroxFuzzError> {
        let mutated_request = self.0.mutate_fields(state, request)?;
        self.1.call_mutate_hooks(state, mutated_request)
    }
}

impl Clone for Box<dyn Mutator> {
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}
