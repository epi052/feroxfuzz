//! actions taken against [`Data`] that change the underlying bytes in some way
mod afl;
mod havoc;
mod wordlist_token;

use std::sync::{Arc, Once, RwLock};

use crate::error::FeroxFuzzError;
use crate::events::{EventPublisher, Mutation, Publisher};
use crate::input::Data;
use crate::metadata::AsAny;
use crate::requests::{Request, RequestId};
use crate::state::SharedState;
use crate::std_ext::tuple::Named;
use crate::MutatorsList;

pub use self::afl::*;
pub use self::havoc::HavocMutator;
pub use self::wordlist_token::ReplaceKeyword;

use dyn_clone::DynClone;
use tracing::instrument;

static mut HAS_LISTENERS: bool = false;
static INIT: Once = Once::new();

/// caches the answer to whether or not the publisher has any [`Mutation`] listeners
///
/// [`Mutation`]: crate::events::Mutation
fn has_mutation_listeners(publisher: &Arc<RwLock<Publisher>>) -> bool {
    unsafe {
        INIT.call_once(|| {
            HAS_LISTENERS = publisher.has_listeners::<Mutation>();
        });

        HAS_LISTENERS
    }
}

#[inline]
fn notify_listeners(
    publisher: &Arc<RwLock<Publisher>>,
    id: RequestId,
    field: &'static str,
    entry: Data,
) {
    let has_listeners = has_mutation_listeners(publisher);

    if has_listeners {
        publisher.notify(Mutation { id, field, entry });
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
    /// # Note
    ///
    /// It may appear that we can call [`Data::toggle_type`] after performing each field's
    /// mutation, but this is not the case. Consider the following situation:
    ///
    /// - `Request` has a fuzzable `path` field
    /// - The `path` field uses two `ReplaceKeyword` mutators
    /// - The `path` field's initial value is set to `FUZZ.EXT`
    /// - The expectation is that the first mutator will replace `FUZZ` with a value from the
    ///   `words` corpus and the second mutator will replace `EXT` with a value from
    ///   the `extensions` corpus.
    ///
    /// If we were to call [`Data::toggle_type`] after each field's mutation, the `path` field
    /// the `path` field would be mutated to `WORD.EXT` after the first mutator and then
    /// would fail to be mutated by the second mutator because it is no longer fuzzable.
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
            notify_listeners(
                &state.events(),
                request.id,
                "scheme",
                request.scheme.clone(),
            );
        }

        if let Some(username) = request.username.as_mut() {
            if username.is_fuzzable() {
                self.mutate(username, state)?;
                notify_listeners(&state.events(), request.id, "username", username.clone());
            }
        }

        if let Some(password) = request.password.as_mut() {
            if password.is_fuzzable() {
                self.mutate(password, state)?;
                notify_listeners(&state.events(), request.id, "password", password.clone());
            }
        }

        if let Some(host) = request.host.as_mut() {
            if host.is_fuzzable() {
                self.mutate(host, state)?;
                notify_listeners(&state.events(), request.id, "host", host.clone());
            }
        }

        if let Some(port) = request.port.as_mut() {
            if port.is_fuzzable() {
                self.mutate(port, state)?;
                notify_listeners(&state.events(), request.id, "port", port.clone());
            }
        }

        if request.path.is_fuzzable() {
            self.mutate(&mut request.path, state)?;
            notify_listeners(&state.events(), request.id, "path", request.path.clone());
        }

        if let Some(fragment) = request.fragment.as_mut() {
            if fragment.is_fuzzable() {
                self.mutate(fragment, state)?;
                notify_listeners(&state.events(), request.id, "fragment", fragment.clone());
            }
        }

        if request.method.is_fuzzable() {
            self.mutate(&mut request.method, state)?;
            notify_listeners(
                &state.events(),
                request.id,
                "method",
                request.method.clone(),
            );
        }

        if let Some(body) = request.body.as_mut() {
            if body.is_fuzzable() {
                self.mutate(body, state)?;
                notify_listeners(&state.events(), request.id, "body", body.clone());
            }
        }

        if let Some(headers) = request.headers.as_mut() {
            for (key, value) in headers.iter_mut() {
                if key.is_fuzzable() {
                    self.mutate(key, state)?;
                    notify_listeners(
                        &state.events(),
                        request.id,
                        "header",
                        Data::Fuzzable(format!("{}: {}", key, value).into()),
                    );
                }

                if value.is_fuzzable() {
                    self.mutate(value, state)?;
                    notify_listeners(
                        &state.events(),
                        request.id,
                        "header",
                        Data::Fuzzable(format!("{}: {}", key, value).into()),
                    );
                }
            }
        }

        if let Some(params) = request.params.as_mut() {
            for (key, value) in params.iter_mut() {
                if key.is_fuzzable() {
                    self.mutate(key, state)?;
                    notify_listeners(
                        &state.events(),
                        request.id,
                        "parameter",
                        Data::Fuzzable(format!("{}={}", key, value).into()),
                    );
                }

                if value.is_fuzzable() {
                    self.mutate(value, state)?;
                    notify_listeners(
                        &state.events(),
                        request.id,
                        "parameter",
                        Data::Fuzzable(format!("{}={}", key, value).into()),
                    );
                }
            }
        }

        if let Some(user_agent) = request.user_agent.as_mut() {
            if user_agent.is_fuzzable() {
                self.mutate(user_agent, state)?;
                notify_listeners(
                    &state.events(),
                    request.id,
                    "user-agent",
                    user_agent.clone(),
                );
            }
        }

        if request.version.is_fuzzable() {
            self.mutate(&mut request.version, state)?;
            notify_listeners(
                &state.events(),
                request.id,
                "version",
                request.version.clone(),
            );
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
    /// [`Observers::call_pre_send_hooks`]: crate::observers::Observers::call_pre_send_hooks
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
