//! actions taken after all other processing is complete
#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize
use crate::actions::Action;
use crate::observers::Observers;
use crate::requests::Request;
use crate::responses::Response;
use crate::state::SharedState;
use crate::ProcessorsList;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::request::RequestProcessor;
pub use self::response::ResponseProcessor;
pub use self::statistics::StatisticsProcessor;
mod request;
mod response;
mod statistics;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::client::HttpClient;
    }
}

/// Used to specify when an implementor of `Processor` should execute its hooks
#[derive(Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Ordering {
    /// only call [`ProcessorHooks::pre_send_hook`]
    PreSend,

    /// only call [`ProcessorHooks::post_send_hook`]
    PostSend,

    /// call both [`ProcessorHooks::pre_send_hook`] and [`ProcessorHooks::post_send_hook`]
    #[default]
    PreAndPostSend,
}

/// marker trait; post-processors are used to perform actions after observations
/// are made and actions are taken. They can be thought of a 'final action' that
/// the fuzzer should perform, i.e. logging/printing etc...
pub trait Processor {}

/// defines the hooks that are executed for the purpose of processing
/// requests/responses/fuzzer state either before or after a request
/// has been sent.
///
/// expected order of operations:
/// - `mutators.call_mutate_hooks`
/// - `observers.call_pre_send_hooks`
/// - `deciders.call_pre_send_hooks`
/// - `processors.call_pre_send_hooks`
///
/// - `response = client.send(request)`
///
/// - `observers.call_post_send_hooks`
/// - `deciders.call_post_send_hooks`
/// - `processors.call_post_send_hooks`
pub trait ProcessorHooks {
    /// called before an [`HttpClient`] sends a [`Request`]
    fn pre_send_hook(
        &mut self,
        _state: &SharedState,
        _request: &mut Request,
        _action: Option<&Action>,
    ) {
    }

    /// called after an [`HttpClient`] receives a [`Response`]
    fn post_send_hook<O, R>(
        &mut self,
        _state: &SharedState,
        _observers: &O,
        _action: Option<&Action>,
    ) where
        O: Observers<R>,
        R: Response,
    {
    }
}

/// marker trait for a collection of implementors of [`ProcessorHooks`]
///
/// recursively calls [`ProcessorHooks::pre_send_hook`] or [`ProcessorHooks::post_send_hook`]
/// as appropriate.
pub trait Processors {
    /// called before an [`HttpClient`] sends a [`Request`]
    ///
    /// recursively calls [`ProcessorHooks::pre_send_hook`]
    fn call_pre_send_hooks(
        &mut self,
        _state: &SharedState,
        _request: &mut Request,
        _action: Option<&Action>,
    ) {
    }

    /// called after an [`HttpClient`] receives a [`Response`]
    ///
    /// recursively calls [`ProcessorHooks::post_send_hook`]
    fn call_post_send_hooks<O, R>(
        &mut self,
        _state: &SharedState,
        _observers: &O,
        _action: Option<&Action>,
    ) where
        O: Observers<R>,
        R: Response,
    {
    }
}

/// implement trait for an empty tuple, defining the exit condition for the tuple list
///
/// an empty impl allows the default empty hooks to be called
///
/// in this case, there's no need to override
impl Processors for () {}

/// recursive trait method, calls pre/post hooks on the current
/// item, then the following item until the empty tuple is reached
impl<Head, Tail> Processors for (Head, Tail)
where
    Head: ProcessorHooks,
    Tail: Processors + ProcessorsList,
{
    fn call_pre_send_hooks(
        &mut self,
        state: &SharedState,
        request: &mut Request,
        action: Option<&Action>,
    ) {
        self.0.pre_send_hook(state, request, action);
        self.1.call_pre_send_hooks(state, request, action);
    }

    fn call_post_send_hooks<O, R>(
        &mut self,
        state: &SharedState,
        observers: &O,
        action: Option<&Action>,
    ) where
        O: Observers<R>,
        R: Response,
    {
        self.0.post_send_hook(state, observers, action);
        self.1.call_post_send_hooks(state, observers, action);
    }
}
