// ignore clippy's "docs for function which may panic missing `# Panics` section"
// since the unwraps are safe due to typestate
#![allow(clippy::missing_panics_doc)]
// need complex types to express the typestate
#![allow(clippy::type_complexity)]
// clippy complains of missing const, but we can't use const because of the typestate
// needing to run the destructor of self as it moves through the states (which
// isn't possible with const)
#![allow(clippy::missing_const_for_fn)]
use std::marker::PhantomData;

#[allow(clippy::wildcard_imports)]
use super::typestate::*;
use super::{BlockingFuzzer, FuzzingLoopHook};
use crate::client;
use crate::deciders::Deciders;
use crate::mutators::Mutators;
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::BlockingResponse;
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::LogicOperation;

// CS - client state
// RS - request state
// SS - scheduler state
// MS - mutator state
// OS - observer state
// PS - processor state
// DS - decider state
// PreSndLgcS - pre-send logic state
// PostSndLgcS - post-send logic state
// PreLpHkS - pre-loop hook state
// PostLpHkS - post-loop hook state
/// create a new [`BlockingFuzzerBuilder`] that, when finalized with [`BlockingFuzzerBuilder::build`],
/// will create an [`BlockingFuzzer`]
///
/// mandatory build methods:
/// - [`BlockingFuzzerBuilder::client`]
/// - [`BlockingFuzzerBuilder::request`]
/// - [`BlockingFuzzerBuilder::scheduler`]
///
/// optional build methods:
/// - [`BlockingFuzzerBuilder::mutators`]
/// - [`BlockingFuzzerBuilder::observers`]
/// - [`BlockingFuzzerBuilder::processors`]
/// - [`BlockingFuzzerBuilder::deciders`]
/// - [`BlockingFuzzerBuilder::pre_send_logic`]
/// - [`BlockingFuzzerBuilder::post_send_logic`]
/// - [`BlockingFuzzerBuilder::pre_loop_hook`]
/// - [`BlockingFuzzerBuilder::post_loop_hook`]
pub struct BlockingFuzzerBuilder<
    CS,
    RS,
    SS,
    MS,
    OS,
    PS,
    DS,
    PreSndLgcS,
    PostSndLgcS,
    PreLpHkS,
    PostLpHkS,
    A,
    D,
    M,
    O,
    P,
    S,
> where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    request_id: usize,
    client: Option<A>,
    request: Option<Request>,
    scheduler: Option<S>,
    mutators: Option<M>,
    observers: Option<O>,
    processors: Option<P>,
    deciders: Option<D>,
    pre_send_logic: Option<LogicOperation>,
    post_send_logic: Option<LogicOperation>,
    pre_loop_hook: Option<FuzzingLoopHook>,
    post_loop_hook: Option<FuzzingLoopHook>,

    _client_state: PhantomData<CS>,
    _request_state: PhantomData<RS>,
    _scheduler_state: PhantomData<SS>,
    _mutator_state: PhantomData<MS>,
    _observer_state: PhantomData<OS>,
    _processor_state: PhantomData<PS>,
    _decider_state: PhantomData<DS>,
    _pre_loop_logic_state: PhantomData<PreSndLgcS>,
    _post_loop_logic_state: PhantomData<PostSndLgcS>,
    _pre_loop_hook_state: PhantomData<PreLpHkS>,
    _post_loop_hook_state: PhantomData<PostLpHkS>,
}

impl<A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        NoClient,
        NoRequest,
        NoScheduler,
        NoMutators,
        NoObservers,
        NoProcessors,
        NoDeciders,
        NoPreSendLogic,
        NoPostSendLogic,
        NoPreLoopHook,
        NoPostLoopHook,
        A,
        D,
        M,
        O,
        P,
        S,
    >
{
    /// given the initial [`RequestId`] value, create a new [`BlockingFuzzerBuilder`]
    /// that, when finalized with [`BlockingFuzzerBuilder::build`], will create
    /// a [`BlockingFuzzer`]
    ///
    /// [`RequestId`]: crate::requests::RequestId
    /// [`BlockingFuzzerBuilder::build`]: BlockingFuzzerBuilder::build
    /// [`BlockingFuzzer`]: crate::fuzzers::BlockingFuzzer
    #[must_use]
    pub fn new(request_id: usize) -> Self {
        Self {
            request_id,
            client: None,
            request: None,
            scheduler: None,
            mutators: None,
            observers: None,
            processors: None,
            deciders: None,
            pre_send_logic: None,
            post_send_logic: None,
            pre_loop_hook: None,
            post_loop_hook: None,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<RS, SS, MS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        NoClient,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`BlockingClient`] to be used by the [`BlockingFuzzer`] (mandatory)
    ///
    /// [`BlockingClient`]: crate::client::BlockingClient
    pub fn client(
        self,
        client: A,
    ) -> BlockingFuzzerBuilder<
        HasClient,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: Some(client),
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, SS, MS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        NoRequest,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Request`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn request(
        self,
        request: Request,
    ) -> BlockingFuzzerBuilder<
        CS,
        HasRequest,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: Some(request),
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, MS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        NoScheduler,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Scheduler`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn scheduler(
        self,
        scheduler: S,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        HasScheduler,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: Some(scheduler),
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        NoMutators,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Mutators`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn mutators(
        self,
        mutators: M,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        HasMutators,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: Some(mutators),
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        NoObservers,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Observers`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn observers(
        self,
        observers: O,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        HasObservers,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: Some(observers),
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        NoProcessors,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Processors`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn processors(
        self,
        processors: P,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        HasProcessors,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: Some(processors),
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, PS, PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the [`Deciders`] to be used by the [`BlockingFuzzer`] (mandatory)
    pub fn deciders(
        self,
        deciders: D,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: Some(deciders),
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, PS, DS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        NoPreSendLogic,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the pre-send [`LogicOperation`] to be used by the [`BlockingFuzzer`] (optional)
    pub fn pre_send_logic(
        self,
        logic_operation: LogicOperation,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        HasPreSendLogic,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: Some(logic_operation),
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, PS, DS, PreSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        NoPostSendLogic,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the post-send [`LogicOperation`] to be used by the [`BlockingFuzzer`] (optional)
    pub fn post_send_logic(
        self,
        logic_operation: LogicOperation,
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        HasPostSendLogic,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: Some(logic_operation),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        NoPreLoopHook,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
{
    /// set the pre-fuzzing hook to be used by the [`BlockingFuzzer`] (optional)
    ///
    /// this hook is called before the fuzzing loop starts
    ///
    /// - `Fuzzer::fuzz`: called every time the loop calls `fuzz_once`, until the fuzzer stops  
    /// - `Fuzzer::fuzz_n_iterations`: called n times, each time the loop calls `fuzz_once`
    /// - `Fuzzer::fuzz_once`: called once, at the top of the `fuzz_once` function
    pub fn pre_loop_hook(
        self,
        callback: fn(&mut SharedState),
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        HasPreLoopHook,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: Some(FuzzingLoopHook::new(callback)),
            post_loop_hook: self.post_loop_hook,

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

impl<CS, RS, SS, MS, OS, PS, DS, PreSndLgcS, PostSndLgcS, PreLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        NoPostLoopHook,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    CS: FuzzerBuildState,
    RS: FuzzerBuildState,
    SS: FuzzerBuildState,
    MS: FuzzerBuildState,
    OS: FuzzerBuildState,
    PS: FuzzerBuildState,
    DS: FuzzerBuildState,
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
{
    /// set the post-fuzzing hook to be used by the [`BlockingFuzzer`] (optional)
    ///
    /// this hook is called after the fuzzing loop completes a single iteration over the corpus
    ///
    /// - `Fuzzer::fuzz`: called every time the loop calls `fuzz_once`, until the fuzzer stops  
    /// - `Fuzzer::fuzz_n_iterations`: called n times, each time the loop calls `fuzz_once`
    /// - `Fuzzer::fuzz_once`: called once, at the top of the `fuzz_once` function
    pub fn post_loop_hook(
        self,
        callback: fn(&mut SharedState),
    ) -> BlockingFuzzerBuilder<
        CS,
        RS,
        SS,
        MS,
        OS,
        PS,
        DS,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        HasPostLoopHook,
        A,
        D,
        M,
        O,
        P,
        S,
    > {
        BlockingFuzzerBuilder {
            request_id: self.request_id,
            client: self.client,
            request: self.request,
            scheduler: self.scheduler,
            mutators: self.mutators,
            observers: self.observers,
            processors: self.processors,
            deciders: self.deciders,
            pre_send_logic: self.pre_send_logic,
            post_send_logic: self.post_send_logic,
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: Some(FuzzingLoopHook::new(callback)),

            _client_state: PhantomData,
            _request_state: PhantomData,
            _scheduler_state: PhantomData,
            _mutator_state: PhantomData,
            _observer_state: PhantomData,
            _processor_state: PhantomData,
            _decider_state: PhantomData,
            _pre_loop_logic_state: PhantomData,
            _post_loop_logic_state: PhantomData,
            _pre_loop_hook_state: PhantomData,
            _post_loop_hook_state: PhantomData,
        }
    }
}

// everything below this line is how we make deciders/mutators/observers/processors
// optional
//
// this is due to the fact that we can't have a default value for a generic type
// parameter, so we have to use a concrete type where the generic type parameter
// hasn't been provided
//
// the differences are great enough that a macro would be more confusing than
// helpful, so we just have to write out the code for each type
//
// there are 16 possible combinations of the 4 types, so we have to write out
// 16 different implementations of the builder
//
// thought of like a truth table, the 4 types are the columns and each row
// represents a possible combination of the 4 types
//
// 4 trues and 4 falses
//
// M | O | P | D
// -------------
// T | T | T | T
// F | F | F | F
//
impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        HasObservers,
        HasProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
    P: Processors<O, BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, M, O, P, S> {
        // T | T | T | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,          // from constructor
            client: self.client.unwrap(),         // constrained by type-system to be provided
            request: self.request.unwrap(),       // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(),   // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),     // constrained by type-system to be provided
            observers: self.observers.unwrap(),   // constrained by type-system to be provided
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: self.deciders.unwrap(),     // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        NoObservers,
        NoProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        (),
        (),
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), (), (), (), S> {
        // F | F | F | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: (),
            processors: (),
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

// Single false and 3 trues
//
// M | O | P | D
// -------------
// T | T | T | F
// T | T | F | T
// T | F | T | T
// F | T | T | T
//

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, O, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        HasObservers,
        HasProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        (),
        O,
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    O: Observers<BlockingResponse>,
    P: Processors<O, BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, (), O, P, S> {
        // F | T | T | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,          // from constructor
            client: self.client.unwrap(),         // constrained by type-system to be provided
            request: self.request.unwrap(),       // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(),   // constrained by type-system to be provided
            mutators: (),                         // constrained by type-system to be provided
            observers: self.observers.unwrap(),   // constrained by type-system to be provided
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: self.deciders.unwrap(),     // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        NoObservers,
        HasProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        (),
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<(), BlockingResponse>,
    M: Mutators,
    P: Processors<(), BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, M, (), P, S> {
        BlockingFuzzer {
            // T | F | T | T
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided
            observers: (),
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: self.deciders.unwrap(),     // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, O, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        HasObservers,
        NoProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        O,
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, M, O, (), S> {
        BlockingFuzzer {
            // T | T | F | T
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided
            observers: self.observers.unwrap(), // constrained by type-system to be provided
            processors: (),
            deciders: self.deciders.unwrap(), // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, M, O, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        HasObservers,
        HasProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        M,
        O,
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    M: Mutators,
    O: Observers<BlockingResponse>,
    P: Processors<O, BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), M, O, P, S> {
        BlockingFuzzer {
            // T | T | T | F
            request_id: self.request_id,          // from constructor
            client: self.client.unwrap(),         // constrained by type-system to be provided
            request: self.request.unwrap(),       // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(),   // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),     // constrained by type-system to be provided
            observers: self.observers.unwrap(),   // constrained by type-system to be provided
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}
// Single true and 3 falses
//
// M | O | P | D
// -------------
// T | F | F | F
// F | T | F | F
// F | F | T | F
// F | F | F | T
//

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, M, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        NoObservers,
        NoProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        M,
        (),
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    M: Mutators,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), M, (), (), S> {
        // T | F | F | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided,
            observers: (),
            processors: (),
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, O, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        HasObservers,
        NoProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        (),
        O,
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    O: Observers<BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), (), O, (), S> {
        // F | T | F | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: self.observers.unwrap(), // constrained by type-system to be provided,
            processors: (),
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        NoObservers,
        HasProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        (),
        (),
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    P: Processors<(), BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), (), (), P, S> {
        // F | F | T | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: (),
            processors: self.processors.unwrap(), // constrained by type-system to be provided,
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        NoObservers,
        NoProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        (),
        (),
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<(), BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, (), (), (), S> {
        // F | F | F | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: (),
            processors: (),
            deciders: self.deciders.unwrap(), // constrained by type-system to be provided,
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

// 2 trues and 2 falses
//
// M | O | P | D
// -------------
// T | T | F | F
// T | F | T | F
// T | F | F | T
// F | T | T | F
// F | T | F | T
// F | F | T | T

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, M, O, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        HasObservers,
        NoProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        M,
        O,
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    M: Mutators,
    O: Observers<BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), M, O, (), S> {
        // T | T | F | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided
            observers: self.observers.unwrap(), // constrained by type-system to be provided
            processors: (),
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, M, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        NoObservers,
        HasProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        M,
        (),
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    M: Mutators,
    P: Processors<(), BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), M, (), P, S> {
        // T | F | T | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided
            observers: (),
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, M, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        HasMutators,
        NoObservers,
        NoProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        M,
        (),
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<(), BlockingResponse>,
    M: Mutators,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, M, (), (), S> {
        // T | F | F | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: self.mutators.unwrap(),   // constrained by type-system to be provided
            observers: (),
            processors: (),
            deciders: self.deciders.unwrap(), // constrained by type-system to be provided,
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, O, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        HasObservers,
        HasProcessors,
        NoDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        (),
        (),
        O,
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    O: Observers<BlockingResponse>,
    P: Processors<O, BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, (), (), O, P, S> {
        // F | T | T | F
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: self.observers.unwrap(), // constrained by type-system to be provided
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: (),
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, O, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        HasObservers,
        NoProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        (),
        O,
        (),
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    O: Observers<BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, (), O, (), S> {
        // F | T | F | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: self.observers.unwrap(), // constrained by type-system to be provided
            processors: (),
            deciders: self.deciders.unwrap(), // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

impl<PreSndLgcS, PostSndLgcS, PreLpHkS, PostLpHkS, A, D, P, S>
    BlockingFuzzerBuilder<
        HasClient,
        HasRequest,
        HasScheduler,
        NoMutators,
        NoObservers,
        HasProcessors,
        HasDeciders,
        PreSndLgcS,
        PostSndLgcS,
        PreLpHkS,
        PostLpHkS,
        A,
        D,
        (),
        (),
        P,
        S,
    >
where
    PreSndLgcS: FuzzerBuildState,
    PostSndLgcS: FuzzerBuildState,
    PreLpHkS: FuzzerBuildState,
    PostLpHkS: FuzzerBuildState,
    A: client::BlockingRequests,
    D: Deciders<(), BlockingResponse>,
    P: Processors<(), BlockingResponse>,
    S: Scheduler,
{
    /// finalize and return an [`BlockingFuzzer`]
    pub fn build(self) -> BlockingFuzzer<A, D, (), (), P, S> {
        // F | F | T | T
        BlockingFuzzer {
            // from constructor
            request_id: self.request_id,        // from constructor
            client: self.client.unwrap(),       // constrained by type-system to be provided
            request: self.request.unwrap(),     // constrained by type-system to be provided
            scheduler: self.scheduler.unwrap(), // constrained by type-system to be provided
            mutators: (),
            observers: (),
            processors: self.processors.unwrap(), // constrained by type-system to be provided
            deciders: self.deciders.unwrap(),     // constrained by type-system to be provided
            pre_send_logic: self.pre_send_logic.unwrap_or_default(),
            post_send_logic: self.post_send_logic.unwrap_or_default(),
            pre_loop_hook: self.pre_loop_hook,
            post_loop_hook: self.post_loop_hook,
        }
    }
}

#[cfg(test)]
mod tests {
    //! These tests ensure that the [`BlockingFuzzerBuilder`] can be constructed
    //! and that the [`BlockingFuzzerBuilder::build`] method returns
    //! a [`BlockingFuzzer`] satisfying the truth table below with
    //! respect to the presence of each of the following components:
    //! - mutators
    //! - observers
    //! - processors
    //! - deciders
    use super::*;
    use crate::actions::Action;
    use crate::client::{BlockingClient, HttpClient};
    use crate::corpora::Wordlist;
    use crate::deciders::StatusCodeDecider;
    use crate::mutators::ReplaceKeyword;
    use crate::observers::ResponseObserver;
    use crate::processors::RequestProcessor;
    use crate::schedulers::OrderedScheduler;
    use crate::{build_deciders, build_mutators, build_observers, build_processors};

    /// T | T | T | T
    #[test]
    fn test_blocking_fuzzer_builder_tttt() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// F | F | F | F
    #[test]
    fn test_blocking_fuzzer_builder_ffff() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .build();
    }

    /// F | T | T | T
    #[test]
    fn test_blocking_fuzzer_builder_fttt() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// T | F | T | T
    #[test]
    fn test_blocking_fuzzer_builder_tftt() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// T | T | F | T
    #[test]
    fn test_blocking_fuzzer_builder_ttft() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// T | T | T | F
    #[test]
    fn test_blocking_fuzzer_builder_tttf() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .build();
    }

    /// T | F | F | F
    #[test]
    fn test_blocking_fuzzer_builder_tfff() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .build();
    }

    /// F | T | F | F
    #[test]
    fn test_blocking_fuzzer_builder_ftff() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .build();
    }

    /// F | F | T | F
    #[test]
    fn test_blocking_fuzzer_builder_fftf() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .build();
    }

    /// F | F | F | T
    #[test]
    fn test_blocking_fuzzer_builder_ffft() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// T | T | F | F
    #[test]
    fn test_blocking_fuzzer_builder_ttff() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .build();
    }

    /// T | F | T | F
    #[test]
    fn test_blocking_fuzzer_builder_tftf() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .build();
    }

    /// T | F | F | T
    #[test]
    fn test_blocking_fuzzer_builder_tfft() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let mutator = ReplaceKeyword::new(&"RANGE1", "range1");

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// F | T | T | F
    #[test]
    fn test_blocking_fuzzer_builder_fttf() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .build();
    }

    /// F | T | F | T
    #[test]
    fn test_blocking_fuzzer_builder_ftft() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .observers(build_observers!(ResponseObserver::<BlockingResponse>::new()))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }

    /// F | F | T | T
    #[test]
    fn test_blocking_fuzzer_builder_fftt() {
        let req_client = reqwest::blocking::Client::builder().build().unwrap();
        let client = BlockingClient::with_client(req_client);
        let request = Request::from_url("http://localhost:8000/", None).unwrap();
        let corpus = Wordlist::with_words(["hi"]).name("corpus").build();
        let scheduler = OrderedScheduler::new(SharedState::with_corpus(corpus)).unwrap();

        let _tested = BlockingFuzzer::new()
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .processors(build_processors!(RequestProcessor::new(|_, _, _| {})))
            .deciders(build_deciders!(StatusCodeDecider::new(200, |_, _, _| {
                Action::Discard
            })))
            .build();
    }
}
