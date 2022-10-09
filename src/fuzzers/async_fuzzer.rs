use std::fmt::Debug;
use std::iter::Iterator;
use std::marker::Send;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::future;
use futures::stream;
use futures::StreamExt;
use tokio::task::JoinHandle;
use tracing::{instrument, warn};

use super::{AsyncFuzzing, Fuzzer};
use crate::actions::Action;
use crate::actions::FlowControl;
use crate::client;
use crate::deciders::Deciders;
use crate::error::FeroxFuzzError;
use crate::mutators::Mutators;
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::AsyncResponse;
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::LogicOperation;

/// A fuzzer that sends requests asynchronously
#[derive(Clone, Debug, Default)]
pub struct AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors,
    S: Scheduler,
{
    threads: usize,
    request_id: usize,
    client: A,
    request: Request,
    scheduler: S,
    mutators: M,
    observers: O,
    processors: P,
    deciders: D,
    pre_send_logic: Option<LogicOperation>,
    post_send_logic: Option<LogicOperation>,
}

impl<A, D, M, O, P, S> Fuzzer for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors,
    S: Scheduler,
{
    fn pre_send_logic(&self) -> Option<LogicOperation> {
        self.pre_send_logic
    }

    fn post_send_logic(&self) -> Option<LogicOperation> {
        self.post_send_logic
    }

    fn set_pre_send_logic(&mut self, logic_operation: LogicOperation) {
        let _ = std::mem::replace(&mut self.pre_send_logic, Some(logic_operation));
    }

    fn set_post_send_logic(&mut self, logic_operation: LogicOperation) {
        let _ = std::mem::replace(&mut self.post_send_logic, Some(logic_operation));
    }
}

impl<A, D, M, O, P, S> AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors,
    S: Scheduler,
{
    /// create a new fuzzer that operates asynchronously, meaning that it executes
    /// multiple fuzzcases at a time
    ///
    /// # Note
    ///
    /// the `threads` parameter dictates the maximum number of asynchronous
    /// tasks allowed to be actively executing at any given time
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        threads: usize,
        client: A,
        request: Request,
        scheduler: S,
        mutators: M,
        observers: O,
        processors: P,
        deciders: D,
    ) -> Self {
        Self {
            threads,
            request_id: 0,
            client,
            request,
            scheduler,
            mutators,
            observers,
            processors,
            deciders,
            pre_send_logic: Some(LogicOperation::Or),
            post_send_logic: Some(LogicOperation::Or),
        }
    }

    /// get a mutable reference to the baseline request used for mutation
    pub fn request_mut(&mut self) -> &mut Request {
        &mut self.request
    }
}

#[async_trait]
impl<A, D, M, O, P, S> AsyncFuzzing for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests + Send + Sync + Clone + 'static,
    D: Deciders<O, AsyncResponse> + Send + Clone,
    M: Mutators + Send,
    O: Observers<AsyncResponse> + Send + Clone,
    P: Processors + Send + Clone,
    S: Scheduler + Send + Iterator<Item = ()> + Clone,
    <S as Iterator>::Item: Debug,
{
    #[instrument(skip_all, fields(%self.threads, ?self.post_send_logic, ?self.pre_send_logic) name = "fuzz-loop", level = "trace")]
    async fn fuzz_once(
        &mut self,
        state: &mut SharedState,
    ) -> Result<Option<Action>, FeroxFuzzError> {
        let num_threads = self.threads;
        let post_send_logic = self.post_send_logic().unwrap_or_default();
        let scheduler = self.scheduler.clone();

        // facilitates a way to 'break' out of the iterator
        let mut err = Ok(());
        let mut pre_send_action = None;
        // let mut post_send_action = &mut None;
        let should_quit = Arc::new(AtomicBool::new(false));

        let maybe_action = stream::iter(scheduler)
            .map(
                |_| -> Result<
                    (
                        JoinHandle<Result<AsyncResponse, FeroxFuzzError>>,
                        O,
                        D,
                        P,
                        Request,
                        SharedState,
                        Arc<AtomicBool>,
                    ),
                    FeroxFuzzError,
                > {
                    let mut mutated_request = self
                        .mutators
                        .call_mutate_hooks(state, self.request.clone())?;

                    *mutated_request.id_mut() += self.request_id;

                    self.observers.call_pre_send_hooks(&mutated_request);

                    let decision = self.deciders.call_pre_send_hooks(
                        state,
                        &mutated_request,
                        None,
                        self.pre_send_logic().unwrap_or_default(),
                    );

                    self.processors.call_pre_send_hooks(
                        state,
                        &mut mutated_request,
                        decision.as_ref(),
                    );

                    match decision {
                        Some(Action::Discard) => {
                            self.request_id += 1;
                            return Err(FeroxFuzzError::DiscardedRequest);
                        }
                        Some(Action::AddToCorpus(name, flow_control)) => {
                            // i can't think of too many uses for an AddToCorpus to run on the
                            // pre-send side of things... maybe a 'seen' corpus or something?
                            // leaving it here for now.

                            state.add_to_corpus(name, &mutated_request)?;

                            match flow_control {
                                FlowControl::StopFuzzing => {
                                    pre_send_action = Some(Action::StopFuzzing);
                                    return Err(FeroxFuzzError::FuzzingStopped);
                                }
                                FlowControl::Discard => {
                                    self.request_id += 1;
                                    return Err(FeroxFuzzError::DiscardedRequest);
                                }
                                _ => {}
                            }

                            // ignore when flow control is Keep, same as we do for Action::Keep below
                        }
                        Some(Action::StopFuzzing) => {
                            return Err(FeroxFuzzError::FuzzingStopped);
                        }
                        _ => {
                            // do nothing if it's None or an Action::Keep
                        }
                    }

                    let cloned_client = self.client.clone();
                    let cloned_observers = self.observers.clone();
                    let cloned_deciders = self.deciders.clone();
                    let cloned_processors = self.processors.clone();
                    let cloned_state = state.clone();
                    let cloned_request = mutated_request.clone();
                    let cloned_quit_flag = should_quit.clone();

                    let response_handle = tokio::spawn(async move {
                        let result = cloned_client.send(mutated_request).await?;
                        Ok(result)
                    });

                    self.request_id += 1;

                    Ok((
                        response_handle,
                        cloned_observers,
                        cloned_deciders,
                        cloned_processors,
                        cloned_request,
                        cloned_state,
                        cloned_quit_flag,
                    ))
                },
            ).scan(&mut err, |err, result| {
                // println!("post send action: {:?}", post_send_action);
                if should_quit.load(Ordering::Relaxed) {
                    // this check accounts for us setting the action to StopFuzzing in the PostSend phase
                    **err = Err(FeroxFuzzError::FuzzingStopped);
                    println!("[REAL3] Stopping fuzzing due to FlowControl::StopFuzzing");
                    return future::ready(None);
                }

                match result {
                    Ok((response_handle, observers, deciders, processors, request, state, quit_flag)) => {
                        future::ready(Some(Ok((response_handle, observers, deciders, processors, request, state, quit_flag))))
                    }
                    Err(e) => {
                        if matches!(e, FeroxFuzzError::DiscardedRequest) {
                            future::ready(Some(Err(e)))
                        } else {
                            // this is the check that comes from PreSend
                            **err = Err(FeroxFuzzError::FuzzingStopped);
                            future::ready(None)
                        }
                    }
                }
            })
            .for_each_concurrent(num_threads, |result|
                async move {
                // the is_err -> return paradigm below isn't necessarily idiomatic rust, however, i didn't like the
                // heavily indented match -> match -> if let Ok ..., so to keep the code more left-aligned, i
                // chose to write it the way you see here

                if result.is_err() {
                    // as of right now, the only possible error states the .map iterator above can get into is
                    // when a mutator fails for w/e random reason and when a Action::Discard is encountered; in
                    // either event, the request was never sent, so we can't reasonably continue

                    // failed mutation errors are logged at the error point, not here
                    return;
                }

                // result cannot be Err after this point, so is safe to unwrap
                let (resp, mut c_observers, mut c_deciders, mut c_processors, c_request, c_state, c_should_quit) =
                    result.unwrap();
                
                if c_should_quit.load(Ordering::Relaxed) {
                    return;
                }

                // await the actual response, which is a double-nested Result
                // Result<Result<AsyncResponse, FeroxFuzzError>, tokio::task::JoinError>
                let response = resp.await;

                if response.is_err() {
                    // tokio::task::JoinError -- task failed to execute to completion
                    // could be a cancelled task, or one that panicked for w/e reason
                    warn!("Task failed to execute to completion: {:?}", response.err());
                    return;
                }

                // response cannot be Err after this point, so is safe to unwrap and get the
                // nested Result<AsyncResponse, FeroxFuzzError>
                let response = response.unwrap();

                if let Err(error) = response {
                    // feroxfuzz::client::Client::send returned an error, which is a client error
                    // that means we need to update the statistics and then continue
                    c_state.update_from_error(&error).unwrap_or_default();

                    warn!(%error, "response errored out and will not continue through the fuzz loop");
                    return;
                }

                // response cannot be Err after this point, so is safe to unwrap
                c_observers.call_post_send_hooks(response.unwrap());

                if c_state.update(&c_observers).is_err() {
                    // could not update the state via the observers; cannot reliably make
                    // decisions or perform actions on this response as a result and must
                    // skip any post processing actions
                    warn!("Could not update state via observers; skipping Deciders and Processors");
                    return;
                }

                let decision =
                    c_deciders.call_post_send_hooks(&c_state, &c_observers, None, post_send_logic);

                c_processors.call_post_send_hooks(&c_state, &c_observers, decision.as_ref());

                match decision {
                    Some(Action::AddToCorpus(name, flow_control)) => {
                        // if we've reached this point, flow control doesn't matter anymore; the
                        // only thing we need to check at this point is if we need to alter the
                        // corpus

                        if let Err(err) = c_state.add_to_corpus(name, &c_request) {
                            warn!("Could not add {:?} to corpus[{name}]: {:?}", c_request, err);
                        }

                        if matches!(flow_control, FlowControl::StopFuzzing) {
                            c_should_quit.store(true, Ordering::Relaxed);
                        }    
                    }
                    Some(Action::StopFuzzing) => {
                        c_should_quit.store(true, Ordering::Relaxed);
                    }    
                    _ => {}

                }
        })
            .await;

        println!("Fuzzing complete: {:?}", maybe_action);

        if let Err(FeroxFuzzError::FuzzingStopped) = err {
            return Ok(Some(Action::StopFuzzing));
        }

        // in case we're fuzzing more than once, reset the scheduler
        self.scheduler.reset();

        Ok(None) // no action taken
    }
}
