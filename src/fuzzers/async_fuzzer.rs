use std::fmt::Debug;
use std::iter::Iterator;
use std::marker::Send;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{instrument, warn};

#[allow(clippy::wildcard_imports)]
use super::typestate::*;
use super::{AsyncFuzzerBuilder, AsyncFuzzing, Fuzzer, FuzzingLoopHook};
use crate::actions::Action;
use crate::actions::FlowControl;
use crate::client;
use crate::corpora::CorpusItemType;
use crate::deciders::Deciders;
use crate::error::FeroxFuzzError;
use crate::events::{
    DiscardedRequest, DiscardedResponse, EventPublisher, FuzzOnce, KeptRequest, KeptResponse,
    StopFuzzing,
};
use crate::mutators::Mutators;
use crate::observers::{Observers, ResponseObserver};
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::{AsyncResponse, Response};
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::LogicOperation;

/// the number of post-processors (i.e. recv side of `flume::mpmc`) to handle
/// the post-send loop logic / execution
///
/// 6 was chosen based on local testing and could be adjusted if needed
///
/// note: if you change this value, you must also change the number of .pop
/// calls that we make on the post-processors vec in the call to
/// `tokio::join` later in this module
const NUM_POST_PROCESSORS: usize = 6;

/// a crude way of passing information from the post-send loops
/// back up to the pre-send loop
///
/// using return values isn't possible because the post-send loops
/// are spawned as background tasks. attempting to use `try_join`
/// doesn't work because the error that is returned is a
/// `tokio::task::JoinError`. We can't trigger an early return
/// from the post-send loop because we don't really own the
/// initial `Result` that is returned from the `tokio::spawn` call
static mut STOP_FUZZING_FLAG: bool = false;

/// A fuzzer that sends requests asynchronously
#[derive(Clone, Debug, Default)]
pub struct AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors<O, AsyncResponse>,
    S: Scheduler,
{
    pub(super) threads: usize,
    pub(super) request_id: usize,
    pub(super) client: A,
    pub(super) request: Request,
    pub(super) scheduler: S,
    pub(super) mutators: M,
    pub(super) observers: O,
    pub(super) processors: P,
    pub(super) deciders: D,
    pub(super) pre_send_logic: LogicOperation,
    pub(super) post_send_logic: LogicOperation,
    pub(super) pre_loop_hook: Option<FuzzingLoopHook>,
    pub(super) post_loop_hook: Option<FuzzingLoopHook>,
}

impl<A, D, M, O, P, S> Fuzzer for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors<O, AsyncResponse>,
    S: Scheduler,
{
    fn pre_send_logic(&self) -> LogicOperation {
        self.pre_send_logic
    }

    fn post_send_logic(&self) -> LogicOperation {
        self.post_send_logic
    }

    fn pre_send_logic_mut(&mut self) -> &mut LogicOperation {
        &mut self.pre_send_logic
    }

    fn post_send_logic_mut(&mut self) -> &mut LogicOperation {
        &mut self.post_send_logic
    }

    fn reset(&mut self) {
        // in case we're fuzzing more than once, reset the scheduler
        self.scheduler.reset();
    }
}

impl<A, D, M, O, P, S> AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests,
    D: Deciders<O, AsyncResponse>,
    M: Mutators,
    O: Observers<AsyncResponse>,
    P: Processors<O, AsyncResponse>,
    S: Scheduler,
{
    /// create a new fuzzer builder that, when finalized with [`AsyncFuzzerBuilder::build`],
    /// operates asynchronously, meaning that it executes multiple fuzzcases at a time
    ///
    /// [`AsyncFuzzerBuilder::build`]: crate::fuzzers::AsyncFuzzerBuilder::build
    ///
    /// # Note
    ///
    /// the `threads` parameter dictates the maximum number of asynchronous
    /// tasks allowed to be actively executing at any given time
    #[allow(clippy::type_complexity)]
    #[allow(clippy::new_ret_no_self)]
    #[must_use]
    pub fn new(
        threads: usize,
    ) -> AsyncFuzzerBuilder<
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
    > {
        let request_id = 0;

        AsyncFuzzerBuilder::new(threads, request_id)
    }

    /// get a mutable reference to the baseline request used for mutation
    pub fn request_mut(&mut self) -> &mut Request {
        &mut self.request
    }

    /// get a mutable reference to the scheduler
    pub fn scheduler_mut(&mut self) -> &mut S {
        &mut self.scheduler
    }

    /// set a function to run before each fuzzing loop
    pub fn set_pre_loop_hook(&mut self, hook: fn(&mut SharedState)) {
        self.pre_loop_hook = Some(FuzzingLoopHook::new(hook));
    }

    /// set a function to run after each fuzzing loop
    pub fn set_post_loop_hook(&mut self, hook: fn(&mut SharedState)) {
        self.post_loop_hook = Some(FuzzingLoopHook::new(hook));
    }
}

#[async_trait]
impl<A, D, M, O, P, S> AsyncFuzzing for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests + Send + Sync + Clone + 'static,
    D: Deciders<O, AsyncResponse> + Send + Clone + 'static,
    M: Mutators + Send,
    O: Observers<AsyncResponse> + Send + Clone + 'static,
    P: Processors<O, AsyncResponse> + Send + Clone + 'static,
    S: Scheduler + Debug + Send,
{
    #[instrument(skip_all, fields(%self.threads, ?self.post_send_logic, ?self.pre_send_logic) name = "fuzz-loop", level = "trace")]
    async fn fuzz_once(
        &mut self,
        state: &mut SharedState,
    ) -> Result<Option<Action>, FeroxFuzzError> {
        if let Some(hook) = &mut self.pre_loop_hook {
            // call the pre-loop hook if it is defined
            (hook.callback)(state);
            hook.called += 1;
        }

        state.events().notify(FuzzOnce {
            threads: self.threads,
            pre_send_logic: self.pre_send_logic(),
            post_send_logic: self.post_send_logic(),
            corpora_length: state.total_corpora_len(),
        });

        // wrap the client in an Arc so that it can be cheaply moved into the async block
        let client = Arc::new(self.client.clone());

        // tokio semaphore to limit the number of concurrent requests
        let semaphore = Arc::new(Semaphore::new(self.threads));

        // in order to process responses as they come in, we need to spawn new tasks
        // that will handle the responses via an mpmc channel. This means that we have
        // two loops going at any given time: one that sends requests/receives responses
        // and one that processes responses. In feroxfuzz terms, the first loop can be
        // thought of as the pre-send loop while the second loop acts as the post-send loop.

        // create an unbounded mpmc channel to send requests to the async block
        let (tx, rx) = flume::unbounded();

        // kick off the response processing threads
        let mut post_processing_handles = Vec::with_capacity(NUM_POST_PROCESSORS);

        for _ in 0..NUM_POST_PROCESSORS {
            // clone the deciders, observers, and processors so that they can be moved into the response
            // processor's async block
            let c_deciders = self.deciders.clone();
            let c_observers = self.observers.clone();
            let c_processors = self.processors.clone();
            let c_logic = self.post_send_logic;
            let c_state = state.clone();
            let c_rx = rx.clone();

            // each spawned post-processor uses the same mpmc recv channel to receive responses
            // from the pre-send loop; changing from mpsc to mpmc dramatically sped up
            // processing time since the pre-send loop could pretty easily overwhelm the
            // post-send loop. as a result, overall scan time was dramatically reduced as well
            // since we could get into situations where all requests/responses were complete
            // but the single consumer was still processing responses
            let handle = tokio::spawn(async move {
                process_responses(
                    c_state,
                    c_deciders,
                    c_observers,
                    c_processors,
                    c_logic,
                    c_rx,
                )
                .await
                .unwrap_or_default();
            });

            post_processing_handles.push(handle);
        }

        // first loop fires off requests and receives the responses
        // those responses are then sent to the second loop via the mpsc channel
        loop {
            let scheduled = Scheduler::next(&mut self.scheduler);

            if matches!(scheduled, Err(FeroxFuzzError::IterationStopped)) {
                // if the scheduler returns an iteration stopped error, we
                // need to stop the fuzzing loop
                break;
            } else if matches!(scheduled, Err(FeroxFuzzError::SkipScheduledItem { .. })) {
                // if the scheduler says we should skip this item, we'll continue to
                // the next item
                continue;
            }

            // the semaphore only has self.threads permits, so this will block
            // until one is available, limiting the number of concurrent requests
            //
            // for the clippy allow: as far as I can tell, this is a false positive since
            // we actually take ownership of the permit in the match arm
            #[allow(clippy::significant_drop_in_scrutinee)]
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(permit) => permit,
                Err(err) => {
                    tracing::error!(
                        "Failed to acquire semaphore permit, skipping RequestId<{}>: {:?}",
                        self.request_id + 1, // +1 because we haven't incremented the request id yet
                        err
                    );

                    // if we couldn't get a permit from the semaphore, we'll skip this request
                    continue;
                }
            };

            if unsafe { STOP_FUZZING_FLAG } {
                // if one of the post-processing tasks set the stop flag, we need to stop
                // here as well. The check is placed here to catch any requests that were
                // previously held by the semaphore but not yet sent
                return Ok(Some(Action::StopFuzzing));
            }

            let mut request = self.request.clone();

            *request.id_mut() += self.request_id;

            let mut mutated_request = self.mutators.call_mutate_hooks(state, request)?;

            self.observers.call_pre_send_hooks(&mutated_request);

            let decision = self.deciders.call_pre_send_hooks(
                state,
                &mutated_request,
                None,
                self.pre_send_logic(),
            );

            self.processors
                .call_pre_send_hooks(state, &mut mutated_request, decision.as_ref());

            if decision.is_some() {
                // if there is an action to take, based off the deciders, then
                // we need to set the action on the request, and then call the
                // state->stats->update method
                mutated_request.set_action(decision.clone());

                // currently, the only stats update this call performs is to
                // update the Action tracker with the request's id, so we
                // can hide it behind the if-let-some
                state.update_from_request(&mutated_request);
            }

            match decision {
                Some(Action::Discard) => {
                    // if the decision is to discard the request, then we need to
                    // increment the request id and notify the event handler
                    // that the request was discarded
                    //
                    // we also need to continue to the next iteration of the loop
                    // so that we don't send the request
                    self.request_id += 1;

                    state.events().notify(DiscardedRequest {
                        id: mutated_request.id(),
                    });

                    continue;
                }
                Some(Action::AddToCorpus(name, corpus_item_type, flow_control)) => {
                    // i can't think of too many uses for an AddToCorpus to run on the
                    // pre-send side of things... maybe a 'seen' corpus or something?
                    // leaving it here for now.
                    match corpus_item_type {
                        CorpusItemType::Request => {
                            // all fuzzable fields of the request are added to the corpus
                            state.add_request_fields_to_corpus(&name, &mutated_request)?;
                        }
                        CorpusItemType::Data(data) => {
                            // the single given Data item is added to the corpus
                            state.add_data_to_corpus(&name, data)?;
                        }
                        CorpusItemType::LotsOfData(data) => {
                            // each item in the given Data vector is added to the corpus
                            for item in data {
                                state.add_data_to_corpus(&name, item)?;
                            }
                        }
                    }

                    match flow_control {
                        FlowControl::StopFuzzing => {
                            tracing::info!(
                                "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                self.request_id
                            );

                            state.events().notify(&StopFuzzing);

                            // bubble the StopFuzzing action up to the caller in case the caller
                            // is fuzz or fuzz_n_iterations, allowing them to break out of their
                            // loops as well
                            return Ok(Some(Action::StopFuzzing));
                        }
                        FlowControl::Discard => {
                            state.events().notify(DiscardedRequest {
                                id: mutated_request.id(),
                            });

                            self.request_id += 1;

                            continue;
                        }
                        FlowControl::Keep => {
                            state.events().notify(KeptRequest {
                                id: mutated_request.id(),
                            });
                        }
                    }
                }
                Some(Action::StopFuzzing) => {
                    tracing::info!(
                        "[ID: {}] stopping fuzzing due to StopFuzzing action",
                        mutated_request.id()
                    );

                    state.events().notify(&StopFuzzing);

                    return Ok(Some(Action::StopFuzzing));
                }
                Some(Action::Keep) => {
                    state.events().notify(KeptRequest {
                        id: mutated_request.id(),
                    });
                }
                None => {} // do nothing
            }

            // we need to clone the Arc-wrapped client here, because the client is moved to the spawned task
            let cloned_client = client.clone();

            // spawn a new task to send the request, and when received, send the response
            // across the mpsc channel to the second/post-send loop
            let sent = tx.send(tokio::spawn(async move {
                // send the request, and await the response
                let result = cloned_client.send(mutated_request).await;

                // release the semaphore permit, now that the request has been sent and is
                // no longer in-flight
                //
                // for reference: the permit is acquired at the top of the loop
                drop(permit);

                result
            }));

            // UnboundedChannel::send can only error if the receiver has called close()
            // on the channel, which we don't do, or the receiver has been dropped.
            //
            // Since we don't call close() on the channel, an error during send must mean
            // that either
            // - None was sent to the receiver
            // - StopFuzzing was returned from a post-send decider
            //
            // Receiving None while this loop is still active is possible because send
            // doesn't block when in an async context, so it's possible for the receiver to
            // receive None before the sender has a chance to send all of the requests.
            //
            // likely this is due in part to the use of the semaphore
            //
            // in any case, to support StopFuzzing behavior, if this particular send is an
            // error, we'll log it and break out of the loop
            if let Err(err) = sent {
                tracing::error!(
                    "Failed to send response to response processing task: {:?}",
                    err
                );
                break;
            }

            self.request_id += 1;
        }

        // now that all requests have been spawned/sent, we can close the tx side of the
        // connection. this will allow the receivers to complete when all of the requests
        // have been processed
        drop(tx);

        // the join! macro here is not driving the spawned tasks, rather it is waiting for
        // the task handles to complete. This is the reason for the use of the
        // STOP_FUZZING_FLAG, since we can't get returned error values early from the spawned
        // tasks
        let (first, second, third, fourth, fifth, sixth) = tokio::join!(
            // note: these unwraps are ok, since the NUM_POST_PROCESSING_TASKS value is a const, without
            // any possibility of user interaction. However, if that value changes, then the
            // number of calls to .pop will need to change to reflect that
            post_processing_handles.pop().unwrap(),
            post_processing_handles.pop().unwrap(),
            post_processing_handles.pop().unwrap(),
            post_processing_handles.pop().unwrap(),
            post_processing_handles.pop().unwrap(),
            post_processing_handles.pop().unwrap(),
        );

        // if any of the tasks failed, log the error and move along, nothing can really be
        // done about it from here
        #[allow(clippy::tuple_array_conversions)] // false positive
        [first, second, third, fourth, fifth, sixth]
            .into_iter()
            .filter_map(|result| match result {
                Ok(()) => None,
                Err(err) => Some(err),
            })
            .for_each(|err| {
                tracing::error!("Failed to join response processing task: {:?}", err);
            });

        if let Some(hook) = &mut self.post_loop_hook {
            // call the post-loop hook if it is defined
            (hook.callback)(state);
            hook.called += 1;
        }

        Ok(None) // no action taken
    }
}

/// The main loop for processing responses
///
/// This loop is responsible for processing responses, and will continue to do
/// so until the `receiver` channel receives `None` from the `fuzz_once` loop.
async fn process_responses<D, O, P>(
    state: SharedState,
    mut deciders: D,
    mut observers: O,
    mut processors: P,
    post_send_logic: LogicOperation,
    receiver: flume::Receiver<JoinHandle<Result<AsyncResponse, FeroxFuzzError>>>,
) -> Result<(), FeroxFuzzError>
where
    D: Deciders<O, AsyncResponse> + Send + Clone,
    O: Observers<AsyncResponse> + Send + Clone,
    P: Processors<O, AsyncResponse> + Send + Clone,
{
    // second loop handles responses
    //
    // outer loop awaits the actual response, which is a double-nested Result
    // Result<Result<AsyncResponse, FeroxFuzzError>, tokio::task::JoinError>
    tracing::debug!("entering the response processing loop...");

    while let Ok(handle) = receiver.recv_async().await {
        if unsafe { STOP_FUZZING_FLAG } {
            // if one task sets the stop fuzzing flag, all other tasks need to
            // act on it as well, so we check for the flag at the top of the loop
            //
            // purposely placing this before the handle.await, so that in the event
            // that the flag is set, while awaiting a given handle, we'll still
            // process that last handle before exiting
            return Ok(());
        }

        let handle = handle.await;

        let Ok(task_result) = handle else {
            // tokio::task::JoinError -- task failed to execute to completion
            // could be a cancelled task, or one that panicked for w/e reason
            //
            // either way, we can't process the response, so we just continue
            continue;
        };

        let Ok(response) = task_result else {
            let error = task_result.err().unwrap();

            // feroxfuzz::client::Client::send returned an error, which is a client error
            // that means we need to update the statistics and then continue
            state.update_from_error(&error).unwrap_or_default();

            warn!(%error, "response errored out and will not continue through the fuzz loop");
            continue;
        };

        observers.call_post_send_hooks(response);

        // at this point, we still need a reference to the request
        //
        // the response observer takes ownership of the response, so we can grab a
        // reference to the response observer and then extract out the request
        // from the observer's reference to the response. this is a rather
        // convoluted way of avoiding an unnecessary clone while not having to
        // rework a bunch of internal implementation details
        let response_observer = observers
            .match_name::<ResponseObserver<AsyncResponse>>("ResponseObserver")
            // reasonable to assume one exists, if not, we can figure it out then
            // if someone comes along with a use-case for not using one, we can
            // figure it out then
            .unwrap();

        let request = response_observer.request();
        let request_id = request.id();

        let decision = deciders.call_post_send_hooks(&state, &observers, None, post_send_logic);

        if state.update(&observers, decision.as_ref()).is_err() {
            // could not update the state via the observers; cannot reliably make
            // decisions or perform actions on this response as a result and must
            // skip any post processing actions
            warn!("Could not update state via observers; skipping Processors");
            continue;
        }

        processors.call_post_send_hooks(&state, &observers, decision.as_ref());

        match decision {
            Some(Action::AddToCorpus(name, corpus_item_type, flow_control)) => {
                match corpus_item_type {
                    CorpusItemType::Request => {
                        if let Err(err) = state.add_request_fields_to_corpus(&name, request) {
                            warn!("Could not add {:?} to corpus[{name}]: {:?}", &request, err);
                        }
                    }
                    CorpusItemType::Data(data) => {
                        if let Err(err) = state.add_data_to_corpus(&name, data) {
                            warn!("Could not add {:?} to corpus[{name}]: {:?}", request, err);
                        }
                    }
                    CorpusItemType::LotsOfData(data) => {
                        for item in data {
                            state.add_data_to_corpus(&name, item)?;
                        }
                    }
                }

                match flow_control {
                    FlowControl::StopFuzzing => {
                        tracing::info!(
                            "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                            request_id
                        );

                        state.events().notify(&StopFuzzing);

                        unsafe {
                            STOP_FUZZING_FLAG = true;
                        }

                        return Err(FeroxFuzzError::FuzzingStopped);
                    }
                    FlowControl::Discard => {
                        state.events().notify(DiscardedResponse { id: request_id });
                    }
                    FlowControl::Keep => {
                        state.events().notify(KeptResponse { id: request_id });
                    }
                }
            }
            Some(Action::StopFuzzing) => {
                tracing::info!(
                    "[ID: {}] stopping fuzzing due to StopFuzzing action",
                    request_id
                );

                state.events().notify(&StopFuzzing);

                unsafe {
                    STOP_FUZZING_FLAG = true;
                }

                return Err(FeroxFuzzError::FuzzingStopped);
            }
            Some(Action::Discard) => {
                state.events().notify(DiscardedResponse { id: request_id });
            }
            Some(Action::Keep) => {
                state.events().notify(KeptResponse { id: request_id });
            }
            None => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AsyncClient;
    use crate::corpora::{RangeCorpus, Wordlist};
    use crate::deciders::{RequestRegexDecider, ResponseRegexDecider};
    use crate::fuzzers::AsyncFuzzer;
    use crate::mutators::ReplaceKeyword;
    use crate::observers::ResponseObserver;
    use crate::prelude::*;
    use crate::requests::ShouldFuzz;
    use crate::responses::AsyncResponse;
    use crate::schedulers::OrderedScheduler;
    use ::regex::Regex;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use reqwest;
    use std::time::Duration;

    /// test that the fuzz loop will stop if the decider returns a StopFuzzing action in
    /// the pre-send phase
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_async_fuzzer_stops_fuzzing_pre_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock = srv.mock(|when, then| {
            // registers hits for 0, 1, 2
            when.method(GET).path_matches(Regex::new("[012]").unwrap());
            then.status(200).body("this is a test");
        });

        // 0, 1, 2
        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = AsyncClient::with_client(req_client);

        let mutator = ReplaceKeyword::new(&"FUZZ", "range");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath]))?;

        // stop fuzzing if path matches '1'
        let decider = RequestRegexDecider::new("1", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::StopFuzzing
            } else {
                Action::Keep
            }
        });

        let mut fuzzer = AsyncFuzzer::new(3)
            .client(client.clone())
            .request(request.clone())
            .scheduler(OrderedScheduler::new(state.clone())?)
            .mutators(build_mutators!(mutator.clone()))
            .observers(build_observers!(ResponseObserver::new()))
            .deciders(build_deciders!(decider.clone()))
            .build();

        let result = fuzzer.fuzz_once(&mut state.clone()).await?;
        assert!(matches!(result, Some(Action::StopFuzzing)));

        // due to how the async fuzzer works, it's possible that no requests will
        // be sent in this short of a test, so the mock server may or may not
        // have received requests
        assert!(mock.hits() == 1 || mock.hits() == 0);

        fuzzer.scheduler.reset();
        fuzzer.fuzz_n_iterations(3, &mut state).await?;

        assert!(mock.hits() <= 2);

        fuzzer.scheduler.reset();
        fuzzer.fuzz(&mut state).await?;

        assert!(mock.hits() <= 3);

        Ok(())
    }

    /// test that the fuzz loop will stop if the decider returns a StopFuzzing action
    /// in the post-send phase
    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_async_fuzzer_stops_fuzzing_post_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let _mock0 = srv.mock(|when, then| {
            when.method(GET).path("/0");
            then.status(200);
        });

        let _mock1 = srv.mock(|when, then| {
            when.method(GET).path("/1");
            then.status(201).body("derp");
        });

        let _mock2 = srv.mock(|when, then| {
            when.method(GET).path("/2");
            then.status(200);
        });

        // 0, 1, 2
        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range.clone());

        let req_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = AsyncClient::with_client(req_client);

        let mutator = ReplaceKeyword::new(&"FUZZ", "range");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath]))?;

        // stop fuzzing if body matches 'derp' which should be '/1' endpoint
        let decider = ResponseRegexDecider::new("derp", |regex, response, _state| {
            if regex.is_match(response.body()) {
                Action::StopFuzzing
            } else {
                Action::Keep
            }
        });

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<AsyncResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider);
        let mutators = build_mutators!(mutator);

        let mut fuzzer = AsyncFuzzer::new(1)
            .client(client.clone())
            .request(request.clone())
            .scheduler(scheduler.clone())
            .mutators(mutators.clone())
            .observers(observers.clone())
            .deciders(deciders.clone())
            .build();

        fuzzer.fuzz_once(&mut state).await?;

        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 2.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 1);
            assert_eq!(guard.status_code_count(201).unwrap(), 1);
            assert_eq!(
                guard
                    .actions()
                    .get("response")
                    .unwrap()
                    .get(&Action::StopFuzzing)
                    .unwrap(),
                &1
            );
        }

        fuzzer = AsyncFuzzer::new(1)
            .client(client.clone())
            .request(request.clone())
            .scheduler(scheduler.clone())
            .mutators(mutators.clone())
            .observers(observers.clone())
            .deciders(deciders.clone())
            .build();

        fuzzer.fuzz_n_iterations(2, &mut state).await?;

        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 2.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 1);
            assert_eq!(guard.status_code_count(201).unwrap(), 1);
            assert_eq!(
                guard
                    .actions()
                    .get("response")
                    .unwrap()
                    .get(&Action::StopFuzzing)
                    .unwrap(),
                &1
            );
        }

        fuzzer = AsyncFuzzer::new(1)
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(mutators)
            .observers(observers)
            .deciders(deciders)
            .build();

        fuzzer.fuzz(&mut state).await?;

        // at this point, /2 was hit from both previous tests, so we're 2 higher than expected
        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 2.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 1);
            assert_eq!(guard.status_code_count(201).unwrap(), 1);
            assert_eq!(
                guard
                    .actions()
                    .get("response")
                    .unwrap()
                    .get(&Action::StopFuzzing)
                    .unwrap(),
                &1
            );
        }

        // the take away is that the fuzz/fuzz_n_iterations methods stop when told to, even though
        // the request is still in-flight, i.e. we don't have a never-ending test or anything
        // which proves that the logic is working and correct
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    /// test that the fuzz loop will continue iterating over a corpus that has been
    /// modified in-place by the AddToCorpus action
    async fn test_add_to_corpus_iters_over_new_entries_without_reset(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let _mock = srv.mock(|when, then| {
            // registers hits for 0, 1, 2, 3
            when.method(GET)
                .path_matches(Regex::new("[0123](.js)?").unwrap());
            then.status(200).body("this is a test");
        });

        // 0, 1, 2
        let words = Wordlist::with_words(["0", "1.js", "2"])
            .name("words")
            .build();

        let mut state = SharedState::with_corpus(words);

        let req_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = AsyncClient::with_client(req_client);

        let mutator = ReplaceKeyword::new(&"FUZZ", "words");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath]))?;

        // add /3 to the path corpus
        let decider = ResponseRegexDecider::new("/1.js", |regex, observer, _state| {
            if regex.is_match(observer.url().as_str().as_bytes()) {
                Action::AddToCorpus(
                    "words".to_string(),
                    CorpusItemType::Data("3".into()),
                    FlowControl::Keep,
                )
            } else {
                Action::Keep
            }
        });

        let scheduler = OrderedScheduler::new(state.clone())?;

        let mut fuzzer = AsyncFuzzer::new(1)
            .client(client.clone())
            .request(request.clone())
            .scheduler(scheduler)
            .mutators(build_mutators!(mutator.clone()))
            .observers(build_observers!(ResponseObserver::new()))
            .deciders(build_deciders!(decider.clone()))
            .build();

        let mut corpora_len = state.total_corpora_len();

        fuzzer.fuzz_once(&mut state).await?;

        // corpora_len should be +1 from the initial call
        assert_eq!(corpora_len + 1, state.total_corpora_len());

        // reset corpora_len to the new value
        corpora_len = state.total_corpora_len();

        // call again to hit the new /3 entry
        fuzzer.scheduler_mut().update_length();
        fuzzer.fuzz_once(&mut state).await?;

        // corpora_len shouldn't have changed
        assert_eq!(corpora_len, state.total_corpora_len());

        // 0-3 sent/recv'd and ok
        assert_eq!(
            state
                .stats()
                .read()
                .unwrap()
                .status_code_count(200)
                .unwrap(),
            4
        );

        Ok(())
    }
}
