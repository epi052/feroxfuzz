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

#[allow(clippy::wildcard_imports)]
use super::typestate::*;
use super::{AsyncFuzzerBuilder, AsyncFuzzing, Fuzzer, FuzzingLoopHook};
use crate::actions::Action;
use crate::actions::FlowControl;
use crate::client;
use crate::deciders::Deciders;
use crate::error::FeroxFuzzError;
use crate::events::{
    DiscardedRequest, DiscardedResponse, EventPublisher, FuzzOnce, KeptRequest, KeptResponse,
    StopFuzzing,
};
use crate::mutators::Mutators;
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::{AsyncResponse, Response};
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::Len;
use crate::std_ext::ops::LogicOperation;

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
}

#[async_trait]
impl<A, D, M, O, P, S> AsyncFuzzing for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests + Send + Sync + Clone + 'static,
    D: Deciders<O, AsyncResponse> + Send + Clone,
    M: Mutators + Send,
    O: Observers<AsyncResponse> + Send + Clone,
    P: Processors<O, AsyncResponse> + Send + Clone,
    S: Scheduler + Send + Iterator<Item = ()> + Clone,
    <S as Iterator>::Item: Debug,
{
    #[instrument(skip_all, fields(%self.threads, ?self.post_send_logic, ?self.pre_send_logic) name = "fuzz-loop", level = "trace")]
    async fn fuzz_once(
        &mut self,
        state: &mut SharedState,
    ) -> Result<Option<Action>, FeroxFuzzError> {
        let num_threads = self.threads;
        let post_send_logic = self.post_send_logic();
        let pre_send_logic = self.pre_send_logic();
        let scheduler = self.scheduler.clone();

        if let Some(hook) = &mut self.pre_loop_hook {
            // call the pre-loop hook if it is defined
            (hook.callback)(state);
            hook.called += 1;
        }

        state.events().notify(FuzzOnce {
            threads: num_threads,
            pre_send_logic,
            post_send_logic,
            corpora_length: state.corpora().iter().map(|(_, v)| v.len()).sum(),
        });

        // facilitates a threadsafe way to 'break' out of the iterator
        let should_quit = Arc::new(AtomicBool::new(false));
        let mut err = Ok(());

        stream::iter(scheduler)
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
                    let mut request = self.request.clone();

                    *request.id_mut() += self.request_id;

                    let mut mutated_request = self
                        .mutators
                        .call_mutate_hooks(state, request)?;

                    self.observers.call_pre_send_hooks(&mutated_request);

                    let decision = self.deciders.call_pre_send_hooks(
                        state,
                        &mutated_request,
                        None,
                        pre_send_logic,
                    );

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

                    self.processors.call_pre_send_hooks(
                        state,
                        &mut mutated_request,
                        decision.as_ref(),
                    );

                    match decision {
                        Some(Action::Discard) => {
                            self.request_id += 1;

                            state.events().notify(DiscardedRequest {
                                id: mutated_request.id(),
                            });

                            return Err(FeroxFuzzError::DiscardedRequest);
                        }
                        Some(Action::AddToCorpus(name, flow_control)) => {
                            // i can't think of too many uses for an AddToCorpus to run on the
                            // pre-send side of things... maybe a 'seen' corpus or something?
                            // leaving it here for now.

                            state.add_to_corpus(&name, &mutated_request)?;

                            match flow_control {
                                FlowControl::StopFuzzing => {
                                    tracing::info!(
                                        "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                        self.request_id
                                    );
                                    return Err(FeroxFuzzError::FuzzingStopped);
                                }
                                FlowControl::Discard => {
                                    self.request_id += 1;

                                    state.events().notify(DiscardedRequest {
                                        id: mutated_request.id(),
                                    });

                                    return Err(FeroxFuzzError::DiscardedRequest);
                                }
                                FlowControl::Keep => {
                                    state.events().notify(KeptRequest {
                                        id: mutated_request.id(),
                                    });
                                }
                            }

                            // ignore when flow control is Keep, same as we do for Action::Keep below
                        }
                        Some(Action::StopFuzzing) => {
                            tracing::info!(
                                "[ID: {}] stopping fuzzing due to StopFuzzing action",
                                self.request_id
                            );
                            return Err(FeroxFuzzError::FuzzingStopped);
                        }
                        Some(Action::Keep) => {
                            state.events().notify(KeptRequest {
                                id: mutated_request.id(),
                            });
                        }
                        _ => {}// do nothing
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
                if should_quit.load(Ordering::Relaxed) {
                    // this check accounts for us setting the action to StopFuzzing in the PostSend phase
                    **err = Err(FeroxFuzzError::FuzzingStopped);
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
                            should_quit.store(true, Ordering::Relaxed);
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

                let request_id = response.as_ref().unwrap().id();  // only used for logging

                // response cannot be Err after this point, so is safe to unwrap
                c_observers.call_post_send_hooks(response.unwrap());

                let decision =
                    c_deciders.call_post_send_hooks(&c_state, &c_observers, None, post_send_logic);

                if c_state.update(&c_observers, decision.as_ref()).is_err() {
                    // could not update the state via the observers; cannot reliably make
                    // decisions or perform actions on this response as a result and must
                    // skip any post processing actions
                    warn!("Could not update state via observers; skipping Deciders and Processors");
                    return;
                }

                c_processors.call_post_send_hooks(&c_state, &c_observers, decision.as_ref());

                match decision {
                    Some(Action::AddToCorpus(name, flow_control)) => {
                        // if we've reached this point, flow control doesn't matter anymore; the
                        // only thing we need to check at this point is if we need to alter the
                        // corpus

                        if let Err(err) = c_state.add_to_corpus(&name, &c_request) {
                            warn!("Could not add {:?} to corpus[{name}]: {:?}", c_request, err);
                        }

                        match flow_control {
                            FlowControl::StopFuzzing => {
                                tracing::info!(
                                    "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                    request_id
                                );
                                c_should_quit.store(true, Ordering::Relaxed);
                            }
                            FlowControl::Discard => {
                                c_state.events().notify(DiscardedResponse {
                                    id: request_id
                                });
                            }
                            FlowControl::Keep => {
                                c_state.events().notify(KeptResponse {
                                    id: request_id
                                });
                            }
                        }
                    }
                    Some(Action::StopFuzzing) => {
                        tracing::info!(
                            "[ID: {}] stopping fuzzing due to StopFuzzing action",
                            request_id
                        );
                        c_should_quit.store(true, Ordering::Relaxed);
                    }
                    Some(Action::Discard) => {
                        c_state.events().notify(DiscardedResponse {
                            id: request_id
                        });
                    }
                    Some(Action::Keep) => {
                        c_state.events().notify(KeptResponse {
                            id: request_id
                        });
                    }
                    None => {}

                }
        })
            .await;

        // in case we're fuzzing more than once, reset the scheduler
        self.scheduler.reset();

        if err.is_err() || should_quit.load(Ordering::SeqCst) {
            // fire the stop fuzzing event
            state.events().notify(&StopFuzzing);

            if let Some(hook) = &mut self.post_loop_hook {
                // call the post loop hook if available;
                (hook.callback)(state);
                hook.called += 1;
            }

            return Ok(Some(Action::StopFuzzing));
        }

        Ok(None) // no action taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::AsyncClient;
    use crate::corpora::RangeCorpus;
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    /// test that the fuzz loop will stop if the decider returns a StopFuzzing action in
    /// the pre-send phase
    async fn test_async_fuzzer_stops_fuzzing_pre_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let _mock = srv.mock(|when, then| {
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

        let mut fuzzer = AsyncFuzzer::new(1)
            .client(client.clone())
            .request(request.clone())
            .scheduler(OrderedScheduler::new(state.clone())?)
            .mutators(build_mutators!(mutator.clone()))
            .observers(build_observers!(ResponseObserver::new()))
            .deciders(build_deciders!(decider.clone()))
            .build();

        fuzzer.fuzz_once(&mut state.clone()).await?;

        // /1 and /2 never sent
        assert_eq!(
            state
                .stats()
                .read()
                .unwrap()
                .status_code_count(200)
                .unwrap(),
            1
        );

        fuzzer.scheduler.reset();
        fuzzer.fuzz_n_iterations(3, &mut state).await?;

        // /1 and /2 never sent, but /0 was sent again
        assert_eq!(
            state
                .stats()
                .read()
                .unwrap()
                .status_code_count(200)
                .unwrap(),
            2
        );

        fuzzer.scheduler.reset();
        fuzzer.fuzz(&mut state).await?;

        // /1 and /2 never sent, but /0 was sent again
        assert_eq!(
            state
                .stats()
                .read()
                .unwrap()
                .status_code_count(200)
                .unwrap(),
            3
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    /// test that the fuzz loop will stop if the decider returns a StopFuzzing action
    /// in the post-send phase
    async fn test_async_fuzzer_stops_fuzzing_post_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let _mock = srv.mock(|when, then| {
            // registers hits for 0
            when.method(GET).path_matches(Regex::new("[02]").unwrap());
            then.status(200).body("this is a test");
        });

        let _mock2 = srv.mock(|when, then| {
            // registers hits for 1, 2
            #[allow(clippy::trivial_regex)]
            when.method(GET).path_matches(Regex::new("1").unwrap());
            then.status(201).body("derp");
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

        // stop fuzzing if path matches '1'
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
            .client(client)
            .request(request)
            .scheduler(scheduler)
            .mutators(mutators)
            .observers(observers)
            .deciders(deciders)
            .build();

        fuzzer.fuzz_once(&mut state).await?;

        // /0 sent/recv'd and ok
        // /1 sent/recv'd and bad
        // /2 never *processed*
        //
        // in an async context, this works ok by itself with a threadcount of 1, but the other request
        // is still in-flight and will likely hit the target, this matters for the following test
        // assertions as the expected count is more than what one may think is accurate
        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 2.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 1);
            assert_eq!(guard.status_code_count(201).unwrap(), 1);
        }

        fuzzer.scheduler.reset();
        fuzzer.fuzz_n_iterations(2, &mut state).await?;

        // at this point, /2 was hit from the previous test, so we're 1 higher than expected
        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 4.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 2);
            assert_eq!(guard.status_code_count(201).unwrap(), 2);
        }

        fuzzer.scheduler.reset();
        fuzzer.fuzz(&mut state).await?;

        // at this point, /2 was hit from both previous tests, so we're 2 higher than expected
        if let Ok(guard) = state.stats().read() {
            assert!((guard.requests() - 6.0).abs() < std::f64::EPSILON);
            assert_eq!(guard.status_code_count(200).unwrap(), 3);
            assert_eq!(guard.status_code_count(201).unwrap(), 3);
        }

        // the take away is that the fuzz/fuzz_n_iterations methods stop when told to, even though
        // the request is still in-flight, i.e. we don't have a never-ending test or anything
        // which proves that the logic is working and correct
        Ok(())
    }
}
