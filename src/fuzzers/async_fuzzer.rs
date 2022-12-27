use std::fmt::Debug;
use std::iter::Iterator;
use std::marker::Send;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
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
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::{AsyncResponse, Response};
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::LogicOperation;

/// internal type used to pass a single object from the `tokio::spawn`
/// call to the `FuturesUnordered` stream
#[derive(Debug, Clone)]
struct RequestFuture {
    request: Request,
    response: AsyncResponse,
}

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
}

#[async_trait]
impl<A, D, M, O, P, S> AsyncFuzzing for AsyncFuzzer<A, D, M, O, P, S>
where
    A: client::AsyncRequests + Send + Sync + Clone + 'static,
    D: Deciders<O, AsyncResponse> + Send + Clone,
    M: Mutators + Send,
    O: Observers<AsyncResponse> + Send + Clone,
    P: Processors<O, AsyncResponse> + Send + Clone,
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

        // collection of unordered futures to store the responses in for processing
        let mut request_futures = FuturesUnordered::new();

        // first loop fires off requests
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

            self.processors
                .call_pre_send_hooks(state, &mut mutated_request, decision.as_ref());

            match decision {
                Some(Action::Discard) => {
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
                            state.add_request_fields_to_corpus(&name, &mutated_request)?;
                        }
                        CorpusItemType::Data(data) => {
                            state.add_data_to_corpus(&name, data)?;
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
                                self.request_id
                            );
                            state.events().notify(&StopFuzzing);
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

            // two arc clones are needed here, one for the semaphore, and one for the client
            let cloned_client = client.clone();
            let cloned_semaphore = semaphore.clone();

            // spawn a new task to send the request, and store the handle in the
            // request_futures collection
            request_futures.push(tokio::spawn(async move {
                // the semaphore only has self.threads permits, so this will block
                // until one is available, limiting the number of concurrent requests
                match cloned_semaphore.acquire_owned().await {
                    Ok(permit) => {
                        let cloned_request = mutated_request.clone();

                        let result = cloned_client.send(mutated_request).await;

                        drop(permit);

                        match result {
                            // if the request was successful, return the response
                            // and the request that generated it
                            Ok(response) => Ok(RequestFuture {
                                response,
                                request: cloned_request,
                            }),
                            // otherwise, allow the error to bubble up to the processing
                            // loop
                            Err(err) => Err(err),
                        }
                    }
                    Err(err) => {
                        tracing::error!("Failed to acquire semaphore permit: {:?}", err);
                        Err(FeroxFuzzError::FailedSemaphoreAcquire { source: err })
                    }
                }
            }));

            self.request_id += 1;
        }

        // second loop handles responses
        //
        // outer loop awaits the actual response, which is a double-nested Result
        // Result<Result<RequestFuture, FeroxFuzzError>, tokio::task::JoinError>
        while let Some(handle) = request_futures.next().await {
            let Ok(task_result) = handle else {
                // tokio::task::JoinError -- task failed to execute to completion
                // could be a cancelled task, or one that panicked for w/e reason
                warn!("Task failed to execute to completion: {:?}", handle.err());
                continue;
            };

            let Ok(request_future) = task_result else {
                let error = task_result.err().unwrap();

                // feroxfuzz::client::Client::send returned an error, which is a client error
                // that means we need to update the statistics and then continue
                state.update_from_error(&error).unwrap_or_default();

                warn!(%error, "response errored out and will not continue through the fuzz loop");
                continue;
            };

            // unpack the request_future into its request and response
            let (request, response) = (request_future.request, request_future.response);

            let request_id = response.id(); // only used for logging

            self.observers.call_post_send_hooks(response);

            let decision = self.deciders.call_post_send_hooks(
                state,
                &self.observers,
                None,
                self.post_send_logic(),
            );

            if state.update(&self.observers, decision.as_ref()).is_err() {
                // could not update the state via the observers; cannot reliably make
                // decisions or perform actions on this response as a result and must
                // skip any post processing actions
                warn!("Could not update state via observers; skipping Deciders and Processors");
                continue;
            }

            self.processors
                .call_post_send_hooks(state, &self.observers, decision.as_ref());

            match decision {
                Some(Action::AddToCorpus(name, corpus_item_type, flow_control)) => {
                    match corpus_item_type {
                        CorpusItemType::Request => {
                            if let Err(err) = state.add_request_fields_to_corpus(&name, &request) {
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
                            return Ok(Some(Action::StopFuzzing));
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
                    return Ok(Some(Action::StopFuzzing));
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

        if let Some(hook) = &mut self.post_loop_hook {
            // call the post-loop hook if it is defined
            (hook.callback)(state);
            hook.called += 1;
        }

        Ok(None) // no action taken
    }
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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

        let mut fuzzer = AsyncFuzzer::new(1)
            .client(client.clone())
            .request(request.clone())
            .scheduler(OrderedScheduler::new(state.clone())?)
            .mutators(build_mutators!(mutator.clone()))
            .observers(build_observers!(ResponseObserver::new()))
            .deciders(build_deciders!(decider.clone()))
            .build();

        let result = fuzzer.fuzz_once(&mut state.clone()).await?;
        assert!(matches!(result, Some(Action::StopFuzzing)));

        // due to how the async fuzzer works, no requests will be sent in this short
        // of a test, so we can't assert that the mock server received any requests
        assert_eq!(mock.hits(), 0);

        fuzzer.scheduler.reset();
        fuzzer.fuzz_n_iterations(3, &mut state).await?;

        assert_eq!(mock.hits(), 0);

        fuzzer.scheduler.reset();
        fuzzer.fuzz(&mut state).await?;

        assert_eq!(mock.hits(), 0);

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
