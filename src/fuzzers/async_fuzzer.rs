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
use crate::responses::{AsyncResponse, Response};
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
                                    tracing::info!(
                                        "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                        self.request_id
                                    );                
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
                            tracing::info!(
                                "[ID: {}] stopping fuzzing due to StopFuzzing action",
                                self.request_id
                            );        
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

                let request_id = response.unwrap().id();  // only used for logging

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
                            tracing::info!(
                                "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                request_id
                            );    
                            c_should_quit.store(true, Ordering::Relaxed);
                        }
                    }
                    Some(Action::StopFuzzing) => {
                        tracing::info!(
                            "[ID: {}] stopping fuzzing due to StopFuzzing action",
                            request_id
                        );
                        c_should_quit.store(true, Ordering::Relaxed);
                    }
                    _ => {}

                }
        })
            .await;

        // in case we're fuzzing more than once, reset the scheduler
        self.scheduler.reset();

        if err.is_err() {
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

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

        // stop fuzzing if path matches '1'
        let decider = RequestRegexDecider::new("1", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::StopFuzzing
            } else {
                Action::Keep
            }
        });

        let mut fuzzer = AsyncFuzzer::new(
            1,
            client.clone(),
            request.clone(),
            OrderedScheduler::new(state.clone())?,
            build_mutators!(mutator.clone()),
            build_observers!(ResponseObserver::new()),
            (),
            build_deciders!(decider.clone()),
        );

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

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

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

        let mut fuzzer = AsyncFuzzer::new(
            1,
            client,
            request,
            scheduler,
            mutators,
            observers,
            (),
            deciders,
        );

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
