use std::sync::atomic::AtomicBool;

use super::{BlockingFuzzing, Fuzzer};
use crate::actions::{Action, FlowControl};
use crate::client::BlockingRequests;
use crate::deciders::Deciders;
use crate::error::FeroxFuzzError;
use crate::events::{
    DiscardedRequest, DiscardedResponse, EventPublisher, FuzzOnce, KeptRequest, KeptResponse,
};
use crate::mutators::Mutators;
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::BlockingResponse;
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::{Len, LogicOperation};

use tracing::instrument;
use tracing::log::warn;

/// A fuzzer that operates in serial, meaning that it executes a single fuzzcase at a time
#[derive(Debug, Default, Clone)]
pub struct BlockingFuzzer<B, D, M, O, P, S>
where
    B: BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
    P: Processors,
    S: Scheduler,
{
    client: B,
    request: Request,
    scheduler: S,
    mutators: M,
    observers: O,
    processors: P,
    deciders: D,
    request_id: usize,
    pre_send_logic: Option<LogicOperation>,
    post_send_logic: Option<LogicOperation>,
    pre_loop_called: bool,
}

impl<B, D, M, O, P, S> Fuzzer for BlockingFuzzer<B, D, M, O, P, S>
where
    B: BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
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

impl<B, D, M, O, P, S> BlockingFuzzing for BlockingFuzzer<B, D, M, O, P, S>
where
    B: BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
    P: Processors,
    S: Scheduler,
{
    #[instrument(skip_all, fields(?self.post_send_logic, ?self.pre_send_logic), name = "fuzz-loop", level = "trace")]
    fn fuzz_once(&mut self, state: &mut SharedState) -> Result<Option<Action>, FeroxFuzzError> {
        // if !self.pre_loop_called {
        //     self.pre_loop_hook(state);
        //     self.pre_loop_called = true;
        // }
        state.events().notify(FuzzOnce {
            threads: 1,
            pre_send_logic: self.pre_send_logic().unwrap_or_default(),
            post_send_logic: self.post_send_logic().unwrap_or_default(),
            corpora_length: state.corpora().iter().map(|(_, v)| v.len()).sum(),
        });

        while self.scheduler.next().is_ok() {
            let mut request = self.request.clone();

            *request.id_mut() += self.request_id;

            let mut mutated_request = self.mutators.call_mutate_hooks(state, request)?;

            self.observers.call_pre_send_hooks(&mutated_request);

            let decision = self.deciders.call_pre_send_hooks(
                state,
                &mutated_request,
                None,
                self.pre_send_logic().unwrap_or_default(),
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
                            return Ok(Some(Action::StopFuzzing));
                        }
                        FlowControl::Discard => {
                            self.request_id += 1;

                            state.events().notify(DiscardedRequest {
                                id: mutated_request.id(),
                            });

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
                    return Ok(Some(Action::StopFuzzing));
                }
                Some(Action::Keep) => {
                    state.events().notify(KeptRequest {
                        id: mutated_request.id(),
                    });
                }
                None => {} // do nothing
            }

            let response = self.client.send(mutated_request.clone());

            if let Err(error) = response {
                // can't continue fuzzing if the response is an error
                state.update_from_error(&error)?;

                self.request_id += 1;
                tracing::warn!(%error, "response errored out and will not continue through the fuzz loop");
                continue;
            }

            self.observers.call_post_send_hooks(response.unwrap());

            let decision = self.deciders.call_post_send_hooks(
                state,
                &self.observers,
                None,
                self.post_send_logic().unwrap_or_default(),
            );

            state.update(&self.observers, decision.as_ref())?;

            self.processors
                .call_post_send_hooks(state, &self.observers, decision.as_ref());

            match decision {
                // if we've reached this point, the only flow control that matters anymore is
                // if the fuzzer should stop fuzzing; that means the only thing we need
                // to check at this point is if we need to alter the corpus
                Some(Action::AddToCorpus(name, flow_control)) => {
                    state.add_to_corpus(&name, &mutated_request)?;

                    match flow_control {
                        FlowControl::StopFuzzing => {
                            tracing::info!(
                                "[ID: {}] stopping fuzzing due to AddToCorpus[StopFuzzing] action",
                                self.request_id
                            );
                            return Ok(Some(Action::StopFuzzing));
                        }
                        FlowControl::Discard => {
                            self.request_id += 1;

                            state.events().notify(DiscardedResponse {
                                id: mutated_request.id(),
                            });

                            continue;
                        }
                        FlowControl::Keep => {
                            state.events().notify(KeptResponse {
                                id: mutated_request.id(),
                            });
                        }
                    }
                }
                Some(Action::StopFuzzing) => {
                    tracing::info!(
                        "[ID: {}] stopping fuzzing due to StopFuzzing action",
                        self.request_id
                    );
                    return Ok(Some(Action::StopFuzzing));
                }
                Some(Action::Discard) => {
                    state.events().notify(DiscardedResponse {
                        id: mutated_request.id(),
                    });
                }
                Some(Action::Keep) => {
                    state.events().notify(KeptResponse {
                        id: mutated_request.id(),
                    });
                }
                _ => {}
            }

            self.request_id += 1;
        }

        // in case we're fuzzing more than once, reset the scheduler
        self.scheduler.reset();

        Ok(None) // no action to take
    }
}

impl<B, D, M, O, P, S> BlockingFuzzer<B, D, M, O, P, S>
where
    B: BlockingRequests,
    D: Deciders<O, BlockingResponse>,
    M: Mutators,
    O: Observers<BlockingResponse>,
    P: Processors,
    S: Scheduler,
{
    /// create a new fuzzer that operates in serial, meaning a single fuzzcase is run at a time
    pub const fn new(
        client: B,
        request: Request,
        scheduler: S,
        mutators: M,
        observers: O,
        processors: P,
        deciders: D,
    ) -> Self {
        Self {
            client,
            request,
            scheduler,
            mutators,
            observers,
            processors,
            deciders,
            request_id: 0,
            pre_send_logic: Some(LogicOperation::Or),
            post_send_logic: Some(LogicOperation::Or),
            pre_loop_called: false,
        }
    }

    /// get a mutable reference to the baseline request used for mutation
    pub fn request_mut(&mut self) -> &mut Request {
        &mut self.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::BlockingClient;
    use crate::corpora::RangeCorpus;
    use crate::deciders::{RequestRegexDecider, ResponseRegexDecider};
    use crate::fuzzers::BlockingFuzzer;
    use crate::mutators::ReplaceKeyword;
    use crate::observers::ResponseObserver;
    use crate::prelude::*;
    use crate::requests::ShouldFuzz;
    use crate::responses::BlockingResponse;
    use crate::schedulers::OrderedScheduler;
    use ::regex::Regex;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use reqwest;
    use std::time::Duration;

    #[test]
    /// test that the fuzz loop will stop if the decider returns a `StopFuzzing` action in
    /// the pre-send phase
    fn test_blocking_fuzzer_stops_fuzzing_pre_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock = srv.mock(|when, then| {
            // registers hits for 0, 1, 2
            when.method(GET).path_matches(Regex::new("[012]").unwrap());
            then.status(200).body("this is a test");
        });

        // 0, 1, 2
        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = BlockingClient::with_client(req_client);

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

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider);
        let mutators = build_mutators!(mutator);

        let mut fuzzer = BlockingFuzzer::new(
            client,
            request,
            scheduler,
            mutators,
            observers,
            (),
            deciders,
        );

        fuzzer.fuzz_once(&mut state.clone())?;

        // /1 and /2 never sent
        mock.assert_hits(1);

        fuzzer.scheduler.reset();
        fuzzer.fuzz_n_iterations(1, &mut state.clone())?;

        // /1 and /2 never sent, but /0 was sent again
        mock.assert_hits(2);

        fuzzer.scheduler.reset();
        fuzzer.fuzz(&mut state)?;

        // /1 and /2 never sent, but /0 was sent again
        mock.assert_hits(3);

        Ok(())
    }

    #[test]
    /// test that the fuzz loop will stop if the decider returns a `StopFuzzing` action
    /// in the post-send phase
    fn test_blocking_fuzzer_stops_fuzzing_post_send() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock = srv.mock(|when, then| {
            // registers hits for 0/2
            when.method(GET).path_matches(Regex::new("[02]").unwrap());
            then.status(200).body("this is a test");
        });

        let mock2 = srv.mock(|when, then| {
            // registers hits for 1
            #[allow(clippy::trivial_regex)]
            when.method(GET).path_matches(Regex::new("1").unwrap());
            then.status(200).body("derp");
        });

        // 0, 1, 2
        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = BlockingClient::with_client(req_client);

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
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider);
        let mutators = build_mutators!(mutator);

        let mut fuzzer = BlockingFuzzer::new(
            client,
            request,
            scheduler,
            mutators,
            observers,
            (),
            deciders,
        );

        fuzzer.fuzz_once(&mut state)?;

        // /0 sent/recv'd and ok
        // /1 sent/recv'd and bad
        // /2 never sent
        mock.assert_hits(1);
        mock2.assert_hits(1);

        // fuzzer.scheduler.reset();
        // fuzzer.fuzz_n_iterations(2, &mut state)?;

        // // /0 sent/recv'd and ok
        // // /1 sent/recv'd and bad
        // // /2 never sent
        // mock.assert_hits(2);
        // mock2.assert_hits(2);

        // fuzzer.scheduler.reset();
        // fuzzer.fuzz(&mut state)?;

        // // /0 sent/recv'd and ok
        // // /1 sent/recv'd and bad
        // // /2 never sent
        // mock.assert_hits(3);
        // mock2.assert_hits(3);

        Ok(())
    }
}
