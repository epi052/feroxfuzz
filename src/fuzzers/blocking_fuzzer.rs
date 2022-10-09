use super::{BlockingFuzzing, Fuzzer};
use crate::actions::{Action, FlowControl};
use crate::client::BlockingRequests;
use crate::deciders::Deciders;
use crate::error::FeroxFuzzError;
use crate::mutators::Mutators;
use crate::observers::Observers;
use crate::processors::Processors;
use crate::requests::Request;
use crate::responses::BlockingResponse;
use crate::schedulers::Scheduler;
use crate::state::SharedState;
use crate::std_ext::ops::LogicOperation;

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
        while self.scheduler.next().is_ok() {
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

            self.processors
                .call_pre_send_hooks(state, &mut mutated_request, decision.as_ref());

            match decision {
                Some(Action::Discard) => {
                    self.request_id += 1;
                    continue;
                }
                Some(Action::AddToCorpus(name, flow_control)) => {
                    // i can't think of too many uses for an AddToCorpus to run on the
                    // pre-send side of things... maybe a 'seen' corpus or something?
                    // leaving it here for now.

                    state.add_to_corpus(name, &mutated_request)?;

                    if matches!(flow_control, FlowControl::Discard) {
                        self.request_id += 1;
                        continue;
                    }
                    // ignore when flow control is Keep, same as we do for Action::Keep below
                }
                Some(Action::StopFuzzing) => {
                    return Ok(Some(Action::StopFuzzing));
                }
                _ => {
                    // do nothing if it's None or an Action::Keep
                }
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

            state.update(&self.observers)?;

            let decision = self.deciders.call_post_send_hooks(
                state,
                &self.observers,
                None,
                self.post_send_logic().unwrap_or_default(),
            );

            self.processors
                .call_post_send_hooks(state, &self.observers, decision.as_ref());

            match decision {
                // if we've reached this point, the only flow control that matters anymore is
                // if the fuzzer should stop fuzzing; that means the only thing we need
                // to check at this point is if we need to alter the corpus
                Some(Action::AddToCorpus(name, flow_control)) => {
                    state.add_to_corpus(name, &mutated_request)?;

                    if matches!(flow_control, FlowControl::StopFuzzing) {
                        return Ok(Some(Action::StopFuzzing));
                    }
                }
                Some(Action::StopFuzzing) => {
                    return Ok(Some(Action::StopFuzzing));
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
        }
    }

    /// get a mutable reference to the baseline request used for mutation
    pub fn request_mut(&mut self) -> &mut Request {
        &mut self.request
    }
}
