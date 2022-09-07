//! Use data from an [`Observer`] to make a decision about the supplied data
mod regex;
mod status_code;

use crate::actions::Action;
use crate::metadata::AsAny;
use crate::observers::Observers;
use crate::requests::Request;
use crate::responses::Response;
use crate::state::SharedState;
use crate::std_ext::tuple::Named;
use crate::DecidersList;

pub use self::regex::RequestRegexDecider;
pub use self::regex::ResponseRegexDecider;
pub use self::status_code::StatusCodeDecider;
// re-export LogicOperation from here, for a more logical location from an external user's perspective
pub use crate::std_ext::ops::LogicOperation;

use cfg_if::cfg_if;
use dyn_clone::DynClone;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::client::HttpClient;
        use crate::observers::Observer;
    }
}

/// A `Decider` pulls information from some [`Observer`] in order to
/// reach a decision about what [`Action`] should be taken
pub trait Decider<O, R>: DynClone + AsAny + Named
where
    O: Observers<R>,
    R: Response,
{
    /// given the fuzzer's [`SharedState`], and the current mutated [`Request`] to be sent,
    /// make a decision that returns an [`Action`]
    ///
    /// this is typically called via the `pre_send_hook`
    fn decide_with_request(&mut self, _state: &SharedState, _request: &Request) -> Option<Action> {
        None
    }

    /// given the fuzzer's [`SharedState`], and a collection of [`Observers`], make a decision that
    /// returns an [`Action`]
    ///
    /// this is typically called via the `post_send_hook`
    fn decide_with_observers(&mut self, _state: &SharedState, _observers: &O) -> Option<Action> {
        None
    }
}

impl<O, R> Clone for Box<dyn Decider<O, R>>
where
    O: Observers<R>,
    R: Response,
{
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}

impl<O, R> Clone for Box<dyn DeciderHooks<O, R>>
where
    O: Observers<R>,
    R: Response,
{
    fn clone(&self) -> Self {
        dyn_clone::clone_box(&**self)
    }
}

/// defines the hooks that are executed before a request is sent
/// and after a response is received
///
/// expected order of operations:
/// - `pre_send_hook(.., request, ..)`
/// - `let response = client.send(request)`
/// - `post_send_hook(.., response,)`
pub trait DeciderHooks<O, R>: Decider<O, R> + DynClone + AsAny + Sync + Send
where
    O: Observers<R>,
    R: Response,
{
    /// called before an [`HttpClient`] sends a [`Request`]
    fn pre_send_hook(
        &mut self,
        state: &SharedState,
        request: &Request,
        action: Option<Action>,
        operation: LogicOperation,
    ) -> Option<Action> {
        // short-circuit logic
        if let Some(ref inner) = action {
            match (inner, operation) {
                // received a Discard with an And, or a Keep with an Or
                // this means we can skip the decide_with_observers call
                // altogether and simply return the current action
                (Action::Discard, LogicOperation::And) => return Some(Action::Discard),
                (Action::Keep, LogicOperation::Or) => return Some(Action::Keep),
                _ => {}
            }
        }

        let new_action = self.decide_with_request(state, request)?;

        // take the current action that was decided upon via decide_with_observers, and the
        // previously decided action (if any) to arrive at what should be returned as the
        // current decided action
        let final_action = match (action, operation) {
            (None, _) => new_action,
            (Some(old_action), LogicOperation::And) => new_action & old_action,
            (Some(old_action), LogicOperation::Or) => new_action | old_action,
        };

        Some(final_action)
    }

    /// called after an [`HttpClient`] receives a [`Response`]
    fn post_send_hook(
        &mut self,
        state: &SharedState,
        observers: &O,
        action: Option<Action>,
        operation: LogicOperation,
    ) -> Option<Action> {
        // short-circuit logic
        if let Some(ref inner) = action {
            match (inner, operation) {
                // received a Discard with an And, or a Keep with an Or
                // this means we can skip the decide_with_observers call
                // altogether and simply return the current action
                (Action::Discard, LogicOperation::And) => return Some(Action::Discard),
                (Action::Keep, LogicOperation::Or) => return Some(Action::Keep),
                _ => {}
            }
        }

        let new_action = self.decide_with_observers(state, observers)?;

        // take the current action that was decided upon via decide_with_observers, and the
        // previously decided action (if any) to arrive at what should be returned as the
        // current decided action
        let final_action = match (action, operation) {
            (None, _) => new_action,
            (Some(old_action), LogicOperation::And) => new_action & old_action,
            (Some(old_action), LogicOperation::Or) => new_action | old_action,
        };

        Some(final_action)
    }
}

/// marker trait for a collection of implementors of [`DeciderHooks`]
///
/// recursively calls [`DeciderHooks::pre_send_hook`] or [`DeciderHooks::post_send_hook`]
/// as appropriate.
///
/// The given [`LogicOperation`] is chained between all implementors of [`DeciderHooks`]
/// for the current [`DecidersList`]. This means that a single group of `DeciderHooks` will
/// all share the same logical operation, i.e. hook AND hook AND hook AND ... etc.
///
/// In order to logically group different sets of hooks, with different logic, we need
/// to make a separate [`Deciders`] tuple for each logical grouping.
pub trait Deciders<O, R>
where
    O: Observers<R>,
    R: Response,
{
    /// called before an [`HttpClient`] sends a [`Request`]
    ///
    /// recursively calls [`DeciderHooks::pre_send_hook`]
    fn call_pre_send_hooks(
        &mut self,
        _state: &SharedState,
        _request: &Request,
        action: Option<Action>,
        _operation: LogicOperation,
    ) -> Option<Action> {
        action
    }

    /// called after an [`HttpClient`] receives a [`Response`]
    ///
    /// recursively calls [`DeciderHooks::post_send_hook`]
    fn call_post_send_hooks(
        &mut self,
        _state: &SharedState,
        _observers: &O,
        action: Option<Action>,
        _operation: LogicOperation,
    ) -> Option<Action> {
        action
    }
}

impl<O, R> Deciders<O, R> for ()
where
    O: Observers<R>,
    R: Response,
{
}

impl<Head, Tail, O, R> Deciders<O, R> for (Head, Tail)
where
    Head: DeciderHooks<O, R>,
    Tail: Deciders<O, R> + DecidersList,
    O: Observers<R>,
    R: Response,
{
    fn call_pre_send_hooks(
        &mut self,
        state: &SharedState,
        request: &Request,
        action: Option<Action>,
        operation: LogicOperation,
    ) -> Option<Action> {
        let action = self.0.pre_send_hook(state, request, action, operation);
        self.1
            .call_pre_send_hooks(state, request, action, operation)
    }

    fn call_post_send_hooks(
        &mut self,
        state: &SharedState,
        observers: &O,
        action: Option<Action>,
        operation: LogicOperation,
    ) -> Option<Action> {
        let action = self.0.post_send_hook(state, observers, action, operation);
        self.1
            .call_post_send_hooks(state, observers, action, operation)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::similar_names)]
    use super::*;
    use crate::client::{BlockingClient, BlockingRequests};
    use crate::corpora::RangeCorpus;
    use crate::fuzzers::BlockingFuzzer;
    use crate::mutators::ReplaceKeyword;
    use crate::observers::ResponseObserver;
    use crate::prelude::*;
    use crate::processors::ResponseProcessor;
    use crate::requests::ShouldFuzz;
    use crate::responses::BlockingResponse;
    use crate::schedulers::OrderedScheduler;
    use ::regex::Regex;
    use httpmock::Method::GET;
    use httpmock::MockServer;
    use reqwest;
    use std::time::Duration;

    /// corpus has 3 entries, two of which should be discarded due to the two regex deciders
    /// chained by a logical AND (non-default); chaining deciders with an AND that return
    /// Discards can be thought of as a denylist
    #[test]
    fn pre_send_deciders_used_as_denylist() -> Result<(), Box<dyn std::error::Error>> {
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

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

        // discard if path matches '1'
        let decider1 = RequestRegexDecider::new("1", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::Discard
            } else {
                Action::Keep
            }
        });

        // discard if path matches '2'
        let decider2 = RequestRegexDecider::new("2", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::Discard
            } else {
                Action::Keep
            }
        });

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider1, decider2);
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

        // this call is key to making a denylist work with chained Discard actions
        fuzzer.set_pre_send_logic(LogicOperation::And);

        fuzzer.fuzz_once(&mut state)?;

        // /1 and /2 never sent
        mock.assert_hits(1);

        Ok(())
    }

    /// corpus has 3 entries, two of which should be kept due to the two regex deciders
    /// chained by a logical OR; chaining deciders with an OR that return
    /// Discard can be thought of as an allowlist
    #[test]
    fn pre_send_deciders_used_as_allow_list() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock = srv.mock(|when, then| {
            when.method(GET).path_matches(Regex::new("[012]").unwrap());
            then.status(200).body("this is a test");
        });

        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        let client = BlockingClient::with_client(req_client);

        let mutator = ReplaceKeyword::new(&"FUZZ", "range");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

        let decider1 = RequestRegexDecider::new("1", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::Keep
            } else {
                Action::Discard
            }
        });

        let decider2 = RequestRegexDecider::new("2", |regex, request, _state| {
            if regex.is_match(request.path().inner()) {
                Action::Keep
            } else {
                Action::Discard
            }
        });

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider1, decider2);
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

        // only /1 and /2 sent
        mock.assert_hits(2);

        Ok(())
    }

    /// corpus has 3 entries, two of which should be discarded due to the two regex deciders
    /// chained by a logical AND (non-default); chaining deciders with an AND that return
    /// Discards can be thought of as a denylist
    #[test]
    fn post_send_deciders_used_as_denylist() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock_200s = srv.mock(|when, then| {
            // registers 200 response for 0
            when.method(GET).path("/0");
            then.status(200).body("this is a test");
        });
        let mock_401s = srv.mock(|when, then| {
            // registers 401 response for 1
            when.method(GET).path("/1");
            then.status(401).body("this is a test");
        });
        let mock_404s = srv.mock(|when, then| {
            // registers 404 response for 2
            when.method(GET).path("/2");
            then.status(404).body("this is a test");
        });
        let mock_tracked_side_effects = srv.mock(|when, then| {
            // registers 404 response for 2
            when.method(GET).path("/side-effect");
            then.status(301).body("this is a test");
        });

        // 0, 1, 2
        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        // cloning so i can reuse the client to produce the testable side-effect
        let client = BlockingClient::with_client(req_client);
        let side_effect_generator = client.clone();

        let mutator = ReplaceKeyword::new(&"FUZZ", "range");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

        // discard if response's status code matches 401
        let decider1 = StatusCodeDecider::new(401, |status, observed, _state| {
            if status == observed {
                Action::Discard
            } else {
                Action::Keep
            }
        });

        // discard if response's status code matches 404
        let decider2 = StatusCodeDecider::new(404, |status, observed, _state| {
            if status == observed {
                Action::Discard
            } else {
                Action::Keep
            }
        });

        let processor = ResponseProcessor::new(
            |observer: &ResponseObserver<BlockingResponse>, action, _state| {
                if let Some(action) = action {
                    if matches!(action, Action::Discard) {
                        assert!([401, 404].contains(&observer.status_code()));
                        let req = Request::from_url(&srv.url("/side-effect"), None).unwrap();
                        side_effect_generator.send(req).unwrap();
                    }
                }
            },
        );

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider1, decider2);
        let mutators = build_mutators!(mutator);
        let processors = build_processors!(processor);

        let mut fuzzer = BlockingFuzzer::new(
            client, request, scheduler, mutators, observers, processors, deciders,
        );

        // this call is key to making a denylist work with chained Discard actions
        fuzzer.set_post_send_logic(LogicOperation::And);

        fuzzer.fuzz_once(&mut state)?;

        mock_200s.assert_hits(1);
        mock_401s.assert_hits(1);
        mock_404s.assert_hits(1); // just ensures the right endpoints were hit

        // processor should have hit this endpoint for each discarded item
        mock_tracked_side_effects.assert_hits(2);

        Ok(())
    }

    /// corpus has 3 entries, two of which should be kept due to the two regex deciders
    /// chained by a logical OR; chaining deciders with an OR that return
    /// Keep can be thought of as an allowlist
    #[test]
    fn post_send_deciders_used_as_allow_list() -> Result<(), Box<dyn std::error::Error>> {
        let srv = MockServer::start();

        let mock_200s = srv.mock(|when, then| {
            // registers 200 response for 0
            when.method(GET).path("/0");
            then.status(200).body("this is a test");
        });
        let mock_403s = srv.mock(|when, then| {
            // registers 403 response for 1
            when.method(GET).path("/1");
            then.status(403).body("this is a test");
        });
        let mock_404s = srv.mock(|when, then| {
            // registers 404 response for 2
            when.method(GET).path("/2");
            then.status(404).body("this is a test");
        });
        let mock_tracked_side_effects = srv.mock(|when, then| {
            // registers 404 response for 2
            when.method(GET).path("/side-effect");
            then.status(301).body("this is a test");
        });

        let range = RangeCorpus::with_stop(3).name("range").build()?;
        let mut state = SharedState::with_corpus(range);

        let req_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(1))
            .build()?;

        // cloning so i can reuse the client to produce the testable side-effect
        let client = BlockingClient::with_client(req_client);
        let side_effect_generator = client.clone();

        let mutator = ReplaceKeyword::new(&"FUZZ", "range");

        let request = Request::from_url(&srv.url("/FUZZ"), Some(&[ShouldFuzz::URLPath(b"/FUZZ")]))?;

        // keep if response's status code matches 200
        let decider1 = StatusCodeDecider::new(200, |status, observed, _state| {
            if status == observed {
                Action::Keep
            } else {
                Action::Discard
            }
        });

        // keep if response's status code matches 403
        let decider2 = StatusCodeDecider::new(403, |status, observed, _state| {
            if status == observed {
                Action::Keep
            } else {
                Action::Discard
            }
        });

        let processor = ResponseProcessor::new(
            |observer: &ResponseObserver<BlockingResponse>, action, _state| {
                println!("{:?}", observer);
                if let Some(action) = action {
                    if matches!(action, Action::Keep) {
                        assert!([200, 403].contains(&observer.status_code()));
                        let req = Request::from_url(&srv.url("/side-effect"), None).unwrap();
                        side_effect_generator.send(req).unwrap();
                    }
                }
            },
        );

        let scheduler = OrderedScheduler::new(state.clone())?;
        let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

        let observers = build_observers!(response_observer);
        let deciders = build_deciders!(decider1, decider2);
        let mutators = build_mutators!(mutator);
        let processors = build_processors!(processor);

        let mut fuzzer = BlockingFuzzer::new(
            client, request, scheduler, mutators, observers, processors, deciders,
        );

        fuzzer.fuzz_once(&mut state)?;

        mock_200s.assert_hits(1);
        mock_403s.assert_hits(1);
        mock_404s.assert_hits(1); // just ensures the right endpoints were hit

        // processor should have hit this endpoint for each discarded item
        mock_tracked_side_effects.assert_hits(2);

        Ok(())
    }
}
