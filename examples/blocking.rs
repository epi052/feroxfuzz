//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example blocking
use feroxfuzz::actions::Action;
use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::{RangeCorpus, Wordlist};
use feroxfuzz::deciders::{RequestRegexDecider, ResponseRegexDecider, StatusCodeDecider};
use feroxfuzz::fuzzers::{BlockingFuzzer, BlockingFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::{Ordering, ResponseProcessor, StatisticsProcessor};
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;
use feroxfuzz::AsInner;

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let corpora = [
        RangeCorpus::new().name("range1").stop(3).build()?,
        Wordlist::with_words(["a", "b", "c"]).name("chars").build(),
        RangeCorpus::new().name("range2").stop(6).start(4).build()?,
    ];

    let mut state = SharedState::with_corpora(corpora);

    let scheduler = OrderedScheduler::new(state.clone())?;

    // byo-client, this example uses reqwest
    let req_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    // with some client that can handle the actual http request/response stuff
    // we can build a feroxfuzz client, specifically a blocking client in this
    // instance. Because we're using a blocking client, there's an implicit
    // opt-in to using the BlockingResponse implementor of the Response trait
    let client = BlockingClient::with_client(req_client);

    // ReplaceKeyword mutators operate similar to how ffuf/wfuzz work, in that they'll
    // put the current corpus item wherever the keyword is found, as long as its found
    // in data marked fuzzable (see ShouldFuzz directives below)
    let mutator1 = ReplaceKeyword::new(&"RANGE1", "range1");
    let mutator2 = ReplaceKeyword::new(&"CHARS", "chars");
    let mutator3 = ReplaceKeyword::new(&"RANGE2", "range2");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[ShouldFuzz::URLParameterValue(
            b"injectable=/RANGE1/CHARS/RANGE2",
            b"=",
        )]),
    )?;

    // a StatusCodeDecider provides a way to inspect each response's status code and decide upon some Action
    // based on the result of whatever comparison function is passed to the StatusCodeDecider constructor
    //
    // in plain english, the StatusCodeDecider below will check to see if the request's http response code
    // received is equal to 200/OK. If the response code is 200, then the decider will recommend the Keep
    // action be performed. If the response code is anything other than 200, then the recommendation will
    // be to Discard the response.
    let decider = StatusCodeDecider::new(200, |status, observed, _state| {
        if status == observed {
            Action::Keep
        } else {
            Action::Discard
        }
    });

    // todo change this to only use one decider or something and update the name accordingly (probably, async/blocking may be ok..., but either way need to pare it down)

    let body_decider = ResponseRegexDecider::new("[dD][eE][rR][pP]", |regex, observer, _state| {
        if regex.is_match(observer.body()) {
            Action::Keep
        } else {
            Action::Discard
        }
    });

    let path_decider = RequestRegexDecider::new("128", |regex, request, _state| {
        if let Some(params) = request.params() {
            for (key, value) in params {
                if regex.is_match(key.inner()) || regex.is_match(value.inner()) {
                    println!("dropping request: {}", request.id());
                    return Action::Discard;
                }
            }
        }

        Action::Keep
    });

    let stats_printer =
        StatisticsProcessor::new(Ordering::PostSend, |statistics, _action, _state| {
            if let Ok(guard) = statistics.read() {
                if guard.elapsed().trunc() % 5.0 < f64::EPSILON {
                    println!(
                        "{} reqs/sec (requests: {}, elapsed: {:?})",
                        guard.requests_per_sec(),
                        guard.requests(),
                        guard.elapsed()
                    );
                }
            }
        });

    let response_printer = ResponseProcessor::new(
        |response_observer: &ResponseObserver<BlockingResponse>, action, _state| {
            if let Some(action) = action {
                if matches!(action, Action::Keep) {
                    println!(
                        "[{}] {} - {} - {:?}",
                        response_observer.status_code(),
                        response_observer.content_length(),
                        response_observer.url(),
                        response_observer.elapsed(),
                    );
                }
            }
        },
    );

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let deciders = build_deciders!(path_decider, body_decider, decider);
    let mutators = build_mutators!(mutator1, mutator2, mutator3);
    let processors = build_processors!(stats_printer, response_printer);

    let mut fuzzer = BlockingFuzzer::new(
        client, request, scheduler, mutators, observers, processors, deciders,
    );

    fuzzer.fuzz_n_iterations(2, &mut state)?;

    Ok(())
}
