//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example sniper
//!
//! This is a demonstration of how to mimic burp's cluster bomb behavior when
//! fuzzing an application.
//!
//! From https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types
//!
//! Sniper uses a single set of payloads. It targets each payload position in turn, and places
//! each payload into that position in turn. Positions that are not targeted for a given request
//! are not affected - the position markers are removed and any enclosed text that appears
//! between them in the template remains unchanged. This attack type is useful for fuzzing a
//! number of request parameters individually for common vulnerabilities. The total number of
//! requests generated in the attack is the product of the number of positions and the number
//! of payloads in the payload set.
use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::RangeCorpus;
use feroxfuzz::fuzzers::{BlockingFuzzer, BlockingFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::RequestProcessor;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a single corpus, as expected for a sniper-style session
    // 0, 1, 2, 3, 4
    let range = RangeCorpus::new().name("range").stop(5).build()?;

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(range);

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
    //
    // in burp terms, these are the "defined positions"
    //
    // note: we could either have any combination of ReplaceKeyword mutators here. We could have a
    // single mutator and put that single keyword into all of the static_param calls below, or
    // we can do what's shown and have a separate mutator for each static_param call. We could also
    // combine the two, using 3 mutators and 5 params or whatever combination makes sense.
    //
    // i think this strategy is likely to be used more often than a single value, as realistic
    // replacement values can be specified here for when those values are static and not being
    // mutated.
    let mutator1 = ReplaceKeyword::new(&"first-value", "range");
    let mutator2 = ReplaceKeyword::new(&"second-value", "range");
    let mutator3 = ReplaceKeyword::new(&"third-value", "range");
    let mutator4 = ReplaceKeyword::new(&"fourth-value", "range");
    let mutator5 = ReplaceKeyword::new(&"fifth-value", "range");

    let mut request = Request::from_url("http://localhost:8000/", None)?;

    // In order for us to get the same behavior as burp's "sniper" mode, we'll begin by adding our insertion points.
    // What's important here is that we're adding Static insertion points, which differs from normal fuzzing
    // sessions, where the insertion points are Fuzzable. We'll flip the parameters to fuzzable one-by-one later on.
    request.add_static_param(b"injectable=first-value", b"=")?;
    request.add_static_param(b"second=second-value", b"=")?;
    request.add_static_param(b"third=third-value", b"=")?;
    request.add_static_param(b"fourth=fourth-value", b"=")?;
    request.add_static_param(b"fifth=fifth-value", b"=")?;

    let num_positions = 5;

    let scheduler = OrderedScheduler::new(state.clone())?;

    // a RequestProcessor provides a way to inspect each request and decide upon some Action based on the
    // result of the mutation that was performed. In this case, the RequestProcessor doesn't care about
    // checking the mutation, we simply want to print the mutated fields to show how a OrderedScheduler
    // does its work.
    let request_printer = RequestProcessor::new(move |request, _action, _state| {
        print!("{}?", request.original_url());

        for (i, (key, value)) in request.params().unwrap().iter().enumerate() {
            if i == num_positions - 1 {
                print!("{}={}", key, value);
            } else {
                print!("{}={}&", key, value);
            }
        }

        println!();
    });

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let mutators = build_mutators!(mutator1, mutator2, mutator3, mutator4, mutator5);
    let processors = build_processors!(request_printer);

    let mut fuzzer = BlockingFuzzer::new()
        .client(client)
        .request(request)
        .scheduler(scheduler)
        .mutators(mutators)
        .observers(observers)
        .processors(processors)
        .build();

    // our overall strategy is to let the fuzzer run through a full iteration of the corpus/scheduler
    // on each iteration of this outer loop. Within each iteration, we'll also only mark a single
    // position as fuzzable. This is to emulate the behavior of burp's "sniper" mode.
    for position_idx in 0..num_positions {
        // num_positions must match the number of parameters added to the request above
        let params = fuzzer.request_mut().params_mut().unwrap();

        for (param_idx, (_param_key, param_value)) in params.iter_mut().enumerate() {
            if param_value.is_fuzzable() {
                // this check catches the previous fuzzable position and sets it to Static
                param_value.toggle_type();
            }

            if position_idx == param_idx {
                // we've reached the point at which our number of fuzz iterations matches the
                // parameter we want to fuzz. We'll flip the parameter to Fuzzable.
                param_value.toggle_type();
                break;
            }
        }

        // perform a single fuzz session over the corpus
        fuzzer.fuzz_once(&mut state)?;

        println!();
    }

    // example output:
    //
    // http://localhost:8000/?injectable=0&second=second-value&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=1&second=second-value&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=2&second=second-value&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=3&second=second-value&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=4&second=second-value&third=third-value&fourth=fourth-value&fifth=fifth-value
    //
    // http://localhost:8000/?injectable=first-value&second=0&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=1&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=2&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=3&third=third-value&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=4&third=third-value&fourth=fourth-value&fifth=fifth-value
    //
    // http://localhost:8000/?injectable=first-value&second=second-value&third=0&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=1&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=2&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=3&fourth=fourth-value&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=4&fourth=fourth-value&fifth=fifth-value
    //
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=0&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=1&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=2&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=3&fifth=fifth-value
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=4&fifth=fifth-value
    //
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=fourth-value&fifth=0
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=fourth-value&fifth=1
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=fourth-value&fifth=2
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=fourth-value&fifth=3
    // http://localhost:8000/?injectable=first-value&second=second-value&third=third-value&fourth=fourth-value&fifth=4

    Ok(())
}
