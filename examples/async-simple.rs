//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --example async-simple
use feroxfuzz::client::AsyncClient;
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::deciders::StatusCodeDecider;
use feroxfuzz::fuzzers::AsyncFuzzer;
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::ResponseProcessor;
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;

use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a new corpus from the given list of words
    let words = Wordlist::from_file("./examples/words")?
        .name("words")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(words);

    // bring-your-own client, this example uses the reqwest library
    let req_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;

    // with some client that can handle the actual http request/response stuff
    // we can build a feroxfuzz client, specifically an asynchronous client in this
    // instance.
    //
    // feroxfuzz provides both a blocking and an asynchronous client implementation
    // using reqwest.
    let client = AsyncClient::with_client(req_client);

    // ReplaceKeyword mutators operate similar to how ffuf/wfuzz work, in that they'll
    // put the current corpus item wherever the keyword is found, as long as its found
    // in data marked fuzzable (see ShouldFuzz directives below)
    let mutator = ReplaceKeyword::new(&"FUZZ", "words");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    //
    // ShouldFuzz directives map to the various components of an HTTP request
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[ShouldFuzz::URLParameterValue(b"admin=FUZZ", b"=")]),
    )?;

    // a `StatusCodeDecider` provides a way to inspect each response's status code and decide upon some Action
    // based on the result of whatever comparison function (closure) is passed to the StatusCodeDecider's
    // constructor
    //
    // in plain english, the `StatusCodeDecider` below will check to see if the request's http response code
    // received is equal to 200/OK. If the response code is 200, then the decider will recommend the `Keep`
    // action be performed. If the response code is anything other than 200, then the recommendation will
    // be to `Discard` the response.
    //
    // `Keep`ing the response means that the response will be allowed to continue on for further processing
    // later in the fuzz loop.
    let decider = StatusCodeDecider::new(200, |status, observed, _state| {
        if status == observed {
            Action::Keep
        } else {
            Action::Discard
        }
    });

    // a `ResponseObserver` is responsible for gathering information from each response and providing
    // that information to later fuzzing components, like Processors. It knows things like the response's
    // status code, content length, the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<AsyncResponse> = ResponseObserver::new();

    // a `ResponseProcessor` provides access to the fuzzer's instance of `ResponseObserver`
    // as well as the `Action` returned from calling `Deciders` (like the `StatusCodeDecider` above).
    // Those two objects may be used to produce side-effects, such as printing, logging, calling out to
    // some other service, or whatever else you can think of.
    let response_printer = ResponseProcessor::new(
        |response_observer: &ResponseObserver<AsyncResponse>, action, _state| {
            if let Some(inner) = action {
                if matches!(inner, Action::Keep) {
                    println!(
                        "[{}] {} - {} - {:?}",
                        response_observer.status_code(),
                        response_observer.content_length(),
                        response_observer.url(),
                        response_observer.elapsed()
                    );
                }
            }
        },
    );

    // `Scheduler`s manage how the fuzzer gets entries from the corpus. The `OrderedScheduler` provides
    // in-order access of the associated `Corpus` (`Wordlist` in this example's case)
    let scheduler = OrderedScheduler::new(state.clone())?;

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let deciders = build_deciders!(decider);
    let mutators = build_mutators!(mutator);
    let observers = build_observers!(response_observer);
    let processors = build_processors!(response_printer);

    let threads = 40; // number of threads to use for the fuzzing process

    // the `Fuzzer` is the main component of the feroxfuzz library. It wraps most of the other components
    // and takes care of the actual fuzzing process.
    let mut fuzzer = AsyncFuzzer::new(
        threads, client, request, scheduler, mutators, observers, processors, deciders,
    );

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state).await?;

    println!("{state:#?}");

    Ok(())
}
