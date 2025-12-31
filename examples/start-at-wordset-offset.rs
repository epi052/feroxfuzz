//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example start-at-wordset-offset
//!
//! This is a demonstration of how to begin a scan from an offset in a wordlist corpus.
use std::time::Duration;

use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::fuzzers::{BlockingFuzzer, BlockingFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::RequestProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a corpus with 9 items
    let wordlist = Wordlist::new()
        .name("corpus")
        .words([
            "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        ])
        .build();

    let mut state = SharedState::with_corpus(wordlist);
    // The schedulers use Statistics.requests() as the "current iteration offset" when they
    // are constructed (to support resume-from). We can use that to start the scan at a
    // desired offset.
    //
    // Start at offset 3 (0-based), i.e. "four"
    if let Ok(mut guard) = state.stats().write() {
        *guard.requests_mut() = 3.0;
    }

    let scheduler = OrderedScheduler::new(state.clone())?;

    //
    //
    //
    // ---
    // stuff that doesn't matter for this example, but is required to build a fuzzer
    // ---
    let req_client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let client = BlockingClient::with_client(req_client);
    let mutator = ReplaceKeyword::new(&"FUZZ", "corpus");
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[ShouldFuzz::URLParameterValue(b"injectable=/FUZZ", b"=")]),
    )?;
    let request_printer = RequestProcessor::new(|request, _action, _state| {
        print!("{}?", request.original_url());
        for (key, value) in request.params().unwrap().iter() {
            print!("{key}={value}");
        }
        println!();
    });
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();
    let observers = build_observers!(response_observer);
    let mutators = build_mutators!(mutator);
    let processors = build_processors!(request_printer);
    let mut fuzzer = BlockingFuzzer::new()
        .client(client)
        .request(request)
        .scheduler(scheduler)
        .mutators(mutators)
        .observers(observers)
        .processors(processors)
        .build();
    fuzzer.fuzz_once(&mut state)?;
    Ok(())
}
