//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example battering-ram
//!
//! This is a demonstration of how to mimic burp's battering ram behavior when
//! fuzzing an application.
//!
//! From https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types
//!
//! Battering Ram uses a single set of payloads. It iterates through the payloads, and places the same
//! payload into all of the defined payload positions at once. This attack type is useful
//! where an attack requires the same input to be inserted in multiple places within the
//! request (e.g. a username within a Cookie and a body parameter). The total number of requests
//! generated in the attack is the number of payloads in the payload set.
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

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // recall that burp's battering ram uses a single corpus (payload set).
    let wordlist = Wordlist::from_file("./examples/words")?
        .name("words")
        .build();

    let mut state = SharedState::with_corpus(wordlist);

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
    let mutator = ReplaceKeyword::new(&"WORD", "words");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[
            ShouldFuzz::URLParameterValue(b"injectable=/home/WORD/.ssh/id_rsa", b"="),
            ShouldFuzz::HeaderValue(b"x-injected-for: WORD", b": "),
        ]),
    )?;

    // In order for us to get the same behavior as burp's "battering ram" mode, all we need to do is to use
    // the OrderedScheduler. OrderedScheduler is a scheduler that schedules one corpus entry for each corpus by
    // placing the first corpus entry in the first position, the second corpus entry in the second position, and so on.
    //
    // if you have a single corpus and multiple fuzzable fields using the same replacement keyword, as we setup above,
    // you're left with a request that is mutated the same way in multiple places. Given the corpus below
    //
    // FUZZ_WORD: ["word1", "word2", "word3"]
    //
    // and a fuzzable url defined as
    //
    // `http://example.com/login?stuff=FUZZ_WORD&things=FUZZ_WORD`
    //
    // then the resultant OrderedScheduler scheduling of the corpus would be:
    //
    // `http://example.com/login?stuff=word1&things=word1`
    // `http://example.com/login?stuff=word2&things=word2`
    // `http://example.com/login?stuff=word3&things=word3`
    let scheduler = OrderedScheduler::new(state.clone())?;

    // a RequestProcessor provides a way to inspect each request and decide upon some Action based on the
    // result of the mutation that was performed. In this case, the RequestProcessor doesn't care about
    // checking the mutation, we simply want to print the mutated fields to show how a OrderedScheduler
    // does its work.
    let request_printer = RequestProcessor::new(|request, _action, _state| {
        print!("{}?", request.original_url());

        for (key, value) in request.params().unwrap().iter() {
            print!("{}={}", key, value);
        }

        println!();

        for (key, value) in request.headers().unwrap().iter() {
            println!("   {}: {}", key, value);
        }
    });

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let mutators = build_mutators!(mutator);
    let processors = build_processors!(request_printer);

    let mut fuzzer = BlockingFuzzer::new(
        client,
        request,
        scheduler,
        mutators,
        observers,
        processors,
        (), // since we didn't use any Deciders, we just pass in ()
    );

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state)?;

    // example output:
    //
    // http://localhost:8000/?injectable=/home/A/.ssh/id_rsa
    //    x-injected-for: A
    // http://localhost:8000/?injectable=/home/A's/.ssh/id_rsa
    //    x-injected-for: A's
    // http://localhost:8000/?injectable=/home/AMD/.ssh/id_rsa
    //    x-injected-for: AMD
    // ----8<----

    Ok(())
}
