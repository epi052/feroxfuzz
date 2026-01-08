//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example cluster-bomb
//!
//! This is a demonstration of how to mimic burp's cluster bomb behavior when
//! fuzzing an application.
//!
//! From https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types
//!
//! Cluster Bomb uses multiple payload sets. There is a different payload set for each defined position.
//! The attack iterates through each payload set in turn, so that all permutations of payload
//! combinations are tested. I.e., if there are two payload positions, the attack will place the
//! first payload from payload set 2 into position 2, and iterate through all the payloads in
//! payload set 1 in position 1; it will then place the second payload from payload set 2 into
//! position 2, and iterate through all the payloads in payload set 1 in position 1. This
//! attack type is useful where an attack requires different and unrelated or unknown input to be
//! inserted in multiple places within the request (e.g. when guessing credentials, a username
//! in one parameter, and a password in another parameter). The total number of requests generated
//! in the attack is the product of the number of payloads in all defined payload sets - this may
//! be extremely large.
use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::{RangeCorpus, Wordlist};
use feroxfuzz::fuzzers::{BlockingFuzzer, BlockingFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::RequestProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::ProductScheduler;
use feroxfuzz::state::SharedState;

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create three corpora, each one with 3 items, this will result in 27 total requests
    let wordlist = Wordlist::new()
        .word("a")
        .word("b")
        .word("c")
        .name("chars")
        .build();

    // 0, 1, 2
    let range1 = RangeCorpus::new().name("range1").stop(3).build()?;

    // 4, 6, 8
    let range2 = RangeCorpus::new()
        .name("range2")
        .start(4)
        .stop(9)
        .step(2)
        .build()?;

    let corpora = [range1, wordlist, range2];

    let mut state = SharedState::with_corpora(corpora);

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
        )]),
    )?;

    // In order for us to get the same behavior as burp's "cluster bomb" mode, all we need to do is to use
    // the ProductScheduler. ProductScheduler is a scheduler that schedules corpus entries in a way that
    // mostly boils down to nested for loops (cartesian product, etc...)
    //
    // if you have two corpora with the following entries:
    //
    // FUZZ_USER: ["user1", "user2", "user3"]
    // FUZZ_PASS: ["pass1", "pass2", "pass3"]
    //
    // and a fuzzable url defined as
    //
    // `http://example.com/login?username=FUZZ_USER&password=FUZZ_PASS`
    //
    // then the resultant ProductScheduler scheduling of the two corpora would be:
    //
    // `http://example.com/login?username=user1&password=pass1`
    // `http://example.com/login?username=user1&password=pass2`
    // `http://example.com/login?username=user1&password=pass3`
    // `http://example.com/login?username=user2&password=pass1`
    // `http://example.com/login?username=user2&password=pass2`
    // `http://example.com/login?username=user2&password=pass3`
    // `http://example.com/login?username=user3&password=pass1`
    // `http://example.com/login?username=user3&password=pass2`
    // `http://example.com/login?username=user3&password=pass3`
    //
    // of note: to truly emulate burp's cluster bomb behavior, we have to flip the order of the corpora.
    // The ProductScheduler's ordering is such that the zeroth corpus is considered the outermost loop,
    // and therefore, iterates at the slowest rate. This is the opposite of how burp's cluster bomb works.
    // Burp's cluster bomb works by iterating the payload set at position one at the fastest rate.
    let scheduler = ProductScheduler::new(["range2", "chars", "range1"], state.clone())?;

    // a RequestProcessor provides a way to inspect each request and decide upon some Action based on the
    // result of the mutation that was performed. In this case, the RequestProcessor doesn't care about
    // checking the mutation, we simply want to print the mutated fields to show how a OrderedScheduler
    // does its work.
    let request_printer = RequestProcessor::new(|request, _action, _state| {
        print!("{}?", request.original_url());

        for (key, value) in request.params().unwrap().iter() {
            print!("{key}={value}");
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
    let mutators = build_mutators!(mutator1, mutator2, mutator3);
    let processors = build_processors!(request_printer);

    let mut fuzzer = BlockingFuzzer::new()
        .client(client)
        .request(request)
        .scheduler(scheduler)
        .mutators(mutators)
        .observers(observers)
        .processors(processors)
        .build();

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state)?;

    Ok(())
}
