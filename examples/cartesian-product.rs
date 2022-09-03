//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example cartesian-product
use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::{RangeCorpus, Wordlist};
use feroxfuzz::fuzzers::BlockingFuzzer;
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::RequestProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::ProductScheduler;

use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create two corpora, one with a set of user names, and one with a range of ids
    // where only even ids are considered
    let users = Wordlist::with_words(["user", "admin"])
        .name("users")
        .build();

    let ids = RangeCorpus::with_stop(10).step(2).name("ids").build()?;

    // associate the user names with the `users` corpus name, and the user ids with the
    // `ids` corpus name
    //
    // i.e. key-value pairs
    let corpora = [ids, users];

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
    let user_mutator = ReplaceKeyword::new(&"USER", "users");
    let id_mutator = ReplaceKeyword::new(&"ID", "ids");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[
            ShouldFuzz::URLParameterValue(b"user=USER", b"="),
            ShouldFuzz::URLParameterValue(b"id=ID", b"="),
        ]),
    )?;

    // a RequestProcessor provides a way to inspect each request and decide upon some Action based on the
    // result of the mutation that was performed. In this case, the RequestProcessor doesn't care about
    // checking the mutation, we simply want to print the mutated fields to show how a ProductScheduler
    // does its work.
    //
    // example output:
    // http://localhost:8000/?user=user&id=0
    // ...
    let request_printer = RequestProcessor::new(|request, _action, _state| {
        print!("{}?", request.original_url());

        for (i, (key, value)) in request.params().unwrap().iter().enumerate() {
            if i == 0 {
                print!("{}={}&", key, value);
            } else {
                print!("{}={}", key, value);
            }
        }
        println!();
    });

    // the ProductScheduler is a scheduler that creates a nested for-loop scheduling pattern.
    // Ordering of the loops is determined by passing the corpus names to the constructor.
    //
    // for this particular example, the order of the corpora is:
    // users -> ids
    //
    // what this means is that the outermost loop will iterate over the users corpus, and the innermost
    // loop will iterate over the ids corpus.
    //
    // the result should produce a product of the following:
    // user1 -> id1
    // user1 -> id2
    // user1 -> id3
    // user1 -> id4
    // user1 -> id5
    // user2 -> id1
    // user2 -> id2
    // user2 -> id3
    // user2 -> id4
    // user2 -> id5
    let order = ["users", "ids"];
    let scheduler = ProductScheduler::new(order, state.clone())?;

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let mutators = build_mutators!(user_mutator, id_mutator);
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

    Ok(())
}
