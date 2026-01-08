//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example pitchfork
//!
//! This is a demonstration of how to mimic burp's pitchfork behavior when
//! fuzzing an application.
//!
//! From https://portswigger.net/burp/documentation/desktop/tools/intruder/attack-types
//!
//! Pitchfork uses multiple payload sets. There is a different payload set for each defined position.
//! The attack iterates through all payload sets simultaneously, and places one payload into
//! each defined position. In other words, the first request will place the first payload
//! from payload set 1 into position 1 and the first payload from payload set 2 into position 2;
//! the second request will place the second payload from payload set 1 into position 1 and the
//! second payload from payload set 2 into position 2, etc. This attack type is useful where
//! an attack requires different but related input to be inserted in multiple places within the
//! request (e.g. a username in one parameter, and a known ID number corresponding to that
//! username in another parameter). The total number of requests generated in the attack is the
//! number of payloads in the smallest payload set.

use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::{RangeCorpus, Wordlist};
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
    // each corpus is what burp refers to as a "payload set", for a pitchfork style session, we'll
    // need to create one corpus for each fuzzable position in the request.

    // a Wordlist is a corpus that will iterate over a list of words
    // in this case, we're going to iterate over the words "a", "b", and "c"
    let wordlist = Wordlist::new()
        .word("a")
        .word("b")
        .word("c")
        .name("chars")
        .build();

    // a RangeCorpus is a corpus that will iterate over a range of values
    // in this case, we're going to iterate over the numbers 0-2, stepping
    // by 1
    let range1 = RangeCorpus::new().name("range1").stop(3).build()?;

    // this RangeCorpus will iterate over the numbers 4, 6, and 8
    let range2 = RangeCorpus::new()
        .name("range2")
        .start(4)
        .stop(9)
        .step(2)
        .build()?;

    // pass all corpora to the state object, which will be shared between all of the fuzzers and processors
    let corpora = [range1, wordlist, range2];
    let mut state = SharedState::with_corpora(corpora);

    // byo-client, this example uses reqwest
    let req_client = reqwest::blocking::Client::builder().build()?;

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

    // In order for us to get the same behavior as burp's "pitchfork" mode, all we need to do is to use
    // the OrderedScheduler. OrderedScheduler is a scheduler that schedules one corpus entry for each corpus by
    // placing the first corpus entry in the first position, the second corpus entry in the second position, and so on.
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
    // then the resultant OrderedScheduler scheduling of the two corpora would be:
    //
    // `http://example.com/login?username=user1&password=pass1`
    // `http://example.com/login?username=user2&password=pass2`
    // `http://example.com/login?username=user3&password=pass3`
    let scheduler = OrderedScheduler::new(state.clone())?;

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

    // fuzz_n_iterations means that the fuzzer will iterate over whatever is provided by the scheduler
    // n times. In this case, we're going to iterate over the corpus entries twice.
    fuzzer.fuzz_n_iterations(2, &mut state)?;

    // example output:
    //
    // http://localhost:8000/?injectable=/0/a/4
    // http://localhost:8000/?injectable=/1/b/6
    // http://localhost:8000/?injectable=/2/c/8
    // http://localhost:8000/?injectable=/0/a/4
    // http://localhost:8000/?injectable=/1/b/6
    // http://localhost:8000/?injectable=/2/c/8

    Ok(())
}
