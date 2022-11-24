//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --features blocking --example blocking-regex
use feroxfuzz::actions::Action;
use feroxfuzz::client::{BlockingClient, HttpClient};
use feroxfuzz::corpora::{RangeCorpus, Wordlist};
use feroxfuzz::deciders::ResponseRegexDecider;
use feroxfuzz::fuzzers::{BlockingFuzzer, BlockingFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::ResponseProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::BlockingResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let corpora = [
        // a RangeCorpus is a corpus that will iterate over a range of values
        // in this case, we're going to iterate over the numbers 0-2, stepping
        // by 1
        RangeCorpus::new().name("range1").stop(3).build()?,
        // a Wordlist is a corpus that will iterate over a list of words
        // in this case, we're going to iterate over the words "a", "b", and "c"
        Wordlist::with_words(["a", "b", "c"]).name("chars").build(),
        // this RangeCorpus will iterate over the numbers 4-6
        RangeCorpus::new().name("range2").start(4).stop(7).build()?,
    ];

    // pass all corpora to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpora(corpora);

    // `Scheduler`s manage how the fuzzer gets entries from the corpora. The `OrderedScheduler` provides
    // in-order access of the associated corpora. The ordered scheduler will schedule the same index for
    // each provided corpus at the same time.
    //
    // In this case, the scheduled corpus entries will be
    //   index 0: 0, a, 4
    //   index 1: 1, b, 5
    //   index 2: 2, c, 6
    let scheduler = OrderedScheduler::new(state.clone())?;

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

    // a ResponseRegexDecider provides a way to inspect the response body and decide upon some Action
    // based on the result of whatever comparison function is passed to the ResponseRegexDecider constructor
    //
    // in plain english, the ResponseRegexDecider below will check to see if the response body contains a
    // string that matches the regex "[dD][eE][rR][pP]". If the response body contains the string "derp" or
    // some variation, then the decider will recommend the Discard action be performed. If the response body
    // does not contain the string "derp", then the recommendation will be to Keep the response.
    let body_decider = ResponseRegexDecider::new("[dD][eE][rR][pP]", |regex, observer, _state| {
        if regex.is_match(observer.body()) {
            Action::Discard
        } else {
            Action::Keep
        }
    });

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<BlockingResponse> = ResponseObserver::new();

    // a `ResponseProcessor` provides access to the fuzzer's instance of `ResponseObserver`
    // as well as the `Action` returned from calling `Deciders` (like the `StatusCodeDecider` above).
    // Those two objects may be used to produce side-effects, such as printing, logging, calling out to
    // some other service, or whatever else you can think of.
    let response_printer = ResponseProcessor::new(
        |response_observer: &ResponseObserver<BlockingResponse>, action, _state| {
            if let Some(Action::Keep) = action {
                println!(
                    "[{}] {} - {} - {:?}",
                    response_observer.status_code(),
                    response_observer.content_length(),
                    response_observer.url(),
                    response_observer.elapsed(),
                );
            }
        },
    );

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let deciders = build_deciders!(body_decider);
    let mutators = build_mutators!(mutator1, mutator2, mutator3);
    let processors = build_processors!(response_printer);

    let mut fuzzer = BlockingFuzzer::new(
        client, request, scheduler, mutators, observers, processors, deciders,
    );

    // fuzz_n_iterations means that the fuzzer will iterate over whatever is provided by the scheduler
    // n times. In this case, we're going to iterate over the corpus entries twice.
    fuzzer.fuzz_n_iterations(2, &mut state)?;

    println!("{:?}", state);

    // example output:
    //
    // [500] 0 - http://localhost:8000/?injectable=/0/a/4 - 1.223366ms
    // [302] 603 - http://localhost:8000/?injectable=/1/b/5 - 981.827µs
    // [500] 675 - http://localhost:8000/?injectable=/2/c/6 - 439.846µs
    // [403] 302 - http://localhost:8000/?injectable=/0/a/4 - 437.268µs
    // [500] 717 - http://localhost:8000/?injectable=/1/b/5 - 477.585µs
    // [207] 292 - http://localhost:8000/?injectable=/2/c/6 - 418.939µs

    Ok(())
}
