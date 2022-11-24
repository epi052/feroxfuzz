//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --example havoc
use feroxfuzz::actions::{Action, FlowControl};
use feroxfuzz::client::{AsyncClient, HttpClient};
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::deciders::StatusCodeDecider;
use feroxfuzz::events::EventPublisher;
use feroxfuzz::fuzzers::{AsyncFuzzer, AsyncFuzzing};
use feroxfuzz::mutators::HavocMutator;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::ResponseProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a new corpus with a single entry: `{"FUZZ": "JSON"}`
    let corpus = Wordlist::new()
        .word("{\"FUZZ\":\"JSON\"}")
        .name("corpus")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(corpus);

    // the corpus name "corpus" associates the corpus with the mutator; we need to pass the same information
    // to the havoc mutator in order for it to pull from the correct corpus
    let mutator = HavocMutator::new("corpus");

    // seed the state, this replaces the generated seed with a custom one and recreates
    // the random number generator
    state.set_seed(1234567890);

    // byo-client, this example uses reqwest
    let req_client = reqwest::Client::builder().build()?;

    // with some client that can handle the actual http request/response stuff
    // we can build a feroxfuzz client, specifically an asynchronous client in this
    // instance. Because we're using an asynchronous client, there's an implicit
    // opt-in to using the AsyncResponse implementor of the Response trait
    let client = AsyncClient::with_client(req_client);

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[ShouldFuzz::RequestBody(b"{\"FUZZ\":\"JSON\"}")]),
    )?;

    // a StatusCodeDecider provides a way to inspect each response's status code and decide upon some Action
    // based on the result of whatever comparison function is passed to the StatusCodeDecider constructor
    //
    // in plain english, the StatusCodeDecider below will check to see if the request's http response code
    // received is equal to 200/OK. If the response code is 200, then the decider will recommend the Keep
    // action be performed. If the response code is anything other than 200, then the recommendation will
    // be to add the current mutated entry back into the corpus.
    let decider = StatusCodeDecider::new(200, |status, observed, _state| {
        if status == observed {
            // The AddToCorpus action will add the current mutated field(s) to the
            // Corpus named "corpus"
            //
            // the FlowControl passed to the AddToCorpus action is used to
            // embed a Keep or Discard action that will dictate whether the
            // mutated request or response should be allowed to be processed
            // any further, after being added to the corpus.
            //
            // said another way: when the action is AddToCorpus, the current
            // request's fuzzable fields will (unconditionally) be added to the
            // named corpus. If the FlowControl is Keep, the request will continue
            // in the fuzz loop, and if the `FlowControl` is Discard, the request
            // won't progress beyond being added to the corpus. In either case, the
            // resulting `Action` will still be passed to any configured
            // Processors.
            Action::AddToCorpus("corpus".to_string(), FlowControl::Keep)
        } else {
            Action::Discard
        }
    });

    // a `ResponseProcessor` provides access to the fuzzer's instance of `ResponseObserver`
    // as well as the `Action` returned from calling `Deciders` (like the `StatusCodeDecider` above).
    // Those two objects may be used to produce side-effects, such as printing, logging, calling out to
    // some other service, or whatever else you can think of.
    let response_printer = ResponseProcessor::new(
        |response_observer: &ResponseObserver<AsyncResponse>, action, _state| {
            // since we are potentially adding to the corpus, we need to account for the action being
            // both Keep and AddToCorpus (with a FlowControl::Keep)
            if let Some(Action::Keep) | Some(Action::AddToCorpus(_, FlowControl::Keep)) = action {
                println!(
                    "[{}] {} - {} - {:?}",
                    response_observer.status_code(),
                    response_observer.content_length(),
                    response_observer.url(),
                    response_observer.elapsed()
                );
            }
        },
    );

    // `Scheduler`s manage how the fuzzer gets entries from the corpus. The `OrderedScheduler` provides
    // in-order access of the associated `Corpus` (`Wordlist` in this example's case)
    let scheduler = OrderedScheduler::new(state.clone())?;

    // a ResponseObserver is responsible for gathering information from each response and providing
    // that information to later fuzz stages. It knows things like the response's status code, content length,
    // the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<AsyncResponse> = ResponseObserver::new();

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let observers = build_observers!(response_observer);
    let deciders = build_deciders!(decider);
    let mutators = build_mutators!(mutator);
    let processors = build_processors!(response_printer);

    let mut fuzzer = AsyncFuzzer::new(
        40, client, request, scheduler, mutators, observers, processors, deciders,
    );

    state
        .events()
        .subscribe(|event: feroxfuzz::events::FuzzOnce| {
            println!(
                "[FuzzOnce] iterating over corpus of size: {}",
                event.corpora_length
            );
        });

    // fuzz_n_iterations means that the fuzzer will iterate over whatever is provided by the scheduler
    // n times. In this case, we're going to iterate over the corpus entries 200 times. This is to allow
    // the AddToCorpus to increase the corpus and continue running over the new input as it grows.
    fuzzer.fuzz_n_iterations(200, &mut state).await?;

    println!(
        "Final corpus: {}",
        state.corpora().get("corpus").unwrap().read().unwrap()
    );

    // example output:
    //
    // [FuzzOnce] iterating over corpus of size: 1
    // [FuzzOnce] iterating over corpus of size: 1
    // [FuzzOnce] iterating over corpus of size: 1
    // [200] 727 - http://localhost:8000/ - 5.520096ms
    // [FuzzOnce] iterating over corpus of size: 2
    // ...
    // [FuzzOnce] iterating over corpus of size: 1320
    // ...
    // Final corpus: Wordlist::{len=1372, top-3=[Static("{\"FUZZ\":\"JSON\"}"), Fuzzable("Data::{len=8, top-3=[fd, e1, c9]}"), Fuzzable("Data::{len=16, top-3=[da, 1e, 1]}")]}

    // bytes output from the server:
    //
    // [118, 163, 114, 189, 255, 127, 129, 9, 5, 247]
    // [143, 121, 121, 121, 241, 15, 121, 121, 121, 121, 127, 113, 121, 141, 247, 121, 121, 122, 121, 121, 121, 121, 121, 204, 14, 148, 0, 0, 0, 110, 145, 145, 238]
    // [16, 38, 199, 9, 107]
    // [50, 52, 112, 255, 43, 239, 17, 34, 168, 206, 224, 2, 0, 2, 255, 0, 255, 6]

    Ok(())
}
