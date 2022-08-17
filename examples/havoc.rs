//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --example havoc
use feroxfuzz::actions::{Action, FlowControl};
use feroxfuzz::client::{AsyncClient, HttpClient};
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::deciders::StatusCodeDecider;
use feroxfuzz::fuzzers::{AsyncFuzzer, AsyncFuzzing};
use feroxfuzz::mutators::HavocMutator;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::{Ordering, ResponseProcessor, StatisticsProcessor};
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use tracing::subscriber::set_global_default;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::from_default_env();

    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Display source code file paths
        .with_file(true)
        // Display source code line numbers
        .with_line_number(true)
        // Display the thread ID an event was recorded on
        .with_thread_ids(true)
        .with_env_filter(filter)
        // Build the subscriber
        .finish();

    // use that subscriber to process traces emitted after this point
    set_global_default(subscriber)?;

    // create a new corpus from the given range, [0, 20,000)
    // let corpus = RangeCorpus::with_stop(20_000).name("corpus").build()?;
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
    let req_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;

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
    // be to Discard the response.
    let decider = StatusCodeDecider::new(200, |status, observed, _state| {
        if status == observed {
            Action::AddToCorpus("corpus", FlowControl::Keep)
        } else {
            Action::Discard
        }
    });

    let stats_printer =
        StatisticsProcessor::new(Ordering::PostSend, |statistics, _action, _state| {
            if let Ok(guard) = statistics.read() {
                if guard.requests().trunc() % 2500.0 < f64::EPSILON {
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
        |response_observer: &ResponseObserver<AsyncResponse>, action, _state| match action {
            Some(Action::Keep) | Some(Action::AddToCorpus(_, FlowControl::Keep)) => {
                println!(
                    "[{}] {} - {} - {:?}",
                    response_observer.status_code(),
                    response_observer.content_length(),
                    response_observer.url(),
                    response_observer.elapsed()
                );
            }
            _ => {}
        },
    );

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
    let processors = build_processors!(stats_printer, response_printer);

    let mut fuzzer = AsyncFuzzer::new(
        40, client, request, scheduler, mutators, observers, processors, deciders,
    );

    fuzzer.fuzz_n_iterations(3_000, &mut state).await?;

    println!("{state}");

    Ok(())
}
