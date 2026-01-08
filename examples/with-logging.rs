//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! RUST_LOG="hyper=info,trace" cargo run --example with-logging
use feroxfuzz::actions::Action;
use feroxfuzz::client::{AsyncClient, HttpClient};
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::deciders::RequestRegexDecider;
use feroxfuzz::fuzzers::{AsyncFuzzer, AsyncFuzzing};
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::ResponseProcessor;
use feroxfuzz::requests::ShouldFuzz;
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;
use feroxfuzz::state::SharedState;

use tracing::debug;
use tracing::subscriber::set_global_default;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // feroxfuzz utilizes the tracing library to provide structured logging
    //
    // in order to use the tracing library, we need to set a global default subscriber
    //
    // there are multiple ways to configure the tracing subscriber, here we're using the
    // `EnvFilter` subscriber which will read the `RUST_LOG` environment variable, when
    // provided
    //
    // see the comment at the top of this file for an invocation example
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

    // create a new corpus from the given list of words
    let words = Wordlist::from_file("./examples/words")?
        .name("words")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(words);

    // set seed using system entropy; architecture-specific to x86_64
    //
    // when a seed is not provided, feroxfuzz will use a hard-coded default seed of 0x5eed
    state.set_seed(unsafe { std::arch::x86_64::_rdtsc() });

    // byo-client, this example uses reqwest
    let req_client = reqwest::Client::builder().build()?;

    // with some client that can handle the actual http request/response stuff
    // we can build a feroxfuzz client, specifically an asynchronous client in this
    // instance. Because we're using an asynchronous client, there's an implicit
    // opt-in to using the AsyncResponse implementor of the Response trait
    let client = AsyncClient::with_client(req_client);

    // ReplaceKeyword mutators operate similar to how ffuf/wfuzz work, in that they'll
    // put the current corpus item wherever the keyword is found, as long as its found
    // in data marked fuzzable (see ShouldFuzz directives below)
    let mutator = ReplaceKeyword::new(&"FUZZ", "words");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    let request = Request::from_url(
        "http://localhost:8000/",
        Some(&[ShouldFuzz::URLParameterValue(b"admin=FUZZ")]),
    )?;

    // a `RequestRegexDecider` takes a regular expression, compiles it to a `Regex` and then
    // applies it in whatever way is passed via the `comparator` closure.
    //
    // in plain english, the RequestRegexDecider below will compile the given regex, and then
    // check the Request, BEFORE it is sent to the target, to see if the url matches the regex
    //
    // if the url matches "dont-scan-me.com", then the request will never be sent, due to the
    // recommended action of Discard
    let decider = RequestRegexDecider::new("dont-scan-me.com", |regex, request, _state| {
        let url = request.original_url();

        debug!(%url, "checking url against regex");

        if regex.is_match(url.as_bytes()) {
            Action::Discard
        } else {
            Action::Keep
        }
    });

    // a `ResponseProcessor` provides access to the fuzzer's instance of `ResponseObserver`
    // as well as the `Action` returned from calling `Deciders` (like the `StatusCodeDecider` above).
    // Those two objects may be used to produce side-effects, such as printing, logging, calling out to
    // some other service, or whatever else you can think of.
    let response_printer = ResponseProcessor::new(
        |response_observer: &ResponseObserver<AsyncResponse>, _action, _state| {
            println!(
                "[{}] {} - {} - {:?}",
                response_observer.status_code(),
                response_observer.content_length(),
                response_observer.url(),
                response_observer.elapsed()
            );
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

    let mut fuzzer = AsyncFuzzer::new(40)
        .client(client)
        .request(request)
        .scheduler(scheduler)
        .mutators(mutators)
        .observers(observers)
        .processors(processors)
        .deciders(deciders)
        .build();

    // fuzz_n_iterations means that the fuzzer will iterate over whatever is provided by the scheduler
    // n times. In this case, we're going to iterate over the corpus entries twice.
    fuzzer.fuzz_n_iterations(2, &mut state).await?;

    println!("{state:#}");

    // example output:
    //
    // 2022-09-03T20:47:39.468819Z DEBUG ThreadId(01) with_corpus: feroxfuzz::state: src/state.rs:103: created new SharedState seed=24301 num_corpora=1
    // 2022-09-03T20:47:39.566774Z DEBUG ThreadId(01) fuzz_n_iterations{num_iterations=2}:fuzz-loop{self.threads=40 self.post_send_logic=Some(Or) self.pre_send_logic=Some(Or)}: with_logging: examples/with-logging.rs:96: checking url against regex url=http://localhost:8000/
    // [200] 925 - http://localhost:8000/?admin=A - 664.478µs
    // ----8<----
    // SharedState::{
    //   Seed=2270162216501746
    //   Rng=RomuDuoJrRand { x_state: 2270162216444599, y_state: 2270162216106344 }
    //   Corpus[words]=Wordlist::{len=102774, top-3=[Static("A"), Static("A's"), Static("AMD")]},
    //   Statistics={"timeouts":0,"requests":205548.0,"errors":88294,"informatives":7187,"successes":58429,"redirects":51638,"client_errors":36710,"server_errors":51569,"redirection_errors":0,"connection_errors":0,"request_errors":15,"start_time":{"secs":1662238117,"nanos":494784632},"avg_reqs_per_sec":21877.383013539325,"statuses":{"204":7184,"203":7413,"200":7332,"404":7354,"207":7289,"500":29274,"201":7263,"502":7433,"202":7292,"400":7376,"205":7299,"303":7439,"206":7357,"501":7356,"301":7485,"101":7187,"503":7506,"402":7320,"308":7391,"403":7462,"304":7380,"302":7312,"307":7346,"300":7285,"401":7198}}
    // }

    Ok(())
}
