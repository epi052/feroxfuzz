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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a new corpus from the given list of words
    let words = Wordlist::from_file("./examples/words")?
        .name("words")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(words);

    // bring-your-own client, this example uses the reqwest library
    let req_client = reqwest::Client::builder().build()?;

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
        Some(&[ShouldFuzz::URLParameterValue(b"admin=FUZZ")]),
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
            if let Some(Action::Keep) = action {
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
    let mut fuzzer = AsyncFuzzer::new(threads)
        .client(client)
        .request(request)
        .scheduler(scheduler)
        .mutators(mutators)
        .observers(observers)
        .processors(processors)
        .deciders(deciders)
        .post_loop_hook(|state| {
            println!("\n•*´¨`*•.¸¸.•* Finished fuzzing loop •*´¨`*•.¸¸.•*\n");
            println!("{state:#}");
        })
        .build();

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state).await?;

    // example output:
    //
    // [200] 913 - http://localhost:8000/?admin=AMD - 1.934845ms
    // [200] 358 - http://localhost:8000/?admin=Abernathy - 1.009332ms
    // ----8<----
    // [200] 971 - http://localhost:8000/?admin=zoological - 1.595993ms
    // [200] 664 - http://localhost:8000/?admin=zoology%27s - 1.700941ms
    //
    // •*´¨`*•.¸¸.•* Finished fuzzing loop •*´¨`*•.¸¸.•*
    //
    // SharedState::{
    //   Seed=24301
    //   Rng=RomuDuoJrRand { x_state: 97704, y_state: 403063 }
    //   Corpus[words]=Wordlist::{len=102774, top-3=[Static("A"), Static("A's"), Static("AMD")]},
    //   Statistics={"timeouts":0,"requests":102774.0,"errors":44271,"informatives":3655,"successes":29227,"redirects":25621,"client_errors":18463,"server_errors":25799,"redirection_errors":0,"connection_errors":0,"request_errors":9,"start_time":{"secs":1662238251,"nanos":930684935},"avg_reqs_per_sec":32317.09277101265,"statuses":{"402":3702,"404":3683,"200":3716,"303":3725,"304":3697,"204":3632,"502":3813,"205":3638,"300":3576,"400":3794,"101":3655,"401":3647,"308":3705,"202":3664,"207":3634,"301":3604,"206":3646,"302":3600,"201":3717,"307":3714,"500":14674,"203":3580,"503":3653,"501":3659,"403":3637}}
    // }

    Ok(())
}
