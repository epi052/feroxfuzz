//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --example dynamic-dispatch
//!
//! this example demonstrates the use of dynamic dispatch to build a mutator at runtime
use feroxfuzz::client::AsyncClient;
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::deciders::StatusCodeDecider;
use feroxfuzz::fuzzers::AsyncFuzzer;
use feroxfuzz::mutators::{Mutator, Mutators, ReplaceKeyword};
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::ResponseProcessor;
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;

// for dynamic dispatch, we need a replace the normal, build_mutators!() result, which
// is known at compile time, with a `Mutators` implementation that works with
// trait objects, i.e. Box<dyn Mutator>. This can be useful when generating mutators
// (or other components) at runtime, for example when reading them from the command line.
//
// we'll use a struct that wraps a `Vec<Box<dyn Mutator>>`
#[derive(Default, Clone)]
struct DynamicMutators {
    inner: Vec<Box<dyn Mutator>>,
}

// as stated above, we'll need to implement the `Mutators` trait for our `DynamicMutators` struct
//
// by implementing this trait, we'll be able to pass our `DynamicMutators` struct into the
// `AsyncFuzzer::new()` method, which expects a `Mutators` implementation
impl Mutators for DynamicMutators {
    fn call_mutate_hooks(
        &mut self,
        state: &mut SharedState,
        request: Request,
    ) -> Result<Request, FeroxFuzzError> {
        // we'll iterate over each mutator in our `Vec<Box<dyn Mutator>>` and call `mutate_fields`
        // on each one
        let mut mutated_req = request;

        for mutator in &mut self.inner {
            mutated_req = mutator.mutate_fields(state, mutated_req)?;
        }

        Ok(mutated_req)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a new corpus from the given list of words
    let words = Wordlist::from_file("./examples/words")?
        .name("words")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpus(words);

    // create a new instance of our `DynamicMutators` struct, at this point, there's nothing in it
    let mut dynamic_mutators = DynamicMutators::default();

    // simulate reading a list of mutators from the command line
    let parse_cli = || 0..3;

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    //
    // ShouldFuzz directives map to the various components of an HTTP request
    //
    // since we're building a mutator at runtime, we should also build the fuzz directives
    // while we're at it
    let mut params = Vec::new();

    for option in parse_cli() {
        // create a new mutator, which will replace the keyword "FUZZ-[0,1,2]" with a random word from the corpus
        let dynamic_keyword = format!("FUZZ-{}", option);
        let mutator = ReplaceKeyword::new(&dynamic_keyword, "words");

        // add the mutator to our `DynamicMutators` struct
        dynamic_mutators.inner.push(Box::new(mutator));

        params.push(match option {
            0 => format!("admin={}", dynamic_keyword),
            1 => format!("password={}", dynamic_keyword),
            2 => format!("domain={}", dynamic_keyword),
            _ => panic!("invalid option"),
        });
    }

    // bring-your-own client, this example uses the reqwest library
    let req_client = reqwest::Client::builder().build()?;

    // with some client that can handle the actual http request/response stuff
    // we can build a feroxfuzz client, specifically an asynchronous client in this
    // instance.
    //
    // feroxfuzz provides both a blocking and an asynchronous client implementation
    // using reqwest.
    let client = AsyncClient::with_client(req_client);

    let request = Request::from_url(
        "http://localhost:8000/",
        Some(
            // iterate over our dynamically generated url parameters from which we'll
            // create our ShouldFuzz directives
            params
                .iter()
                .map(|p| ShouldFuzz::URLParameterValue(p.as_bytes(), b"="))
                .collect::<Vec<ShouldFuzz>>()
                .as_ref(),
        ),
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
    let observers = build_observers!(response_observer);
    let processors = build_processors!(response_printer);

    let threads = 40; // number of threads to use for the fuzzing process

    // the `Fuzzer` is the main component of the feroxfuzz library. It wraps most of the other components
    // and takes care of the actual fuzzing process.
    let mut fuzzer = AsyncFuzzer::new(
        threads,
        client,
        request,
        scheduler,
        dynamic_mutators, // <-- our dynamic mutators
        observers,
        processors,
        deciders,
    );

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state).await?;

    println!("{state:#}");

    // example output:
    //
    // [200] 1771 - http://localhost:8000/?admin=AOL%27s&password=AOL%27s&domain=AOL%27s - 4.052876ms
    // [200] 1175 - http://localhost:8000/?admin=Aberdeen%27s&password=Aberdeen%27s&domain=Aberdeen%27s - 5.642756ms
    // ----8<----
    // [200] 1315 - http://localhost:8000/?admin=zinc&password=zinc&domain=zinc - 3.400925ms
    // [200] 5868 - http://localhost:8000/?admin=zoom&password=zoom&domain=zoom - 2.463408ms
    // SharedState::{
    //   Seed=24301
    //   Rng=RomuDuoJrRand { x_state: 97704, y_state: 403063 }
    //   Corpus[words]=Wordlist::{len=102774, top-3=[Static("A"), Static("A's"), Static("AMD")]},
    //   Statistics={"timeouts":0,"requests":102774.0,"errors":44186,"informatives":3575,"successes":29264,"redirects":25749,"client_errors":18365,"server_errors":25821,"redirection_errors":0,"connection_errors":0,"request_errors":0,"start_time":{"secs":1663421878,"nanos":346777841},"avg_reqs_per_sec":7426.830018881687,"statuses":{"502":3719,"500":14671,"203":3636,"200":3583,"302":3672,"501":3704,"307":3664,"308":3693,"101":3575,"204":3636,"205":3783,"300":3697,"503":3727,"404":3723,"400":3713,"207":3678,"301":3678,"403":3542,"206":3616,"304":3683,"202":3608,"401":3693,"402":3694,"303":3662,"201":3724}}
    // }

    Ok(())
}
