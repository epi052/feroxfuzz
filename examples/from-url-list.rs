//! first, update the variable named target with a valid url to scan
//!
//! then run the example with the following command
//! cargo run --example from-url-list
use feroxfuzz::client::AsyncClient;
use feroxfuzz::corpora::Wordlist;
use feroxfuzz::fuzzers::AsyncFuzzer;
use feroxfuzz::mutators::ReplaceKeyword;
use feroxfuzz::observers::ResponseObserver;
use feroxfuzz::prelude::*;
use feroxfuzz::processors::{RequestProcessor, ResponseProcessor};
use feroxfuzz::responses::AsyncResponse;
use feroxfuzz::schedulers::OrderedScheduler;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // pretend that we have some code that converts
    //
    // http://google.com:80       <-- schemes[0], hosts[0], ports[0]
    // https://google.com:443     <-- schemes[1], hosts[1], ports[1]
    // http://localhost:9999      <-- schemes[2], hosts[2], ports[2]
    // https://localhost:9999     <-- schemes[3], hosts[3], ports[3]
    //
    // into the following three wordlists
    let schemes = Wordlist::new()
        .words(["http", "https", "http", "https"])
        .name("schemes")
        .build();

    let hosts = Wordlist::new()
        .words(["google.com", "google.com", "localhost", "localhost"])
        .name("hosts")
        .build();

    let ports = Wordlist::new()
        .words(["80", "443", "9999", "9999"])
        .name("ports")
        .build();

    // pass the corpus to the state object, which will be shared between all of the fuzzers and processors
    let mut state = SharedState::with_corpora([schemes, hosts, ports]);

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
    let scheme_mutator = ReplaceKeyword::new(&"FUZZ_SCHEME", "schemes");
    let host_mutator = ReplaceKeyword::new(&"FUZZ_HOST", "hosts");
    let port_mutator = ReplaceKeyword::new(&"FUZZ_PORT", "ports");

    // fuzz directives control which parts of the request should be fuzzed
    // anything not marked fuzzable is considered to be static and won't be mutated
    //
    // ShouldFuzz directives map to the various components of an HTTP request
    let request = Request::from_url(
        "FUZZ_SCHEME://FUZZ_HOST:FUZZ_PORT",
        Some(&[
            ShouldFuzz::URLHost,
            ShouldFuzz::URLPort,
            ShouldFuzz::URLScheme,
        ]),
    )?;

    // a `ResponseObserver` is responsible for gathering information from each response and providing
    // that information to later fuzzing components, like Processors. It knows things like the response's
    // status code, content length, the time it took to receive the response, and a bunch of other stuff.
    let response_observer: ResponseObserver<AsyncResponse> = ResponseObserver::new();

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

    // a `RequestProcessor` provides access to the fuzzer's mutated `Request` that is about to be
    // sent to the target, as well as the `Action` returned from calling `Deciders` (like the
    // `StatusCodeDecider` above). Those two objects may be used to produce side-effects, such as
    // printing, logging, calling out to some other service, or whatever else you can think of.
    let request_printer = RequestProcessor::new(|request, _action, _state| {
        println!("Built request: {}", request.url_to_string().unwrap());
    });

    // `Scheduler`s manage how the fuzzer gets entries from the corpus. The `OrderedScheduler` provides
    // in-order access of the associated `Corpus` (`Wordlist` in this example's case)
    let scheduler = OrderedScheduler::new(state.clone())?;

    // the macro calls below are essentially boilerplate. Whatever observers, deciders, mutators,
    // and processors you want to use, you simply pass them to the appropriate macro call and
    // eventually to the Fuzzer constructor.
    let mutators = build_mutators!(scheme_mutator, host_mutator, port_mutator);
    let observers = build_observers!(response_observer);
    let processors = build_processors!(request_printer, response_printer);

    let threads = 40; // number of threads to use for the fuzzing process

    // the `Fuzzer` is the main component of the feroxfuzz library. It wraps most of the other components
    // and takes care of the actual fuzzing process.
    let mut fuzzer = AsyncFuzzer::new(
        threads,
        client,
        request,
        scheduler,
        mutators,
        observers,
        processors,
        (), // no deciders
    );

    // the fuzzer will run until it iterates over the entire corpus once
    fuzzer.fuzz_once(&mut state).await?;

    println!("{state:#}");

    // example output:
    //
    // Built request: http://google.com:80
    // Built request: https://google.com:443
    // Built request: http://localhost:9999
    // Built request: https://localhost:9999
    // [200] 922 - http://localhost:9999/ - 23.310749ms
    // [200] 54709 - http://www.google.com/ - 216.350722ms
    // [200] 54738 - https://www.google.com/ - 223.503601ms
    // SharedState::{
    //   Seed=24301
    //   Rng=RomuDuoJrRand { x_state: 97704, y_state: 403063 }
    //   Corpus[schemes]=Wordlist::{len=4, top-3=[Static("http"), Static("https"), Static("http")]},
    //   Corpus[hosts]=Wordlist::{len=4, top-3=[Static("google.com"), Static("google.com"), Static("localhost")]},
    //   Corpus[ports]=Wordlist::{len=4, top-3=[Static("80"), Static("443"), Static("9999")]},
    //   Statistics={"timeouts":0,"requests":4.0,"errors":1,"informatives":0,"successes":3,"redirects":0,"client_errors":0,"server_errors":0,"redirection_errors":0,"connection_errors":1,"request_errors":0,"start_time":{"secs":1665525829,"nanos":48677016},"avg_reqs_per_sec":15.911714551924089,"statuses":{"200":3}}
    // }

    Ok(())
}
