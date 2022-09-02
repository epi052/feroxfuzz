//! [`Statistics`] is the primary data container for all [`Request`], [`Response`], and
//! [`Timed`] statistics
use std::collections::HashMap;
use std::fmt::Display;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_json;
use tracing::{error, instrument, warn};

use crate::error::{FeroxFuzzError, RequestErrorKind};
use crate::observers::Observers;
use crate::observers::ResponseObserver;
use crate::responses::{Response, Timed};
use crate::std_ext::time::current_time;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(docsrs)] {
        // just bringing in types for easier intra-doc linking during doc build
        use crate::requests::Request;
    }
}

/// fuzzer's tracked statistics
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Statistics {
    /// tracker for number of timeouts seen by the client
    timeouts: usize,

    /// tracker for total number of requests sent by the client
    requests: f64,

    /// tracker for total number of errors encountered by the client
    errors: usize,

    /// tracker for overall number of 1xx status codes seen by the client
    informatives: usize,

    /// tracker for overall number of 2xx status codes seen by the client
    successes: usize,

    /// tracker for overall number of 3xx status codes seen by the client
    redirects: usize,

    /// tracker for overall number of 4xx status codes seen by the client
    client_errors: usize,

    /// tracker for overall number of 5xx status codes seen by the client
    server_errors: usize,

    /// tracker for number of errors triggered by the [`reqwest::redirect::Policy`]
    redirection_errors: usize,

    /// tracker for number of errors related to the connecting
    connection_errors: usize,

    /// tracker for number of errors related to the request used
    request_errors: usize,

    /// tracker for when the fuzzing began
    start_time: Duration,

    /// average number of requests per second
    avg_reqs_per_sec: f64,

    /// tracker for overall number of any status code seen by the client
    statuses: HashMap<u16, usize>,
}

impl Statistics {
    /// create a new default instance of `Statistics`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// get the number of request timeouts
    #[inline]
    #[must_use]
    pub const fn timeouts(&self) -> usize {
        self.timeouts
    }

    /// get the number of requests sent
    #[inline]
    #[must_use]
    pub const fn requests(&self) -> f64 {
        self.requests
    }

    /// get the number of general errors
    #[inline]
    #[must_use]
    pub const fn errors(&self) -> usize {
        self.errors
    }

    /// get the number of informative responses (status code 1XX)
    #[inline]
    #[must_use]
    pub const fn informatives(&self) -> usize {
        self.informatives
    }

    /// get the number of success responses (status code 2XX)
    #[inline]
    #[must_use]
    pub const fn successes(&self) -> usize {
        self.successes
    }

    /// get the number of redirect responses (status code 3XX)
    #[inline]
    #[must_use]
    pub const fn redirects(&self) -> usize {
        self.redirects
    }

    /// get the number of client errors (status code 4XX)
    #[inline]
    #[must_use]
    pub const fn client_errors(&self) -> usize {
        self.client_errors
    }

    /// get the number of server errors (status code 5XX)
    #[inline]
    #[must_use]
    pub const fn server_errors(&self) -> usize {
        self.server_errors
    }

    /// given a status code, return the number of times it was seen by the client
    #[inline]
    #[must_use]
    pub fn status_code_count(&self, status_code: u16) -> Option<usize> {
        self.statuses.get(&status_code).copied()
    }

    /// get the number of errors encountered during redirection (redirect loops etc)
    #[inline]
    #[must_use]
    pub const fn redirection_errors(&self) -> usize {
        self.redirection_errors
    }

    /// get the number of connection errors
    #[inline]
    #[must_use]
    pub const fn connection_errors(&self) -> usize {
        self.connection_errors
    }

    /// get the number of request errors
    #[inline]
    #[must_use]
    pub const fn request_errors(&self) -> usize {
        self.request_errors
    }

    /// get a reference to the fuzzer's start time
    #[inline]
    #[must_use]
    pub const fn start_time(&self) -> &Duration {
        &self.start_time
    }

    /// get the current average number of requests per second
    #[inline]
    #[must_use]
    pub const fn requests_per_sec(&self) -> f64 {
        self.avg_reqs_per_sec
    }

    /// get the number of seconds elapsed since the fuzzer began fuzzing
    #[inline]
    #[must_use]
    pub fn elapsed(&self) -> f64 {
        current_time()
            .checked_sub(self.start_time)
            .map_or_else(|| 0.0, |duration| duration.as_secs_f64())
    }

    /// Inspect the given status code and increment the appropriate fields
    ///
    /// Implies incrementing:
    ///     - appropriate status_* codes
    ///     - errors (when code is [45]xx)
    #[instrument(skip(self), level = "trace")]
    fn add_status_code(&mut self, status: u16) -> Result<(), FeroxFuzzError> {
        match status {
            100..=199 => {
                // informational
                self.informatives += 1;
            }
            200..=299 => {
                // success
                self.successes += 1;
            }
            300..=399 => {
                // redirect
                self.redirects += 1;
            }
            400..=499 => {
                // client error
                self.errors += 1;
                self.client_errors += 1;
            }
            500..=599 => {
                self.errors += 1;
                self.server_errors += 1;
            }
            // anything outside 100-599 is invalid
            _ => {
                error!(%status, "The status code is invalid and couldn't be parsed");

                return Err(FeroxFuzzError::InvalidStatusCode {
                    status_code: status,
                });
            }
        }

        // update the status code counter map
        *self.statuses.entry(status).or_insert(0) += 1;

        Ok(())
    }

    /// given an [`Observers`] object with at least (and probably only) one
    /// [`ResponseObserver`], update the appropriate internal trackers
    #[instrument(skip_all, level = "trace")]
    fn update_from_response_observer<O, R>(&mut self, observers: &O) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        // there's an implicit expectation that there is only a single ResponseObserver in the
        // list of given Observers
        let observer = observers
            .match_name::<ResponseObserver<R>>("ResponseObserver")
            .ok_or_else(|| {
                error!("The given Observers object doesn't have a ResponseObserver");

                FeroxFuzzError::NamedObjectNotFound {
                    name: "ResponseObserver",
                }
            })?;

        self.add_status_code(observer.status_code())?;

        Ok(())
    }

    #[inline]
    fn update_requests_per_second(&mut self, elapsed: f64) {
        // invariant: self.requests was incremented at least once
        //   prior to this function executing
        self.avg_reqs_per_sec = self.requests / elapsed;
    }

    /// update total # of requests and average # of requests per second
    #[inline]
    fn common_updates(&mut self) {
        if self.requests == 0.0 {
            // first response-based update, can set the fuzzer's start time based off of it
            self.start_time = current_time();
        }

        // increment total # of requests
        self.requests += 1.0;

        let elapsed = self.elapsed();

        if elapsed == 0.0 {
            // set to 0 if checked_sub failed above
            self.avg_reqs_per_sec = 0.0;
        } else {
            self.update_requests_per_second(elapsed);
        }
    }

    #[instrument(skip_all, level = "trace")]
    pub(crate) fn update<O, R>(&mut self, observers: &O) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        // note: if any additional entrypoints are added, the common_updates function must be called
        //       from the new entrypoint (i.e. update and update_from_error)
        self.common_updates();
        self.update_from_response_observer(observers)?;

        Ok(())
    }

    /// update the internal trackers from the given error
    ///
    /// expects to receive [`FeroxFuzzError::RequestError`] and no other [`FeroxFuzzError`] variants
    #[instrument(skip(self), level = "trace")]
    pub(crate) fn update_from_error(
        &mut self,
        error: &FeroxFuzzError,
    ) -> Result<(), FeroxFuzzError> {
        self.common_updates();

        if let FeroxFuzzError::RequestError { kind, .. } = error {
            // increment total # of errors, doesn't matter what kind it is
            self.errors += 1;

            match kind {
                RequestErrorKind::Body(status)
                | RequestErrorKind::Decode(status)
                | RequestErrorKind::Request(status) => {
                    if let Some(code) = status {
                        self.add_status_code(*code)?;
                    }

                    self.request_errors += 1;
                }
                RequestErrorKind::Connect(status) => {
                    if let Some(code) = status {
                        self.add_status_code(*code)?;
                    }

                    self.connection_errors += 1;
                }
                RequestErrorKind::Redirect(status) => {
                    if let Some(code) = status {
                        self.add_status_code(*code)?;
                    }

                    self.redirection_errors += 1;
                }
                RequestErrorKind::Timeout(status) => {
                    if let Some(code) = status {
                        self.add_status_code(*code)?;
                    }

                    self.timeouts += 1;
                }
                _ => {
                    warn!(
                        ?kind,
                        "Unknown FeroxFuzzError::RequestError; did not update Statistics"
                    );
                }
            }
        }

        warn!(
            ?error,
            "Expected FeroxFuzzError::RequestError; did not update Statistics"
        );

        Ok(())
    }
}

impl Display for Statistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(feature = "json")]
        return write!(
            f,
            "{}",
            serde_json::to_string(&self).map_err(|_| { std::fmt::Error })?
        );

        #[cfg(not(feature = "json"))]
        return write!(f, "{:?}", self);
    }
}
