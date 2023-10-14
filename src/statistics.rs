//! [`Statistics`] is the primary data container for all [`Request`], [`Response`], and
//! [`Timed`] statistics
//!
//! [`Statistics`]: crate::statistics::Statistics
//! [`Request`]: crate::requests::Request
//! [`Response`]: crate::responses::Response
use std::collections::HashMap;
use std::fmt::Display;
use std::time::Duration;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_json;
use tracing::{error, instrument, warn};

use crate::actions::{Action, FlowControl};
use crate::error::{FeroxFuzzError, RequestErrorKind};
use crate::observers::Observers;
use crate::observers::ResponseObserver;
use crate::requests::{Request, RequestId};
use crate::responses::{Response, Timed};
use crate::std_ext::time::current_time;

/// just used for typesafe calls to [`Statistics::update_actions`]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum RequestOrResponse {
    Request,
    Response,
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
    ///
    /// these errors are not related to status code based errors in the
    /// 400 or 500 range. The errors tracked here reflect things like
    /// network connection errors, timeouts, etc...
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

    /// total number of seconds the scan has run
    ///
    /// this value is a snapshot in time from when `common_updates` was last called
    elapsed: f64,

    /// average number of requests per second
    avg_reqs_per_sec: f64,

    /// tracker for overall number of any status code seen by the client
    statuses: HashMap<u16, usize>,

    /// tracker for overall number of any [`Action`]s performed by the fuzzer
    /// on any [`Request`] or [`Response`]
    ///
    /// [`Action`]: crate::actions::Action
    /// [`Request`]: crate::requests::Request
    /// [`Response`]: crate::responses::Response
    actions: HashMap<String, HashMap<Action, usize>>,
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

    /// get a summary of the [`Action`]s performed by the fuzzer on any
    /// [`Response`]
    ///
    /// [`Action`]: crate::actions::Action
    /// [`Response`]: crate::responses::Response
    #[must_use]
    #[inline]
    pub const fn actions(&self) -> &HashMap<String, HashMap<Action, usize>> {
        &self.actions
    }

    /// Inspect the given status code and increment the appropriate fields
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
                self.client_errors += 1;
            }
            500..=599 => {
                self.server_errors += 1;
            }
            _ => {
                // anything outside 100-599 is invalid
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
    fn update_from_response_observer<O, R>(
        &mut self,
        observers: &O,
        action: Option<&Action>,
    ) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        if let Some(observer) = observers.match_name::<ResponseObserver<R>>("ResponseObserver") {
            self.add_status_code(observer.status_code())?;
            self.update_actions(observer.id(), action, RequestOrResponse::Response);
        }

        Ok(())
    }

    /// given an [`Observers`] object with at least (and probably only) one
    /// [`RequestObserver`], update the appropriate internal [`Action`] tracker
    #[instrument(skip(self), level = "trace")]
    pub(crate) fn update_actions(
        &mut self,
        id: RequestId,
        action: Option<&Action>,
        update_type: RequestOrResponse,
    ) {
        let mut update = |to_update: Action| match update_type {
            RequestOrResponse::Request => {
                *self
                    .actions
                    .entry("request".to_string())
                    .or_default()
                    .entry(to_update)
                    .or_insert(0) += 1;
            }
            RequestOrResponse::Response => {
                *self
                    .actions
                    .entry("response".to_string())
                    .or_default()
                    .entry(to_update)
                    .or_insert(0) += 1;
            }
        };

        match action {
            Some(Action::Keep) => update(Action::Keep),
            Some(Action::Discard) => update(Action::Discard),
            Some(Action::StopFuzzing) => update(Action::StopFuzzing),
            Some(Action::AddToCorpus(corpus_name, corpus_item_type, inner_action)) => {
                match inner_action {
                    FlowControl::Keep => update(Action::Keep),
                    FlowControl::Discard => update(Action::Discard),
                    FlowControl::StopFuzzing => update(Action::StopFuzzing),
                };
                update(Action::AddToCorpus(
                    corpus_name.clone(),
                    corpus_item_type.clone(),
                    *inner_action,
                ));
            }
            None => {} // do nothing
        }
    }

    #[inline]
    fn update_requests_per_second(&mut self) {
        // invariant: self.requests was incremented at least once
        //   prior to this function executing
        self.avg_reqs_per_sec = self.requests / self.elapsed;
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

        self.elapsed = self.elapsed();

        if self.elapsed == 0.0 {
            // set to 0 if checked_sub failed above
            self.avg_reqs_per_sec = 0.0;
        } else {
            self.update_requests_per_second();
        }
    }

    #[instrument(skip_all, level = "trace")]
    pub(crate) fn update<O, R>(
        &mut self,
        observers: &O,
        action: Option<&Action>,
    ) -> Result<(), FeroxFuzzError>
    where
        O: Observers<R>,
        R: Response + Timed,
    {
        // note: if any additional entrypoints are added, the common_updates function must be called
        //       from the new entrypoint (i.e. update and update_from_error)
        self.common_updates();
        self.update_from_response_observer(observers, action)?;

        Ok(())
    }

    #[instrument(skip_all, level = "trace")]
    pub(crate) fn update_from_request(&mut self, request: &Request) {
        // purposefully not calling common_updates here, as those updates aren't relevant to
        // requests
        self.update_actions(request.id(), request.action(), RequestOrResponse::Request);
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

            return Ok(());
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
