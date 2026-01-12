//! [`Statistics`] is the primary data container for all [`Request`], [`Response`], and
//! [`Timed`] statistics
//!
//! [`Statistics`]: crate::statistics::Statistics
//! [`Request`]: crate::requests::Request
//! [`Response`]: crate::responses::Response
use std::cmp::{Eq, PartialEq};
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::{Add, AddAssign, Sub};
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
    pub elapsed: f64,

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

    /// get a mutable reference to the number of requests sent
    ///
    /// This is primarily useful for pause/resume workflows, or for starting a
    /// [`Scheduler`] from a known offset in its iteration (see scheduler constructors).
    ///
    /// [`Scheduler`]: crate::schedulers::Scheduler
    #[inline]
    #[must_use]
    pub const fn requests_mut(&mut self) -> &mut f64 {
        &mut self.requests
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

    /// get the total number of kept responses
    #[inline]
    #[must_use]
    pub fn kept(&self) -> usize {
        self.actions
            .get("response")
            .and_then(|actions| actions.get(&Action::Keep))
            .copied()
            .unwrap_or(0)
    }

    /// manually start the fuzzer's timer
    ///
    /// this is useful for when the fuzzer is paused and resumed
    /// or for when a `Statistics` object is used outside of a `Fuzzer`
    /// e.g. as a meta-statistics tracker
    #[inline]
    pub fn start_timer(&mut self, offset: f64) {
        let adjustment = Duration::from_secs_f64(offset);
        self.start_time = current_time()
            .checked_sub(adjustment)
            .unwrap_or_else(|| Duration::from_secs_f64(0.0));
        self.elapsed = self.elapsed();
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
                }
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

        // If the request resulted in a StopFuzzing action (directly, or via AddToCorpus with
        // FlowControl::StopFuzzing), refresh the elapsed snapshot so downstream consumers that
        // persist/read `elapsed` as a field get an accurate final value.
        if matches!(request.action(), Some(Action::StopFuzzing))
            || matches!(
                request.action(),
                Some(Action::AddToCorpus(_, _, FlowControl::StopFuzzing))
            )
        {
            self.elapsed = self.elapsed();

            if self.elapsed == 0.0 {
                self.avg_reqs_per_sec = 0.0;
            } else if self.requests > 0.0 {
                self.update_requests_per_second();
            }
        }
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
                RequestErrorKind::Timeout => {
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

impl PartialEq for Statistics {
    fn eq(&self, other: &Self) -> bool {
        self.timeouts == other.timeouts
            && self.requests == other.requests
            && self.errors == other.errors
            && self.informatives == other.informatives
            && self.successes == other.successes
            && self.redirects == other.redirects
            && self.client_errors == other.client_errors
            && self.server_errors == other.server_errors
            && self.redirection_errors == other.redirection_errors
            && self.connection_errors == other.connection_errors
            && self.request_errors == other.request_errors
            && self.start_time == other.start_time
            && self.elapsed == other.elapsed
            && self.avg_reqs_per_sec == other.avg_reqs_per_sec
            && self.statuses == other.statuses
            && self.actions == other.actions
    }
}

impl Eq for Statistics {}

impl Add for Statistics {
    type Output = Self;

    /// add two [`Statistics`] objects together
    ///
    /// does not modify the original objects.
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used
    fn add(self, rhs: Self) -> Self::Output {
        let mut new = self;

        new.timeouts += rhs.timeouts;
        new.requests += rhs.requests;
        new.errors += rhs.errors;
        new.informatives += rhs.informatives;
        new.successes += rhs.successes;
        new.redirects += rhs.redirects;
        new.client_errors += rhs.client_errors;
        new.server_errors += rhs.server_errors;
        new.redirection_errors += rhs.redirection_errors;
        new.connection_errors += rhs.connection_errors;
        new.request_errors += rhs.request_errors;

        // skip start time, it's a point in time, not up for addition

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > new.elapsed {
            new.elapsed = rhs.elapsed;
            new.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        for (status, count) in rhs.statuses {
            *new.statuses.entry(status).or_insert(0) += count;
        }

        for (key, value) in rhs.actions {
            for (action, count) in value {
                *new.actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action)
                    .or_insert(0) += count;
            }
        }

        new
    }
}

impl AddAssign for Statistics {
    /// add two [`Statistics`] objects together, storing the result on the left hand side
    ///
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used
    fn add_assign(&mut self, rhs: Self) {
        self.timeouts += rhs.timeouts;
        self.requests += rhs.requests;
        self.errors += rhs.errors;
        self.informatives += rhs.informatives;
        self.successes += rhs.successes;
        self.redirects += rhs.redirects;
        self.client_errors += rhs.client_errors;
        self.server_errors += rhs.server_errors;
        self.redirection_errors += rhs.redirection_errors;
        self.connection_errors += rhs.connection_errors;
        self.request_errors += rhs.request_errors;

        // skip start time, it's a point in time, not up for addition

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > self.elapsed {
            self.elapsed = rhs.elapsed;
            self.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        for (status, count) in rhs.statuses {
            *self.statuses.entry(status).or_insert(0) += count;
        }

        for (key, value) in rhs.actions {
            for (action, count) in value {
                *self
                    .actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action)
                    .or_insert(0) += count;
            }
        }
    }
}

impl AddAssign<&Self> for Statistics {
    /// add two [`Statistics`] objects together, storing the result on the left hand side
    ///
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used
    fn add_assign(&mut self, rhs: &Self) {
        self.timeouts += rhs.timeouts;
        self.requests += rhs.requests;
        self.errors += rhs.errors;
        self.informatives += rhs.informatives;
        self.successes += rhs.successes;
        self.redirects += rhs.redirects;
        self.client_errors += rhs.client_errors;
        self.server_errors += rhs.server_errors;
        self.redirection_errors += rhs.redirection_errors;
        self.connection_errors += rhs.connection_errors;
        self.request_errors += rhs.request_errors;

        // skip start time, it's a point in time, not up for addition

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > self.elapsed {
            self.elapsed = rhs.elapsed;
            self.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        for (status, count) in &rhs.statuses {
            *self.statuses.entry(*status).or_insert(0) += *count;
        }

        for (key, value) in &rhs.actions {
            for (action, count) in value {
                *self
                    .actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action.clone())
                    .or_insert(0) += *count;
            }
        }
    }
}

impl<'b> AddAssign<&'b Statistics> for &mut Statistics {
    /// add two [`Statistics`] objects together, storing the result on the left hand side
    ///
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used
    fn add_assign(&mut self, rhs: &'b Statistics) {
        self.timeouts += rhs.timeouts;
        self.requests += rhs.requests;
        self.errors += rhs.errors;
        self.informatives += rhs.informatives;
        self.successes += rhs.successes;
        self.redirects += rhs.redirects;
        self.client_errors += rhs.client_errors;
        self.server_errors += rhs.server_errors;
        self.redirection_errors += rhs.redirection_errors;
        self.connection_errors += rhs.connection_errors;
        self.request_errors += rhs.request_errors;

        // skip start time, it's a point in time, not up for addition

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > self.elapsed {
            self.elapsed = rhs.elapsed;
            self.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        for (status, count) in &rhs.statuses {
            *self.statuses.entry(*status).or_insert(0) += *count;
        }

        for (key, value) in &rhs.actions {
            for (action, count) in value {
                *self
                    .actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action.clone())
                    .or_insert(0) += *count;
            }
        }
    }
}

impl Sub for Statistics {
    type Output = Self;

    /// subtract one [`Statistics`] object from another
    ///
    /// does not modify the original objects.
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used.
    /// if the rhs is greater than the lhs, the lhs will saturate at 0 for usize's
    /// and will result in a negative value for f64's
    fn sub(self, rhs: Self) -> Self::Output {
        let mut new = self;

        // usize's
        new.timeouts = new.timeouts.saturating_sub(rhs.timeouts);
        new.errors = new.errors.saturating_sub(rhs.errors);
        new.informatives = new.informatives.saturating_sub(rhs.informatives);
        new.successes = new.successes.saturating_sub(rhs.successes);
        new.redirects = new.redirects.saturating_sub(rhs.redirects);
        new.client_errors = new.client_errors.saturating_sub(rhs.client_errors);
        new.server_errors = new.server_errors.saturating_sub(rhs.server_errors);
        new.redirection_errors = new
            .redirection_errors
            .saturating_sub(rhs.redirection_errors);
        new.connection_errors = new.connection_errors.saturating_sub(rhs.connection_errors);
        new.request_errors = new.request_errors.saturating_sub(rhs.request_errors);

        // skip start time, it's a point in time, not up for subtraction

        for (status, count) in rhs.statuses {
            let value = new.statuses.entry(status).or_insert(0);
            *value = value.saturating_sub(count);
        }

        for (key, value) in rhs.actions {
            for (action, count) in value {
                let value = new
                    .actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action)
                    .or_insert(0);

                *value = value.saturating_sub(count);
            }
        }

        // requests is an f64, but a negative number of requests doesn't make sense
        // so we'll stop at zero when negative
        new.requests -= rhs.requests;

        if new.requests < 0.0 {
            new.requests = 0.0;
        }

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > new.elapsed {
            new.elapsed = rhs.elapsed;
            new.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        new
    }
}

impl<'b> Sub<&'b Statistics> for &Statistics {
    type Output = Statistics;

    /// subtract one [`Statistics`] object from another
    ///
    /// does not modify the original objects.
    /// does not update the start time.
    /// the most recent elapsed time and average requests per second are used.
    /// if the rhs is greater than the lhs, the lhs will saturate at 0 for usize's
    /// and will result in a negative value for f64's
    fn sub(self, rhs: &'b Statistics) -> Self::Output {
        let mut new: Statistics = self.clone();

        // usize's
        new.timeouts = new.timeouts.saturating_sub(rhs.timeouts);
        new.errors = new.errors.saturating_sub(rhs.errors);
        new.informatives = new.informatives.saturating_sub(rhs.informatives);
        new.successes = new.successes.saturating_sub(rhs.successes);
        new.redirects = new.redirects.saturating_sub(rhs.redirects);
        new.client_errors = new.client_errors.saturating_sub(rhs.client_errors);
        new.server_errors = new.server_errors.saturating_sub(rhs.server_errors);
        new.redirection_errors = new
            .redirection_errors
            .saturating_sub(rhs.redirection_errors);
        new.connection_errors = new.connection_errors.saturating_sub(rhs.connection_errors);
        new.request_errors = new.request_errors.saturating_sub(rhs.request_errors);

        // skip start time, it's a point in time, not up for subtraction

        for (status, count) in &rhs.statuses {
            let value = new.statuses.entry(*status).or_insert(0);
            *value = value.saturating_sub(*count);
        }

        for (key, value) in &rhs.actions {
            for (action, count) in value {
                let value = new
                    .actions
                    .entry(key.clone())
                    .or_default()
                    .entry(action.clone())
                    .or_insert(0);

                *value = value.saturating_sub(*count);
            }
        }

        // requests is an f64, but a negative number of requests doesn't make sense
        // so we'll stop at zero when negative
        new.requests -= rhs.requests;

        if new.requests < 0.0 {
            new.requests = 0.0;
        }

        // only update the elapsed time / rps if the rhs is greater
        if rhs.elapsed > new.elapsed {
            new.elapsed = rhs.elapsed;
            new.avg_reqs_per_sec = rhs.avg_reqs_per_sec;
        }

        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test the `Add` implementation for `Statistics`
    #[test]
    fn test_add_two_statistics_structs() {
        let mut stats = Statistics::new();
        let mut stats2 = Statistics::new();
        // actions: HashMap<String, HashMap<Action, usize>>,
        // statuses: HashMap<u16, usize>,

        let mut actions = HashMap::new();
        actions.insert(Action::Keep, 1);
        actions.insert(Action::Discard, 2);
        actions.insert(Action::StopFuzzing, 3);

        let mut outer = HashMap::new();
        outer.insert("request".to_string(), actions);

        let mut statuses = HashMap::new();
        statuses.insert(200, 1);
        statuses.insert(404, 2);

        stats.timeouts = 1;
        stats.requests = 2.0;
        stats.errors = 3;
        stats.informatives = 4;
        stats.successes = 5;
        stats.redirects = 6;
        stats.client_errors = 7;
        stats.server_errors = 8;
        stats.redirection_errors = 9;
        stats.connection_errors = 10;
        stats.request_errors = 11;
        stats.elapsed = 12.0;
        stats.avg_reqs_per_sec = 13.0;
        stats.actions = outer.clone();

        stats2.timeouts = 14;
        stats2.requests = 15.0;
        stats2.errors = 16;
        stats2.informatives = 17;
        stats2.successes = 18;
        stats2.redirects = 19;
        stats2.client_errors = 20;
        stats2.server_errors = 21;
        stats2.redirection_errors = 22;
        stats2.connection_errors = 23;
        stats2.request_errors = 24;
        stats2.elapsed = 25.0;
        stats2.avg_reqs_per_sec = 26.0;
        stats2.statuses = statuses.clone();

        let expected = Statistics {
            timeouts: 15,
            requests: 17.0,
            errors: 19,
            informatives: 21,
            successes: 23,
            redirects: 25,
            client_errors: 27,
            server_errors: 29,
            redirection_errors: 31,
            connection_errors: 33,
            request_errors: 35,
            start_time: Duration::default(),
            elapsed: 25.0,
            avg_reqs_per_sec: 26.0,
            statuses,
            actions: outer,
        };

        let result = stats + stats2;

        assert_eq!(result, expected);
    }

    /// test the `AddAssign` implementation for `Statistics`
    #[test]
    fn test_add_assign_two_statistics_structs() {
        let mut stats = Statistics::new();
        let mut stats2 = Statistics::new();
        // actions: HashMap<String, HashMap<Action, usize>>,
        // statuses: HashMap<u16, usize>,

        let mut actions = HashMap::new();
        actions.insert(Action::Keep, 1);
        actions.insert(Action::Discard, 2);
        actions.insert(Action::StopFuzzing, 3);

        let mut outer = HashMap::new();
        outer.insert("request".to_string(), actions);

        let mut statuses = HashMap::new();
        statuses.insert(200, 1);
        statuses.insert(404, 2);

        stats.timeouts = 1;
        stats.requests = 2.0;
        stats.errors = 3;
        stats.informatives = 4;
        stats.successes = 5;
        stats.redirects = 6;
        stats.client_errors = 7;
        stats.server_errors = 8;
        stats.redirection_errors = 9;
        stats.connection_errors = 10;
        stats.request_errors = 11;
        stats.elapsed = 12.0;
        stats.avg_reqs_per_sec = 13.0;
        stats.actions = outer.clone();

        stats2.timeouts = 14;
        stats2.requests = 15.0;
        stats2.errors = 16;
        stats2.informatives = 17;
        stats2.successes = 18;
        stats2.redirects = 19;
        stats2.client_errors = 20;
        stats2.server_errors = 21;
        stats2.redirection_errors = 22;
        stats2.connection_errors = 23;
        stats2.request_errors = 24;
        stats2.elapsed = 25.0;
        stats2.avg_reqs_per_sec = 26.0;
        stats2.statuses = statuses.clone();

        let expected = Statistics {
            timeouts: 15,
            requests: 17.0,
            errors: 19,
            informatives: 21,
            successes: 23,
            redirects: 25,
            client_errors: 27,
            server_errors: 29,
            redirection_errors: 31,
            connection_errors: 33,
            request_errors: 35,
            start_time: Duration::default(),
            elapsed: 25.0,
            avg_reqs_per_sec: 26.0,
            statuses,
            actions: outer,
        };

        stats += stats2;

        assert_eq!(stats, expected);
    }

    /// test the `Sub` implementation for `Statistics`
    /// when the lhs is greater than the rhs
    #[test]
    fn test_sub_two_statistics_structs_lhs_greater() {
        let mut stats = Statistics::new();
        let mut stats2 = Statistics::new();

        let actions = HashMap::from([(
            "request".to_string(),
            HashMap::from([
                (Action::Keep, 1),
                (Action::Discard, 2),
                (Action::StopFuzzing, 3),
            ]),
        )]);

        let statuses = HashMap::from([(200, 1), (404, 2)]);

        stats.timeouts = 1;
        stats.requests = 2.0;
        stats.errors = 3;
        stats.informatives = 4;
        stats.successes = 5;
        stats.redirects = 6;
        stats.client_errors = 7;
        stats.server_errors = 8;
        stats.redirection_errors = 9;
        stats.connection_errors = 10;
        stats.request_errors = 11;
        stats.elapsed = 12.0;
        stats.avg_reqs_per_sec = 13.0;

        stats2.timeouts = 14;
        stats2.requests = 15.0;
        stats2.errors = 16;
        stats2.informatives = 17;
        stats2.successes = 18;
        stats2.redirects = 19;
        stats2.client_errors = 20;
        stats2.server_errors = 21;
        stats2.redirection_errors = 22;
        stats2.connection_errors = 23;
        stats2.request_errors = 24;
        stats2.elapsed = 25.0;
        stats2.avg_reqs_per_sec = 26.0;
        stats2.actions = actions.clone();
        stats2.statuses = statuses.clone();

        let expected = Statistics {
            timeouts: 13,
            requests: 13.0,
            errors: 13,
            informatives: 13,
            successes: 13,
            redirects: 13,
            client_errors: 13,
            server_errors: 13,
            redirection_errors: 13,
            connection_errors: 13,
            request_errors: 13,
            start_time: Duration::default(),
            elapsed: 25.0,
            avg_reqs_per_sec: 26.0,
            statuses,
            actions,
        };

        let result = stats2 - stats;

        assert_eq!(expected, result);
    }

    /// test the `Sub` implementation for `Statistics`
    /// when the rhs is greater than the lhs
    #[test]
    fn test_sub_two_statistics_structs_rhs_greater() {
        let mut stats = Statistics::new();
        let mut stats2 = Statistics::new();

        let actions = HashMap::from([(
            "request".to_string(),
            HashMap::from([
                (Action::Keep, 1),
                (Action::Discard, 2),
                (Action::StopFuzzing, 3),
            ]),
        )]);

        let expected_actions = HashMap::from([(
            "request".to_string(),
            HashMap::from([
                (Action::Keep, 0),
                (Action::Discard, 0),
                (Action::StopFuzzing, 0),
            ]),
        )]);

        let statuses = HashMap::from([(200, 1), (404, 2)]);
        let expected_statuses = HashMap::from([(200, 0), (404, 0)]);

        stats.timeouts = 1;
        stats.requests = 2.0;
        stats.errors = 3;
        stats.informatives = 4;
        stats.successes = 5;
        stats.redirects = 6;
        stats.client_errors = 7;
        stats.server_errors = 8;
        stats.redirection_errors = 9;
        stats.connection_errors = 10;
        stats.request_errors = 11;
        stats.elapsed = 12.0;
        stats.avg_reqs_per_sec = 13.0;

        stats2.timeouts = 14;
        stats2.requests = 15.0;
        stats2.errors = 16;
        stats2.informatives = 17;
        stats2.successes = 18;
        stats2.redirects = 19;
        stats2.client_errors = 20;
        stats2.server_errors = 21;
        stats2.redirection_errors = 22;
        stats2.connection_errors = 23;
        stats2.request_errors = 24;
        stats2.elapsed = 25.0;
        stats2.avg_reqs_per_sec = 26.0;
        stats2.actions = actions;
        stats2.statuses = statuses;

        let expected = Statistics {
            timeouts: 0,
            requests: 0.0,
            errors: 0,
            informatives: 0,
            successes: 0,
            redirects: 0,
            client_errors: 0,
            server_errors: 0,
            redirection_errors: 0,
            connection_errors: 0,
            request_errors: 0,
            start_time: Duration::default(),
            elapsed: 25.0,
            avg_reqs_per_sec: 26.0,
            statuses: expected_statuses,
            actions: expected_actions,
        };

        let result = stats - stats2;

        assert_eq!(expected, result);
    }

    /// test that a `Statistics.actions` map can include an `AddToCorpus` action and then be serialized using `serde_json`
    ///
    /// Note: This test is currently disabled because `serde_json` requires `HashMap` keys to be strings,
    /// but `Action` is an enum. This would require custom serialization logic to fix.
    #[cfg(feature = "serde")]
    #[test]
    #[ignore = "serde_json requires HashMap keys to be strings; Action is an enum"]
    fn test_add_to_corpus_action_serialization() {
        let mut stats = Statistics::new();

        let mut actions = HashMap::new();
        actions.insert(Action::Keep, 1);
        actions.insert(Action::Discard, 2);
        actions.insert(Action::StopFuzzing, 3);
        actions.insert(
            Action::AddToCorpus(
                "corpus_name".to_string(),
                crate::corpora::CorpusItemType::LotsOfData(vec!["data".into()]),
                FlowControl::Keep,
            ),
            4,
        );

        let mut outer = HashMap::new();
        outer.insert("response".to_string(), actions);

        stats.actions = outer;

        let json = serde_json::to_string(&stats).unwrap();

        let expected = r#"{"timeouts":0,"requests":0.0,"errors":0,"informatives":0,"successes":0,"redirects":0,"client_errors":0,"server_errors":0,"redirection_errors":0,"connection_errors":0,"request_errors":0,"start_time":"0","elapsed":0.0,"avg_reqs_per_sec":0.0,"statuses":{},"actions":{"request":{"Keep":1,"Discard":2,"StopFuzzing":3,"AddToCorpus":{"corpus_name":"corpus_name","corpus_item_type":"corpus_item_type","inner_action":"Keep"}}}}"#;

        assert_eq!(json, expected);
    }
}
