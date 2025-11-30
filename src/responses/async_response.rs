use super::{Response, Timed};

use crate::actions::Action;
use crate::error::FeroxFuzzError;
use crate::requests::{Request, RequestId};
use crate::std_ext::str::ASCII_WHITESPACE;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

use tracing::{error, instrument};

/// feroxfuzz implementation of [`Response`] that extends [`reqwest::Response`]
/// for additional functionality
#[derive(Clone, Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[non_exhaustive]
pub struct AsyncResponse {
    status_code: u16,
    headers: HashMap<String, Vec<u8>>,
    elapsed: Duration,
    content_length: usize,
    line_count: usize,
    word_count: usize,
    action: Option<Action>,
    request: Request,

    #[cfg_attr(all(not(feature = "serialize-body"), feature = "serde"), serde(skip))]
    body: Vec<u8>,
}

impl AsyncResponse {
    /// Create a new `AsyncResponse` object
    pub fn new(status_code: u16, body: Vec<u8>) -> Self {
        let content_length = body.len();
        let line_count = body
            .split(|byte| byte == &b'\n')
            .filter(|s| !s.is_empty())
            .count();
        let word_count = if body.is_empty() {
            0
        } else {
            body.split(|byte| ASCII_WHITESPACE.contains(byte))
                .filter(|s| !s.is_empty())
                .count()
        };

        Self {
            status_code,
            headers: HashMap::new(),
            elapsed: Duration::default(),
            content_length,
            line_count,
            word_count,
            action: None,
            request: Request::default(),
            body,
        }
    }

    /// get the original url (pre-parse/raw) of the request that generated this response
    #[must_use]
    #[inline]
    pub fn original_url(&self) -> &str {
        self.request.original_url()
    }

    /// Create a `Response` object from a [`RequestId`], [`reqwest::Response`], and [`Duration`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use http::response;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use reqwest::StatusCode;
    /// # use std::borrow::Cow;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Response::new("hello world");
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// // should be the actual request that generated the reqwest_response
    /// let request = Request::default();
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(request, reqwest_response.into(), elapsed).await?;
    ///  
    /// assert_eq!(response.id(), 0);
    /// assert_eq!(response.status_code(), StatusCode::OK);
    /// assert_eq!(response.content_length(), 11);
    /// assert_eq!(response.content(), Some(b"hello world".as_ref()));
    /// assert_eq!(response.text(), Cow::from("hello world"));
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This function returns an error if there is a problem while reading the
    /// response body
    #[instrument(skip(resp, elapsed), level = "trace")]
    pub async fn try_from_reqwest_response(
        request: Request,
        resp: reqwest::Response,
        elapsed: Duration,
    ) -> Result<Self, FeroxFuzzError> {
        let mut request = request;

        if request.url_is_fuzzable() {
            // when building out the reqwest request, the reqwest::builder produces a
            // Url based on the feroxfuzz::Request's mutated fields. prior to that
            // call to builder, the feroxfuzz::Request's url is the original url
            //
            // since this only matters when a part of the url is fuzzable, we
            // hide the clone behind that logic
            request.parsed_url = resp.url().clone();
        }

        let status_code = resp.status().as_u16();

        let headers = resp
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();

        let body = resp.bytes().await.map_err(|source| {
            error!(?source, "could not read response body");
            FeroxFuzzError::ResponseReadError { source }
        })?;

        let content_length = body.len();

        let line_count = body
            .as_ref()
            .split(|byte| byte == &b'\n')
            .filter(|s| !s.is_empty())
            .count();

        let word_count = if body.is_empty() {
            0
        } else {
            body.as_ref()
                .split(|byte| ASCII_WHITESPACE.contains(byte))
                .filter(|s| !s.is_empty())
                .count()
        };

        let body = body.as_ref().to_vec();

        Ok(Self {
            status_code,
            headers,
            elapsed,
            content_length,
            line_count,
            word_count,
            action: None,
            request,
            body,
        })
    }

    /// get a mutable reference to the id
    #[must_use]
    #[inline]
    pub fn id_mut(&mut self) -> &mut RequestId {
        self.request.id_mut()
    }

    /// get a mutable reference to the headers
    #[must_use]
    #[inline]
    pub fn headers_mut(&mut self) -> &mut HashMap<String, Vec<u8>> {
        &mut self.headers
    }
}

impl Response for AsyncResponse {
    fn id(&self) -> RequestId {
        self.request.id()
    }

    fn url(&self) -> &Url {
        self.request.parsed_url()
    }

    fn status_code(&self) -> u16 {
        self.status_code
    }

    fn headers(&self) -> &HashMap<String, Vec<u8>> {
        &self.headers
    }

    fn body(&self) -> &[u8] {
        self.body.as_ref()
    }

    fn content_length(&self) -> usize {
        self.content_length
    }

    fn line_count(&self) -> usize {
        self.line_count
    }

    fn word_count(&self) -> usize {
        self.word_count
    }

    fn method(&self) -> &str {
        self.request.method.as_str().unwrap_or_default()
    }

    fn action(&self) -> Option<&Action> {
        self.action.as_ref()
    }

    fn request(&self) -> &Request {
        &self.request
    }
}

impl Timed for AsyncResponse {
    fn elapsed(&self) -> &Duration {
        &self.elapsed
    }
}
