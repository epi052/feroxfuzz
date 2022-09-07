use super::{Response, Timed};

use crate::error::FeroxFuzzError;
use crate::requests::RequestId;
use crate::std_ext::str::ASCII_WHITESPACE;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

use tracing::{error, instrument};

/// feroxfuzz implementation of [`Response`] that extends [`reqwest::Response`]
/// for additional functionality
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(docsrs, doc(cfg(feature = "async")))]
#[non_exhaustive]
pub struct AsyncResponse {
    id: RequestId,
    url: Url,
    status_code: u16,
    headers: HashMap<String, Vec<u8>>,
    elapsed: Duration,
    content_length: usize,
    line_count: usize,
    word_count: usize,
    method: String,

    #[cfg_attr(all(not(feature = "serialize-body"), feature = "serde"), serde(skip))]
    body: Vec<u8>,
}

impl AsyncResponse {
    fn new() -> Self {
        Self::default()
    }

    /// Create a `Response` object from a [`RequestId`], [`reqwest::Response`], and [`Duration`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use http::response;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
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
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, reqwest_response.into(), elapsed).await?;
    ///  
    /// assert_eq!(response.id(), RequestId::new(0));
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
        id: RequestId,
        method: String,
        resp: reqwest::Response,
        elapsed: Duration,
    ) -> Result<Self, FeroxFuzzError> {
        let mut response = Self::new();

        response.id = id;
        response.method = method;
        response.url = resp.url().clone();
        response.status_code = resp.status().as_u16();
        response.headers = resp
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect();

        let body = resp.bytes().await.map_err(|source| {
            error!(?source, "could not read response body");
            FeroxFuzzError::ResponseReadError { source }
        })?;

        response.content_length = body.len();

        response.line_count = body
            .as_ref()
            .split(|byte| byte == &b'\n')
            .filter(|s| !s.is_empty())
            .count();

        response.word_count = if body.is_empty() {
            0
        } else {
            body.as_ref()
                .split(|byte| ASCII_WHITESPACE.contains(byte))
                .filter(|s| !s.is_empty())
                .count()
        };

        response.body = body.as_ref().to_vec();
        response.elapsed = elapsed;

        Ok(response)
    }

    /// get a mutable reference to the id
    #[must_use]
    #[inline]
    pub fn id_mut(&mut self) -> &mut RequestId {
        &mut self.id
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
        self.id
    }

    fn url(&self) -> &Url {
        &self.url
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
        &self.method
    }
}

impl Timed for AsyncResponse {
    fn elapsed(&self) -> &Duration {
        &self.elapsed
    }
}

impl Default for AsyncResponse {
    fn default() -> Self {
        Self {
            id: RequestId::default(),
            method: Default::default(),
            url: Url::parse("http://no.url.provided.local/").unwrap(),
            status_code: Default::default(),
            headers: Default::default(),
            body: Default::default(),
            elapsed: Default::default(),
            content_length: Default::default(),
            line_count: Default::default(),
            word_count: Default::default(),
        }
    }
}
