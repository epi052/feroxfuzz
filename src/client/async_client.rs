use super::utils::{parse_version, reqwest_to_ferox_error};
use super::{AsyncRequests, HttpClient};
use crate::error::FeroxFuzzError;
use crate::requests::Request;
use crate::responses::AsyncResponse;
use crate::std_ext::convert::{AsInner, IntoInner};

use std::time::Instant;

use async_trait::async_trait;
use reqwest::{self, Method, Version};
use tracing::{error, instrument};

/// concrete implementation of an [`AsyncClient`] using an underlying [`reqwest::Client`]
///
/// # Warning
///
/// the HTTP version (HTTP/1.1, etc) cannot be fuzzed by `ReqwestClient`
#[derive(Clone, Default, Debug)]
pub struct AsyncClient {
    client: reqwest::Client,
}

impl HttpClient for AsyncClient {
    type ClientType = reqwest::Client;

    /// create a new client, using [`reqwest::Client`] as the base
    ///
    /// # Examples
    ///
    /// The example below demonstrates by using an async [`reqwest::Client`].
    ///
    /// ```
    /// # use reqwest;
    /// # use std::time::Duration;
    /// # use feroxfuzz::client::{AsyncClient, HttpClient};
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    ///
    /// let req_client = reqwest::Client::builder().timeout(Duration::from_secs(7)).build()?;
    ///
    /// let client = AsyncClient::with_client(req_client);
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If using one of the provided [`reqwest`] clients, this method fails if a
    /// TLS backend cannot be initialized, or the resolver cannot load the system configuration.
    fn with_client(client: Self::ClientType) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AsyncRequests for AsyncClient {
    /// use the underlying [`HttpClient::ClientType`] to send a [`Request`] in order to receive its [`AsyncResponse`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use reqwest;
    /// # use feroxfuzz::requests::{ShouldFuzz, Request, RequestId};
    /// # use std::time::Duration;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::client::{AsyncClient, AsyncRequests, HttpClient};
    /// # use tokio_test;
    /// # use feroxfuzz::responses::Response;
    /// use httpmock::prelude::*;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// let server = MockServer::start();
    /// let mocked = server.mock(|when, then| {
    ///     when.method(GET)
    ///         .path("/doctest");
    ///     then.status(200);
    /// });
    ///
    /// let mut request = Request::from_url(&server.url("/doctest"), None)?;
    /// # request.add_static_header(b"stuff:things", b":")?;
    ///
    /// // bring your own client
    /// let req_client = reqwest::Client::builder().build()?;
    ///
    /// let client = AsyncClient::with_client(req_client);
    ///
    /// let response = client.send(request).await?;
    ///
    /// assert_eq!(mocked.hits(), 1);
    /// assert_eq!(response.status_code(), 200);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails if there was an error while sending request, redirect loop
    /// was detected or redirect limit was exhausted.
    ///
    /// Also, the `send` method will fail if an invalid HTTP version is provided by the given
    /// [`Request`].
    #[instrument(skip_all, level = "trace")]
    async fn send(&self, request: Request) -> Result<AsyncResponse, FeroxFuzzError> {
        // http version cannot be fuzzed via reqwest client due to the use of a Version
        // enum as its input type for that part of the request
        let parsed_version = parse_version(request.version())?;

        // build out the reqwest::Request from our mutated feroxfuzz::Request

        let request_id = request.id;
        let request_method = request.method().as_str()?.to_string();

        let reqwest_request = self.build_request(parsed_version, request)?;
        

        // start timer for the request
        let now = Instant::now();

        // fire ze missiles
        let reqwest_response = self
            .client
            .execute(reqwest_request)
            .await
            .map_err(reqwest_to_ferox_error)?;

        // build the AsyncResponse, the await is for reqwest's asynchronous read of the response body
        let response =
            AsyncResponse::try_from_reqwest_response(request_id, request_method, reqwest_response, now.elapsed())
                .await?;

        Ok(response)
    }
}

impl AsInner for AsyncClient {
    type Type = reqwest::Client;

    fn inner(&self) -> &Self::Type {
        &self.client
    }
}

impl AsyncClient {
    /// create a new default client
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// restructure an existing mutated request into one that can be sent over the wire
    #[instrument(skip_all, level = "trace")]
    fn build_request(
        &self,
        version: Version,
        request: Request,
    ) -> Result<reqwest::Request, FeroxFuzzError> {
        // note to self: this logic is the same as blocking_client's build_request, however, trying to
        // consolidate them using generics was attempted to a point, and found to be more of a pain
        // than it was worth.
        let method = Method::from_bytes(request.method().inner()).map_err(|source| {
            error!(
                method = format!("{}", request.method()),
                %source,
                "could not parse the given http method; must be a valid http method when using a reqwest client"
            );

            FeroxFuzzError::MethodParseError {
                method: format!("{}", request.method()),
            }
        })?;

        let mut builder = if request.url_is_fuzzable() {
            self.inner().request(method, request.url_to_string()?)
        } else {
            self.inner().request(method, request.original_url())
        };

        builder = builder.timeout(request.timeout).version(version);

        if let Some(data_body) = request.body {
            builder = builder.body(data_body.into_inner());
        }

        if let Some(headers) = request.headers {
            for (key, value) in headers {
                builder = builder.header(key.into_inner(), value.into_inner());
            }
        }

        if let Some(user_agent) = request.user_agent {
            builder = builder.header("User-Agent", user_agent.into_inner());
        }

        let reqwest_request = builder.build()?;

        Ok(reqwest_request)
    }
}
