use std::time::Instant;

use reqwest::{self, Method, Version};
use tracing::{error, instrument};

use super::utils::{parse_version, reqwest_to_ferox_error};
use super::{BlockingRequests, HttpClient};
use crate::error::FeroxFuzzError;
use crate::requests::Request;
use crate::responses::BlockingResponse;
use crate::std_ext::convert::{AsInner, IntoInner};

/// concrete implementation of a [`BlockingClient`] using an underlying [`reqwest::blocking::Client`]
///
/// # Warning
///
/// the HTTP version (HTTP/1.1, etc) cannot be fuzzed by `BlockingClient` due to
/// limitations imposed by [`reqwest`]
#[derive(Clone, Default, Debug)]
pub struct BlockingClient {
    client: reqwest::blocking::Client,
}

impl HttpClient for BlockingClient {
    type ClientType = reqwest::blocking::Client;

    fn with_client(client: Self::ClientType) -> Self {
        Self { client }
    }
}

impl BlockingRequests for BlockingClient {
    /// use the underlying [`HttpClient::ClientType`] to send a
    /// [`Request`] in order to receive its [`BlockingResponse`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use reqwest;
    /// # use feroxfuzz::prelude::*;
    /// # use feroxfuzz::requests::{ShouldFuzz, RequestId};
    /// # use std::time::Duration;
    /// # use feroxfuzz::client::{BlockingClient, BlockingRequests};
    /// use httpmock::prelude::*;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// let server = MockServer::start();
    /// let mocked = server.mock(|when, then| {
    ///     when.method(GET)
    ///         .path("/doctest");
    ///     then.status(200);
    /// });
    ///
    /// let mut request = Request::from_url(&server.url("/doctest"), None)?;
    ///
    /// // bring your own client
    /// let req_client = reqwest::blocking::Client::builder().build()?;
    ///
    /// let client = BlockingClient::with_client(req_client);
    ///
    /// let response = client.send(request)?;
    ///
    /// assert_eq!(mocked.hits(), 1);
    /// assert_eq!(response.status_code(), 200);
    /// # Ok(())
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
    fn send(&self, request: Request) -> Result<BlockingResponse, FeroxFuzzError> {
        // http version cannot be fuzzed via reqwest client due to the use of a Version
        // enum as its input type for that part of the request
        let parsed_version = parse_version(request.version())?;

        let request_id = request.id;

        // build out the reqwest Request from our mutated Request
        let reqwest_request = self.build_request(parsed_version, request)?;

        // start timer for the request
        let now = Instant::now();

        // fire ze missiles
        let reqwest_response = self
            .client
            .execute(reqwest_request)
            .map_err(reqwest_to_ferox_error)?;

        // build the AsyncResponse, the await is for reqwest's asynchronous read of the response body
        let response = BlockingResponse::try_from_reqwest_response(
            request_id,
            reqwest_response,
            now.elapsed(),
        )?;

        Ok(response)
    }
}

impl BlockingClient {
    /// restructure an existing mutated request into one that can be sent over the wire
    ///
    /// this function takes in a [`Request`] and returns a [`reqwest::blocking::Request`].
    /// this is because the underlying [`reqwest`] client requires its own request type to
    /// execute the http request.
    ///
    /// if any of our url fields are fuzzable, we need to adjust the url that gets passed to the
    /// [`reqwest::blocking::Client`], since it should have mutated prior to getting here. The
    /// logic to determine if any fields are fuzzable is contained in [`Request::url_is_fuzzable`].
    ///
    /// If a new url string is needed due to mutation, [`Request::url_to_string`] builds a new string that
    /// takes the mutated Data fields into account. if no fields are fuzzable, we just use the original
    /// url when building the request.
    ///
    /// fuzzable url fields considered when determining to create a new url string:
    /// - scheme
    /// - username
    /// - password
    /// - host
    /// - port
    /// - path
    /// - fragment
    /// - params
    #[instrument(skip_all, level = "trace")]
    fn build_request(
        &self,
        version: Version,
        request: Request,
    ) -> Result<reqwest::blocking::Request, FeroxFuzzError> {
        // note to self: this logic is the same as async_client's build_request, however, trying to
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

impl AsInner for BlockingClient {
    type Type = reqwest::blocking::Client;

    fn inner(&self) -> &Self::Type {
        &self.client
    }
}
