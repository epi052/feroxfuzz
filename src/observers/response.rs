use super::{Observer, ObserverHooks};
use crate::requests::RequestId;
use crate::responses::{Response, Timed};
use crate::std_ext::tuple::Named;

use std::collections::HashMap;

use cfg_if::cfg_if;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::instrument;
use url::Url;

const RESPONSE_OBSERVER_NAME: &str = "ResponseObserver";

/// observes the given implementor of implementor of [`Response`] and [`Timed`]
#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ResponseObserver<R>
where
    R: Response,
{
    // satisfy Named trait
    name: &'static str,
    // satisfy ResponseExt trait
    response: R,
}

impl<R> Timed for ResponseObserver<R>
where
    R: Response + Timed,
{
    fn elapsed(&self) -> &std::time::Duration {
        self.response.elapsed()
    }
}

impl<R> ResponseObserver<R>
where
    R: Response + Default,
{
    /// create a new `ResponseObserver`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// given an implementor of [`Response`], return a new `ResponseObserver`
    ///
    /// # Examples
    ///
    /// While the example below works, the normal use-case for this struct is to pass
    /// it, and any other [`Observers`] to the [`build_observers`] macro, and pass
    /// the result of that call to your chosen [`Fuzzer`] implementation.
    ///
    /// [`build_observers`]: crate::build_observers
    /// [`Fuzzer`]: crate::fuzzers::Fuzzer
    /// [`Observers`]: crate::observers::Observers
    ///
    /// ```
    /// # use http;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::prelude::*;
    /// # use feroxfuzz::observers::ResponseObserver;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Builder::new().status(302).header("Location", "/somewhere").body("").unwrap();
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    /// let observer = ResponseObserver::with_response(response);
    ///
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    pub const fn with_response(response: R) -> Self
    where
        R: Response,
    {
        Self {
            response,
            name: RESPONSE_OBSERVER_NAME,
        }
    }

    /// true if this `Response` is a well-formed HTTP redirect
    ///
    /// i.e. response code is 3XX and has a Location header
    ///
    /// # Examples
    ///
    /// ```
    /// # use http;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::observers::ResponseObserver;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Builder::new().status(302).header("Location", "/somewhere").body("").unwrap();
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    /// let observer: ResponseObserver<_> = response.into();
    ///
    /// assert_eq!(observer.is_redirect(), true);
    /// assert_eq!(observer.is_permanent_redirect(), false);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        let is_redirect = (300..400).contains(&self.status_code());

        is_redirect
            && (self.headers().contains_key("Location") || self.headers().contains_key("location"))
    }

    /// true if this `Response` is one of the permanent versions of redirect
    ///
    /// i.e. response code is 301 (Moved Permanently) or 308 (Permanent Redirect)
    /// and has a Location header
    ///
    /// # Examples
    ///
    /// ```
    /// # use http;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::observers::ResponseObserver;
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Builder::new().status(308).header("Location", "/somewhere").body("").unwrap();
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    /// let observer: ResponseObserver<_> = response.into();
    ///
    /// assert_eq!(observer.is_redirect(), true);
    /// assert_eq!(observer.is_permanent_redirect(), true);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    #[must_use]
    pub fn is_permanent_redirect(&self) -> bool {
        let numeric_code = self.status_code();
        let is_permanent_redirect = numeric_code == 301 || numeric_code == 308;

        is_permanent_redirect
            && (self.headers().contains_key("Location") || self.headers().contains_key("location"))
    }

    /// determine whether the response is a directory
    ///
    /// handles 2xx and 3xx responses by either checking if the url ends with a / (2xx)
    /// or if the Location header is present and matches the base url + / (3xx)
    ///
    /// # Examples
    ///
    /// example code requires the **crate-feature** `reqwest`
    ///
    /// A 2xx status code, with a path ending in `/` is interpreted as a directory
    ///
    /// ```
    /// # use http;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use feroxfuzz::observers::ResponseObserver;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Builder::new().status(200).body("derp").unwrap();
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    /// let observer: ResponseObserver<_> = response.into();
    ///
    /// assert_eq!(observer.url().as_str(), "http://no.url.provided.local/");
    /// assert_eq!(observer.is_directory(), true);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    ///
    /// A 3xx response with a location header that matches base url + /
    ///
    /// ```
    /// # use http;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::observers::ResponseObserver;
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let mut reqwest_response = http::response::Builder::new().status(301).header("Location", "/").body("").unwrap();
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    /// let observer: ResponseObserver<_> = response.into();
    ///
    /// assert_eq!(observer.url().as_str(), "http://no.url.provided.local/");
    /// assert_eq!(observer.is_directory(), true);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    pub fn is_directory(&self) -> bool {
        if self.status_code() >= 300 && self.status_code() < 400 {
            // status code is 3xx
            match (
                self.headers().get("Location"), // account for case in header
                self.headers().get("location"),
            ) {
                // and has a Location header
                (Some(location), _) | (_, Some(location)) => {
                    // get absolute redirect Url based on the already known base url
                    if let Ok(abs_url) = self.url().join(&String::from_utf8_lossy(location)) {
                        let mut trailing_slash = self.url().as_str().to_string();

                        if !trailing_slash.ends_with('/') {
                            // only append a slash if not present already
                            trailing_slash.push('/');
                        }

                        if trailing_slash == abs_url.as_str() {
                            // if current response's Url + / == the absolute redirection
                            // location, we've found a directory
                            return true;
                        }
                    }
                }
                _ => {
                    // 3xx response without a Location header
                    return false;
                }
            }
        } else if self.status_code() >= 200 && self.status_code() < 300 {
            // status code is 2xx, need to check if it ends in /
            if self.url().as_str().ends_with('/') {
                return true;
            }
        }

        false
    }
}

impl<R> Named for ResponseObserver<R>
where
    R: Response,
{
    fn name(&self) -> &str {
        self.name
    }
}

impl<R> Response for ResponseObserver<R>
where
    R: Response,
{
    /// get the `id` from the associated `Response`
    fn id(&self) -> RequestId {
        self.response.id()
    }

    /// get the `url` from the associated `Response`
    fn url(&self) -> &Url {
        self.response.url()
    }

    /// get the `status_code` from the associated `Response`
    fn status_code(&self) -> u16 {
        self.response.status_code()
    }
    /// get the `headers` from the associated `Response`
    fn headers(&self) -> &HashMap<String, Vec<u8>> {
        self.response.headers()
    }

    /// get the `body` from the associated `Response`
    fn body(&self) -> &[u8] {
        self.response.body()
    }

    /// get the `content_length` from the associated `Response`
    fn content_length(&self) -> usize {
        self.response.content_length()
    }

    /// get the `line_count` from the associated `Response`
    fn line_count(&self) -> usize {
        self.response.line_count()
    }

    /// get the `word_count` from the associated `Response`
    fn word_count(&self) -> usize {
        self.response.word_count()
    }

    /// get the original http request method used to generate the response
    fn method(&self) -> &str {
        self.response.method()
    }
}

impl<R> Observer for ResponseObserver<R> where R: Response {}

impl<R> ObserverHooks<R> for ResponseObserver<R>
where
    R: Response,
{
    #[instrument(skip_all, fields(%self.name), level = "trace")]
    fn post_send_hook(&mut self, response: R) {
        self.response = response;
    }
}

impl<R> Default for ResponseObserver<R>
where
    R: Response + Default,
{
    fn default() -> Self {
        Self {
            name: RESPONSE_OBSERVER_NAME,
            response: R::default(),
        }
    }
}

cfg_if! {
    if #[cfg(feature = "async")] {
        use crate::responses::AsyncResponse;

        impl From<AsyncResponse> for ResponseObserver<AsyncResponse> {
            fn from(response: AsyncResponse) -> Self {
                Self::with_response(response)
            }
        }
    }
}

cfg_if! {
    if #[cfg(feature = "blocking")] {
        use crate::responses::BlockingResponse;

        impl From<BlockingResponse> for ResponseObserver<BlockingResponse> {
            fn from(response: BlockingResponse) -> Self {
                Self::with_response(response)
            }
        }
    }

}
