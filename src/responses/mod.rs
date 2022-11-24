//! Asynchronous and blocking http response traits, with optional implementations using [`reqwest`]
use cfg_if::cfg_if;

use crate::{actions::Action, requests::RequestId};
use std::borrow::Cow;
use std::collections::HashMap;
use std::time::Duration;
use url::Url;

use tracing::{error, instrument};

cfg_if! {
    if #[cfg(feature = "json")] {
        use crate::error::FeroxFuzzError;
        use serde_json;
        use serde::{de::DeserializeOwned};
    }
}

cfg_if! {
    if #[cfg(feature = "async")] {
        mod async_response;
        pub use self::async_response::AsyncResponse;
    }
}

cfg_if! {
    if #[cfg(feature = "blocking")] {
        mod blocking_response;
        pub use self::blocking_response::BlockingResponse;
    }

}

/// an opinionated trait to represent a server's response
pub trait Response {
    /// get the id
    #[must_use]
    fn id(&self) -> RequestId;

    /// get a reference to the url
    #[must_use]
    fn url(&self) -> &Url;

    /// get the status code
    #[must_use]
    fn status_code(&self) -> u16;

    /// get a reference to the headers
    #[must_use]
    fn headers(&self) -> &HashMap<String, Vec<u8>>;

    /// get a reference to the body
    #[must_use]
    fn body(&self) -> &[u8];

    /// Get the content-length of this response
    #[must_use]
    fn content_length(&self) -> usize;

    /// Get the [`Action`] to be taken as a result of this response
    #[must_use]
    fn action(&self) -> Option<&Action>;

    /// try to deserialize the response body as JSON
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
    /// # use std::collections::HashMap;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Response::new("{\"stuff\":\"things\"}");
    ///
    /// let mut expected = HashMap::new();
    /// expected.insert(String::from("stuff"), String::from("things"));
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    ///
    /// let json = response.json::<HashMap<String, String>>()?;
    ///
    /// assert_eq!(json, expected);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This method fails whenever the response body is not in JSON format
    /// or it cannot be properly deserialized to target type `T`. For more
    /// details please see [`serde_json::from_reader`].
    ///
    /// [`serde_json::from_reader`]: https://docs.serde.rs/serde_json/fn.from_reader.html
    #[cfg(feature = "json")]
    #[cfg_attr(docsrs, doc(cfg(feature = "json")))]
    #[instrument(skip_all, level = "trace")]
    fn json<T>(&self) -> Result<T, FeroxFuzzError>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(self.body()).map_err(|source| {
            error!(?source, "could not deserialize response body as JSON");
            FeroxFuzzError::JSONParseError { source }
        })
    }

    /// try to get the full response body, as bytes
    ///
    /// # Examples
    ///
    /// example code requires the **crate-feature** `reqwest`
    ///
    /// ```
    /// # use http::response;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Response::new("");
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    ///
    /// assert_eq!(response.content(), None);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    #[must_use]
    fn content(&self) -> Option<&[u8]> {
        if self.content_length() > 0 {
            Some(self.body())
        } else {
            None
        }
    }

    /// try to get the full response body, as unicode
    ///
    /// # Note
    ///
    /// Conversion performed on call, cache results
    /// if you're into that sort of thing
    #[must_use]
    fn text(&self) -> Cow<str> {
        String::from_utf8_lossy(self.body())
    }

    /// Get the number of lines contained in the body of this response, if known
    ///
    /// # Examples
    ///
    /// example code requires the **crate-feature** `reqwest`
    ///
    /// ```
    /// # use http::response;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Response::new("this\nbody\n\n\n\n\ncontains\r\nfive\r\nlines\r\n");
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    ///
    /// assert_eq!(response.line_count(), 5);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    #[must_use]
    fn line_count(&self) -> usize;

    /// Get the number of words contained in the body of this response, if known
    ///
    /// # Examples
    ///
    /// example code requires the **crate-feature** `reqwest`
    ///
    /// ```
    /// # use http::response;
    /// # use feroxfuzz::responses::{Response, AsyncResponse};
    /// # use feroxfuzz::requests::RequestId;
    /// # use feroxfuzz::error::FeroxFuzzError;
    /// # use tokio_test;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), FeroxFuzzError> {
    /// # tokio_test::block_on(async {
    /// // for testing, normal Response comes as a result of a sent request
    /// let reqwest_response = http::response::Response::new("this\tbody     contains\rfive\u{000c}words");
    ///
    /// // should come from the related Request
    /// let id = RequestId::new(0);
    ///
    /// // should come from timing during the client's send function
    /// let elapsed = Duration::from_secs(1);  
    ///
    /// let response = AsyncResponse::try_from_reqwest_response(id, String::from("GET"), reqwest_response.into(), elapsed).await?;
    ///
    /// assert_eq!(response.word_count(), 5);
    /// # Result::<(), FeroxFuzzError>::Ok(())
    /// # })
    /// # }
    /// ```
    #[must_use]
    fn word_count(&self) -> usize;

    /// Get the associated [`Request`]'s http request method
    ///
    /// [`Request`]: crate::requests::Request
    #[must_use]
    fn method(&self) -> &str;
}

/// a trait to provide the amount of time taken to perform an action
pub trait Timed {
    /// amount of time elapsed between sending the request and the
    /// arrival of the response
    #[must_use]
    fn elapsed(&self) -> &Duration;
}
