//! Asynchronous and blocking http client traits, with optional implementations using [`reqwest`]
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "async")] {
        mod async_client;
        pub use self::async_client::AsyncClient;
        use crate::responses::AsyncResponse;

        use async_trait::async_trait;

        /// trait for asynchronous clients
        #[async_trait]
        #[cfg_attr(docsrs, doc(cfg(feature = "async")))]
        pub trait AsyncRequests: HttpClient {
            /// use the underlying [`HttpClient::ClientType`] to send
            /// a [`Request`] in order to receive its [`AsyncResponse`]
            ///
            /// see [`AsyncClient`] for an example
            ///
            /// # Note
            ///
            /// This is the most likely place to populate the `elapsed` field resulting [`AsyncResponse`]
            async fn send(&self, request: Request) -> Result<AsyncResponse, FeroxFuzzError>;
        }

    }
}

cfg_if! {
    if #[cfg(feature = "blocking")] {
        mod blocking_client;
        pub use self::blocking_client::BlockingClient;
        use crate::responses::BlockingResponse;

        /// trait for blocking clients
        #[cfg_attr(docsrs, doc(cfg(feature = "blocking")))]
        pub trait BlockingRequests: HttpClient {
            /// use the underlying [`HttpClient::ClientType`] to send a
            /// [`Request`] in order to receive its [`BlockingResponse`]
            ///
            /// see [`BlockingClient`] for an example
            ///
            /// # Note
            ///
            /// This is the most likely place to populate the `elapsed` field resulting [`BlockingResponse`]
            ///
            /// # Errors
            ///
            /// Implementors of this function have the option to error when things go awry
            fn send(&self, request: Request) -> Result<BlockingResponse, FeroxFuzzError>;
        }
    }

}
#[cfg(feature = "reqwest")]
mod utils; // parses bytes from input::Data into reqwest::Version, maps reqwest errors to FeroxFuzzError

use crate::error::FeroxFuzzError;
use crate::requests::Request;

/// marker trait for all client types
pub trait HttpClient {
    /// which concrete client will be used
    ///
    /// see [`AsyncClient`] for an example
    type ClientType;

    /// create a new client, using [`HttpClient::ClientType`] as the base
    fn with_client(client: Self::ClientType) -> Self;
}
