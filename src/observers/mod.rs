//! data gathering models that supply one or more [`Deciders`] with actionable information
//!
//! [`Deciders`]: crate::deciders::Deciders
use crate::requests::Request;
use crate::responses::Response;
use crate::std_ext::tuple::Named;
use crate::MatchName;
use crate::ObserversList;

mod response;
pub use self::response::ResponseObserver;

/// marker trait; observers are used to gather information about requests, responses,
/// target state, etc...
pub trait Observer {}

/// defines the hooks that are executed before a request is sent
/// and after a response is received
///
/// expected order of operations:
/// - `pre_send_hook(request)`
/// - `response = client.send(request)`
/// - `post_send_hook(response)`
pub trait ObserverHooks<R>
where
    R: Response,
{
    /// called before an [`HttpClient`] sends a [`Request`]
    ///
    /// [`HttpClient`]: crate::client::HttpClient
    /// [`Request`]: crate::requests::Request
    fn pre_send_hook(&mut self, _request: &Request) {}

    /// called after an [`HttpClient`] receives a [`Response`]
    ///
    /// [`HttpClient`]: crate::client::HttpClient
    /// [`Response`]: crate::responses::Response
    fn post_send_hook(&mut self, _response: R) {}
}

/// marker trait for a collection of implementors of [`ObserverHooks`]
///
/// recursively calls [`ObserverHooks::pre_send_hook`] or [`ObserverHooks::post_send_hook`]
/// as appropriate.
pub trait Observers<R>: MatchName
where
    R: Response,
{
    /// called before an [`HttpClient`] sends a [`Request`]
    ///
    /// recursively calls [`ObserverHooks::pre_send_hook`]
    ///
    /// [`HttpClient`]: crate::client::HttpClient
    /// [`Request`]: crate::requests::Request
    /// [`ObserverHooks::pre_send_hook`]: crate::observers::ObserverHooks::pre_send_hook
    fn call_pre_send_hooks(&mut self, _request: &Request) {}

    /// called after an [`HttpClient`] receives a [`Response`]
    ///
    /// recursively calls [`ObserverHooks::post_send_hook`]
    ///
    /// [`HttpClient`]: crate::client::HttpClient
    /// [`Response`]: crate::responses::Response
    /// [`ObserverHooks::post_send_hook`]: crate::observers::ObserverHooks::post_send_hook
    fn call_post_send_hooks(&mut self, _response: R)
    where
        R: Response,
    {
    }
}

/// implement trait for an empty tuple, defining the exit condition for the tuple list
///
/// an empty impl allows the default empty hooks to be called
///
/// in this case, there's no need to override
impl<R> Observers<R> for () where R: Response {}

/// recursive trait method, calls pre/post hooks on the current
/// item, then the following item until the empty tuple is reached
impl<Head, Tail, R> Observers<R> for (Head, Tail)
where
    R: Response + Clone,
    Head: Named + ObserverHooks<R>,
    Tail: Observers<R> + ObserversList,
{
    fn call_pre_send_hooks(&mut self, request: &Request) {
        self.0.pre_send_hook(request);
        self.1.call_pre_send_hooks(request);
    }
    fn call_post_send_hooks(&mut self, response: R) {
        self.0.post_send_hook(response.clone());
        self.1.call_post_send_hooks(response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_observers;
    use crate::requests::{Request, RequestId};
    use crate::responses::AsyncResponse;
    use std::time::Duration;

    struct TestObserver {}
    impl Named for TestObserver {
        fn name(&self) -> &str {
            "TestObserver"
        }
    }
    impl Observer for TestObserver {}
    impl ObserverHooks<AsyncResponse> for TestObserver {}

    /// simple test to ensure observer scaffolding an hooks work as expected
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn observer_hooks_can_be_called_recursively() {
        let mut observer = TestObserver {};

        assert_eq!(observer.name(), "TestObserver");

        let request = Request::new();

        let id = RequestId::new(0);
        let elapsed = Duration::from_secs(1);
        let reqwest_response = http::response::Response::new("{\"stuff\":\"things\"}");
        let response = AsyncResponse::try_from_reqwest_response(
            id,
            String::from("GET"),
            reqwest_response.into(),
            elapsed,
        )
        .await
        .unwrap();

        observer.pre_send_hook(&request);
        observer.post_send_hook(response.clone());

        let observer2 = TestObserver {};
        let mut observers_list = build_observers!(observer, observer2);

        observers_list.call_pre_send_hooks(&request);
        observers_list.call_post_send_hooks(response);
    }
}
