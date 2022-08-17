//! provides the core [`Request`] type and the [`ShouldFuzz`] directives that dictate
//! what parts of a `Request` should be mutated. Additionally, a
//! [URL Encoder](./requests/encoders/enum.Encoder.html) is provided by default, while other
//! encoders are available on an opt-in basis via feature flags
mod directives;
mod encoders;
mod request;

pub use self::directives::ShouldFuzz;
pub use self::encoders::{Encoder, RequestExt, RequestField};
pub use self::request::{Request, RequestId};
