#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// represents directives of which pieces of a [`Request`] should be fuzzed
///
/// [`Request`]: crate::requests::Request
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum ShouldFuzz<'a> {
    /// directive associated with a fuzzable HTTP request's body
    RequestBody(&'a [u8]),

    /// directive associated with a fuzzable HTTP method, i.e. GET/POST/etc...
    HTTPMethod(&'a [u8]),

    /// directive associated with a fuzzable HTTP method, ex: HTTP/1.1
    HTTPVersion(&'a [u8]),

    /// directive associated with a fuzzable URL scheme, ex: http/https
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLScheme,

    /// directive associated with a fuzzable URL username
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLUsername,

    /// directive associated with a fuzzable URL password
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLPassword,

    /// directive associated with a fuzzable URL ip address/domain
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLHost,

    /// directive associated with a fuzzable URL port
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLPort,

    /// directive associated with a fuzzable URL path
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLPath,

    /// directive associated with a fuzzable URL fragment
    ///
    /// # Note
    ///
    /// this variant doesn't accept a starting value due to the fact that a [`Request`]
    /// can only be instantiated through its `from_url` method. In order to provide
    /// an initial value to the `Request`'s `host` field, simply use the first
    /// parameter of the [`Request::from_url`] method
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    /// [`Request`]: crate::requests::Request
    URLFragment,

    /// directive associated with a fuzzable User-Agent header where only the
    /// the value is fuzzable; the `User-Agent` key is static and does not
    /// need to be specified
    UserAgent(&'a [u8]),

    /// directive associated with a URL query where only the key is fuzzable; the
    /// value is static
    URLParameterKey(&'a [u8], &'a [u8]),

    /// directive associated with a URL query where only the value is fuzzable; the
    /// key is static
    URLParameterValue(&'a [u8], &'a [u8]),

    /// directive associated with a URL query where both the key and value are fuzzable
    URLParameterKeyAndValue(&'a [u8], &'a [u8]),

    /// directive associated with all URL queries where all query keys are marked
    /// fuzzable; unmarked values remain static
    ///
    /// # Note
    ///
    /// this variant can be used when specifying parameters in the `url` field of
    /// the [`Request::from_url`] method.
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    ///
    /// ex: `Request::from_url("http://example.com/stuff.php?FUZZ=derp", &[ShouldFuzz::URLParameterKeys])`
    URLParameterKeys,

    /// directive associated with all URL queries where all query values are marked
    /// fuzzable; unmarked keys remain static
    ///
    /// # Note
    ///
    /// this variant can be used when specifying parameters in the `url` field of
    /// the [`Request::from_url`] method.
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    ///
    /// ex: `Request::from_url("http://example.com/stuff.php?derp=FUZZ", &[ShouldFuzz::URLParameterValues])`
    URLParameterValues,

    /// directive associated with all URL queries where both all keys and values are fuzzable
    ///
    /// # Note
    ///
    /// this variant can be used when specifying parameters in the `url` field of
    /// the [`Request::from_url`] method.
    ///
    /// [`Request::from_url`]: crate::requests::Request::from_url
    ///
    /// ex: `Request::from_url("http://example.com/stuff.php?FUZZ1=FUZZ2", &[ShouldFuzz::URLParameterKeysAndValues])`
    URLParameterKeysAndValues,

    /// directive associated with an http header where only the key is fuzzable; the
    /// value is static
    HeaderKey(&'a [u8], &'a [u8]),

    /// directive associated with an http header where only the value is fuzzable; the
    /// key is static
    HeaderValue(&'a [u8], &'a [u8]),

    /// directive associated with an http header where both the key and value are fuzzable
    HeaderKeyAndValue(&'a [u8], &'a [u8]),

    /// directive associated with a fuzzable header/query-param key
    Key,

    /// directive associated with a fuzzable header/query-param value
    Value,

    /// directive associated with a fuzzable header/query-param key and value
    KeyAndValue,
}
