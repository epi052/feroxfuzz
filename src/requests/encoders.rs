//! collection of encoders that operate on a individual [`Request`] fields. Each encoder
//! is guaranteed to incur only a single allocation per encoding.
#![allow(clippy::use_self)] // clippy false-positive on Action, doesn't want to apply directly to the enums that derive Serialize

use super::Request;
use crate::input::Data;
use cfg_if::cfg_if;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// macro to generate boiler-plate encoding logic for url/hex/base64 encoders
/// on [`Request`] fields
macro_rules! encode_optional_field {
    // - field is the mutable Data object associated with the field to encode
    // - encoder is which encoder is being matched against
    ($field:ident, $encoder:expr) => {
        // the optional encoders are [in|ex]cluded via cfg_if blocks
        cfg_if! {  // feature-gated base64 encoder
            if #[cfg(any(feature = "encoders", feature = "base64"))] {
                if matches!($encoder, Encoder::Base64) {
                    use base64::{Engine as _, engine::general_purpose};

                    if $field.is_empty() {
                        // can't encode nothing
                        return;
                    }

                    // buffer of a size big enough to hold the encoded value
                    let mut buffer = vec![0; $field.len() * 4 / 3 + 4];

                    // perform the write
                    let written = general_purpose::URL_SAFE.encode_slice(
                        $field.as_ref(),  // Data's inner vec as an &[u8]
                        &mut buffer,
                    ).unwrap_or(0);

                    if written == 0 {
                        tracing::debug!("failed to base64 encode {:?}, will result in an empty buffer", $field.as_ref());
                    }

                    // resize back down to account for any overages
                    buffer.resize(written, 0);

                    let mut new_data = if $field.is_fuzzable() {
                        Data::Fuzzable(buffer)
                    } else {
                        Data::Static(buffer)
                    };

                    std::mem::swap($field, &mut new_data);
                }
            }
        }

        cfg_if! {  // feature-gated hex encoder
            if #[cfg(any(feature = "encoders", feature = "hex"))] {
                if matches!($encoder, Encoder::Hex) {
                    if $field.is_empty() {
                        // can't encode nothing
                        return;
                    }

                    // buffer of a size big enough to hold the encoded value
                    let mut buffer = vec![0; $field.len() * 2];

                    // perform the write
                    //
                    // even though unwrap is used, this call can't fail. from the hex docs:
                    //
                    // "The output buffer, has to be able to hold at least `input.len() * 2` bytes,
                    // otherwise this function will return an error."
                    //
                    // we guarantee the invariant, so it's safe to unwrap
                    hex::encode_to_slice(
                        $field.as_ref(), // Data's inner vec as an &[u8]
                        &mut buffer,
                    ).unwrap_or_default();

                    let mut new_data = if $field.is_fuzzable() {
                        Data::Fuzzable(buffer)
                    } else {
                        Data::Static(buffer)
                    };

                    std::mem::swap($field, &mut new_data);
                }
            }
        }

        // url encoder is always available, since the Url library is a hard requirement
        if matches!($encoder, Encoder::Url) {
            if $field.is_empty() {
                return;
            }

            // byte_serialize returns an iterator of &str slices, so we use fold to keep the encoding to a single
            // allocation. the initial capacity of len*2 seems to be enough to not require resizing during
            // very unscientific tests
            let serialized = url::form_urlencoded::byte_serialize($field.as_ref()).fold(
                // not much rhyme or reason for the double initial capacity other than we know that if
                // any encoding occurs, we'll need more space, and it's easier to multiply
                // a usize by a whole number than deal with something like * 1.5
                Vec::with_capacity($field.len() * 2),
                |mut accumulator, element| {
                    for char in element.chars() {
                        accumulator.push(char as u8);
                    }
                    accumulator
                },
            );

            let mut new_data = if $field.is_fuzzable() {
                Data::Fuzzable(serialized)
            } else {
                Data::Static(serialized)
            };

            std::mem::swap($field, &mut new_data);
        }
    };
}

/// represents each available type of encoder  
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Encoder {
    /// base64 encoder type
    #[cfg_attr(docsrs, doc(cfg(any(feature = "encoders", feature = "base64"))))]
    #[cfg(any(feature = "encoders", feature = "base64"))]
    Base64,

    /// hexadecimal encoder type
    #[cfg_attr(docsrs, doc(cfg(any(feature = "encoders", feature = "hex"))))]
    #[cfg(any(feature = "encoders", feature = "hex"))]
    Hex,

    /// url/percent encoder type
    ///
    /// # Note
    ///
    /// this is an application/x-www-form-urlencoded style encoder, so `' '` (space)
    /// characters will be encoded as `'+'` instead of `"%20"`
    Url,
}

/// represents most possible fields available on a [`Request`] object
///
/// # Note
///
/// omits headers and url query parameters on purpose, as they have a
/// different method of being called for encoding
#[derive(Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum RequestField {
    /// [`Request`]'s url scheme field
    URLScheme,

    /// [`Request`]'s username field
    Username,

    /// [`Request`]'s password field
    Password,

    /// [`Request`]'s host field
    Host,

    /// [`Request`]'s port field
    Port,

    /// [`Request`]'s path field
    Path,

    /// [`Request`]'s fragment field
    Fragment,

    /// [`Request`]'s HTTP method field
    HTTPMethod,

    /// [`Request`]'s body field
    Body,

    /// [`Request`]'s user-agent field
    UserAgent,

    /// [`Request`]'s HTTP version field
    HTTPVersion,
}

/// extension trait to extend the [`Request`] struct by adding
/// methods to encode different request fields
pub trait RequestExt {
    /// convenience wrapper around more specific `encode_FIELD` methods; can be used
    /// as the main entry point or each specific method can be used. whichever is
    /// easier.
    ///
    /// # Note
    ///
    /// to encode a header or query parameter, the [`self.encode_header`] and
    /// [`self.encode_param`] methods must be used, as their function signature
    /// differs from the other available methods
    fn encode(&mut self, field: RequestField, encoder: Encoder) {
        match field {
            RequestField::URLScheme => self.encode_url_scheme(encoder),
            RequestField::UserAgent => self.encode_user_agent(encoder),
            RequestField::Username => self.encode_username(encoder),
            RequestField::Password => self.encode_password(encoder),
            RequestField::Host => self.encode_host(encoder),
            RequestField::Port => self.encode_port(encoder),
            RequestField::Path => self.encode_path(encoder),
            RequestField::Fragment => self.encode_fragment(encoder),
            RequestField::Body => self.encode_body(encoder),
            RequestField::HTTPMethod => self.encode_http_method(encoder),
            RequestField::HTTPVersion => self.encode_http_version(encoder),
        }
    }

    /// given an [`Encoder`], encode the [`Request`]'s url scheme field  
    fn encode_url_scheme(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s username field  
    fn encode_username(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s password field  
    fn encode_password(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s host field  
    fn encode_host(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s port field  
    fn encode_port(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s path field  
    fn encode_path(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s fragment field  
    fn encode_fragment(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s body field  
    fn encode_body(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode a single [`Request`] header
    fn encode_header(&mut self, index: usize, encoder: Encoder);

    /// given an [`Encoder`], encode a single [`Request`] query parameter
    fn encode_param(&mut self, index: usize, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s user-agent field  
    fn encode_user_agent(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s http method field  
    fn encode_http_method(&mut self, encoder: Encoder);

    /// given an [`Encoder`], encode the [`Request`]'s http version field  
    fn encode_http_version(&mut self, encoder: Encoder);
}

impl RequestExt for Request {
    fn encode_url_scheme(&mut self, encoder: Encoder) {
        let field = &mut self.scheme;

        encode_optional_field!(field, encoder);
    }

    fn encode_username(&mut self, encoder: Encoder) {
        if let Some(field) = self.username.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_password(&mut self, encoder: Encoder) {
        if let Some(field) = self.password.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_host(&mut self, encoder: Encoder) {
        if let Some(field) = self.host.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_port(&mut self, encoder: Encoder) {
        if let Some(field) = self.port.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_path(&mut self, encoder: Encoder) {
        let field = &mut self.path;

        encode_optional_field!(field, encoder);
    }

    fn encode_fragment(&mut self, encoder: Encoder) {
        if let Some(field) = self.fragment.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_body(&mut self, encoder: Encoder) {
        if let Some(field) = self.body.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_header(&mut self, index: usize, encoder: Encoder) {
        if let Some(headers) = self.headers.as_mut() {
            if let Some(header) = headers.get_mut(index) {
                let field = &mut header.1;
                encode_optional_field!(field, encoder);
            }
        }
    }

    fn encode_param(&mut self, index: usize, encoder: Encoder) {
        if let Some(params) = self.params.as_mut() {
            if let Some(param) = params.get_mut(index) {
                let field = &mut param.1;
                encode_optional_field!(field, encoder);
            }
        }
    }

    fn encode_user_agent(&mut self, encoder: Encoder) {
        if let Some(field) = self.user_agent.as_mut() {
            encode_optional_field!(field, encoder);
        }
    }

    fn encode_http_method(&mut self, encoder: Encoder) {
        let field = &mut self.method;

        encode_optional_field!(field, encoder);
    }

    fn encode_http_version(&mut self, encoder: Encoder) {
        let field = &mut self.version;

        encode_optional_field!(field, encoder);
    }
}

#[cfg(all(test, feature = "encoders"))]
mod tests {
    use super::*;
    use crate::requests::ShouldFuzz;

    // -----------------------
    // headers and params tests
    // -----------------------
    #[test]
    fn test_header_with_base64_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::HeaderValue(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_header(0, Encoder::Base64);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .headers()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
        );
    }

    #[test]
    fn test_header_with_url_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::HeaderValue(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_header(0, Encoder::Url);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .headers()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "i%27m+a+more+normal+string%3F"
        );
    }

    #[test]
    fn test_header_with_hex_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::HeaderValue(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_header(0, Encoder::Hex);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .headers()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "69276d2061206d6f7265206e6f726d616c20737472696e673f"
        );
    }

    #[test]
    fn test_param_with_base64_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::URLParameterKey(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_param(0, Encoder::Base64);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .params()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
        );
    }

    #[test]
    fn test_param_with_url_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::URLParameterKey(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_param(0, Encoder::Url);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .params()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "i%27m+a+more+normal+string%3F"
        );
    }

    #[test]
    fn test_param_with_hex_encoder() {
        let mut request = Request::from_url(
            "http://localhost:8000",
            Some(&[ShouldFuzz::URLParameterKey(
                b"key:i'm a more normal string?",
                b":",
            )]),
        )
        .unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode_param(0, Encoder::Hex);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request
                .params()
                .unwrap()
                .get(0)
                .unwrap()
                .1
                .as_str()
                .unwrap(),
            "69276d2061206d6f7265206e6f726d616c20737472696e673f"
        );
    }

    // -----------------------
    // request::host tests
    // -----------------------

    #[test]
    fn test_host_with_base64_encoder() {
        let mut request =
            Request::from_url("http://localhost:8000", Some(&[ShouldFuzz::URLHost])).unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode(RequestField::Host, Encoder::Base64);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(request.host().unwrap().as_str().unwrap(), "bG9jYWxob3N0");
    }

    #[test]
    fn test_host_with_url_encoder() {
        let mut request =
            Request::from_url("http://localhost:8000", Some(&[ShouldFuzz::URLHost])).unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode(RequestField::Host, Encoder::Url);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(request.host().unwrap().as_str().unwrap(), "localhost");
    }

    #[test]
    fn test_host_with_hex_encoder() {
        let mut request =
            Request::from_url("http://localhost", Some(&[ShouldFuzz::URLHost])).unwrap();

        let allocations = allocation_counter::count(|| {
            request.encode(RequestField::Host, Encoder::Hex);
        });

        assert_eq!(allocations, 1); // count # of allocations during encode
        assert_eq!(
            request.host().unwrap().as_str().unwrap(),
            "6c6f63616c686f7374"
        );
    }

    // -----------------------
    // macro-able tests
    // -----------------------

    macro_rules! generate_optional_field_test {
        // - method is the Request method to test
        // - field is the mutable Data object associated with the field to encode
        // - directive is the associated ShouldFuzz directive
        // - encoder is which encoder is being matched against
        // - func_name is what the generated test function should be named
        // - expected is the anticipated result of the overall encoding performed
        ($method:ident, $field:expr, $directive:expr, $encoder:expr, $func_name:ident, $expected:expr) => {
            #[test]
            fn $func_name() {
                let mut request = Request::from_url(
                    "http://localhost:8000",
                    Some(&[$directive(b"i'm a more normal string?")]),
                )
                .unwrap();

                let allocations = allocation_counter::count(|| {
                    request.encode($field, $encoder);
                });

                assert_eq!(allocations, 1); // count # of allocations during encode
                assert_eq!(request.$method().unwrap().as_str().unwrap(), $expected);
            }
        };
    }

    macro_rules! generate_field_test {
        // - method is the Request method to test
        // - field is the mutable Data object associated with the field to encode
        // - directive is the associated ShouldFuzz directive
        // - encoder is which encoder is being matched against
        // - func_name is what the generated test function should be named
        // - expected is the anticipated result of the overall encoding performed
        ($method:ident, $field:expr, $directive:expr, $encoder:expr, $func_name:ident, $expected:expr) => {
            #[test]
            fn $func_name() {
                let mut request = Request::from_url(
                    "http://localhost:8000",
                    Some(&[$directive(b"i'm a more normal string?")]),
                )
                .unwrap();

                let allocations = allocation_counter::count(|| {
                    request.encode($field, $encoder);
                });

                assert_eq!(allocations, 1); // count # of allocations during encode
                assert_eq!(request.$method().as_str().unwrap(), $expected);
            }
        };
    }

    macro_rules! generate_field_test_with_optional_unit_variants {
        // - method is the Request method to test
        // - field is the mutable Data object associated with the field to encode
        // - url is the URL to use for the Request::from_url() call
        // - directive is the associated ShouldFuzz directive
        // - encoder is which encoder is being matched against
        // - func_name is what the generated test function should be named
        // - expected is the anticipated result of the overall encoding performed
        ($method:ident, $field:expr, $url:expr, $directive:expr, $encoder:expr, $func_name:ident, $expected:expr) => {
            #[test]
            fn $func_name() {
                let mut request = Request::from_url($url, Some(&[$directive])).unwrap();

                let allocations = allocation_counter::count(|| {
                    request.encode($field, $encoder);
                });

                assert_eq!(allocations, 1); // count # of allocations during encode
                assert_eq!(request.$method().unwrap().as_str().unwrap(), $expected);
            }
        };
    }

    macro_rules! generate_field_test_with_unit_variants {
        // - method is the Request method to test
        // - field is the mutable Data object associated with the field to encode
        // - url is the URL to use for the Request::from_url() call
        // - directive is the associated ShouldFuzz directive
        // - encoder is which encoder is being matched against
        // - func_name is what the generated test function should be named
        // - expected is the anticipated result of the overall encoding performed
        ($method:ident, $field:expr, $url:expr, $directive:expr, $encoder:expr, $func_name:ident, $expected:expr) => {
            #[test]
            fn $func_name() {
                let mut request = Request::from_url($url, Some(&[$directive])).unwrap();

                let allocations = allocation_counter::count(|| {
                    request.encode($field, $encoder);
                });

                assert_eq!(allocations, 1); // count # of allocations during encode
                assert_eq!(request.$method().as_str().unwrap(), $expected);
            }
        };
    }

    generate_field_test_with_optional_unit_variants!(
        username,
        RequestField::Username,
        "http://admin@localhost:8000/",
        ShouldFuzz::URLUsername,
        Encoder::Base64,
        test_username_with_base64_encoder,
        "YWRtaW4="
    );
    generate_field_test_with_optional_unit_variants!(
        username,
        RequestField::Username,
        "http://admin@localhost:8000/",
        ShouldFuzz::URLUsername,
        Encoder::Hex,
        test_username_with_hex_encoder,
        "61646d696e"
    );
    generate_field_test_with_optional_unit_variants!(
        username,
        RequestField::Username,
        "http://admin@localhost:8000/",
        ShouldFuzz::URLUsername,
        Encoder::Url,
        test_username_with_url_encoder,
        "admin"
    );

    generate_field_test_with_optional_unit_variants!(
        password,
        RequestField::Password,
        "http://admin:password@localhost:8000/",
        ShouldFuzz::URLPassword,
        Encoder::Base64,
        test_password_with_base64_encoder,
        "cGFzc3dvcmQ="
    );
    generate_field_test_with_optional_unit_variants!(
        password,
        RequestField::Password,
        "http://admin:password@localhost:8000/",
        ShouldFuzz::URLPassword,
        Encoder::Hex,
        test_password_with_hex_encoder,
        "70617373776f7264"
    );
    generate_field_test_with_optional_unit_variants!(
        password,
        RequestField::Password,
        "http://admin:password@localhost:8000/",
        ShouldFuzz::URLPassword,
        Encoder::Url,
        test_password_with_url_encoder,
        "password"
    );

    generate_field_test_with_optional_unit_variants!(
        port,
        RequestField::Port,
        "http://localhost:8000/",
        ShouldFuzz::URLPort,
        Encoder::Base64,
        test_port_with_base64_encoder,
        "ODAwMA=="
    );
    generate_field_test_with_optional_unit_variants!(
        port,
        RequestField::Port,
        "http://localhost:8000/",
        ShouldFuzz::URLPort,
        Encoder::Hex,
        test_port_with_hex_encoder,
        "38303030"
    );
    generate_field_test_with_optional_unit_variants!(
        port,
        RequestField::Port,
        "http://localhost:8000/",
        ShouldFuzz::URLPort,
        Encoder::Url,
        test_port_with_url_encoder,
        "8000"
    );

    generate_field_test_with_optional_unit_variants!(
        fragment,
        RequestField::Fragment,
        "http://localhost:8000/#fragment",
        ShouldFuzz::URLFragment,
        Encoder::Base64,
        test_fragment_with_base64_encoder,
        "ZnJhZ21lbnQ="
    );
    generate_field_test_with_optional_unit_variants!(
        fragment,
        RequestField::Fragment,
        "http://localhost:8000/#fragment",
        ShouldFuzz::URLFragment,
        Encoder::Hex,
        test_fragment_with_hex_encoder,
        "667261676d656e74"
    );
    generate_field_test_with_optional_unit_variants!(
        fragment,
        RequestField::Fragment,
        "http://localhost:8000/#fragment",
        ShouldFuzz::URLFragment,
        Encoder::Url,
        test_fragment_with_url_encoder,
        "fragment"
    );

    generate_optional_field_test!(
        body,
        RequestField::Body,
        ShouldFuzz::RequestBody,
        Encoder::Base64,
        test_body_with_base64_encoder,
        "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
    );
    generate_optional_field_test!(
        body,
        RequestField::Body,
        ShouldFuzz::RequestBody,
        Encoder::Hex,
        test_body_with_hex_encoder,
        "69276d2061206d6f7265206e6f726d616c20737472696e673f"
    );
    generate_optional_field_test!(
        body,
        RequestField::Body,
        ShouldFuzz::RequestBody,
        Encoder::Url,
        test_body_with_url_encoder,
        "i%27m+a+more+normal+string%3F"
    );

    generate_optional_field_test!(
        user_agent,
        RequestField::UserAgent,
        ShouldFuzz::UserAgent,
        Encoder::Base64,
        test_user_agent_with_base64_encoder,
        "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
    );
    generate_optional_field_test!(
        user_agent,
        RequestField::UserAgent,
        ShouldFuzz::UserAgent,
        Encoder::Hex,
        test_user_agent_with_hex_encoder,
        "69276d2061206d6f7265206e6f726d616c20737472696e673f"
    );
    generate_optional_field_test!(
        user_agent,
        RequestField::UserAgent,
        ShouldFuzz::UserAgent,
        Encoder::Url,
        test_user_agent_with_url_encoder,
        "i%27m+a+more+normal+string%3F"
    );

    generate_field_test_with_unit_variants!(
        scheme,
        RequestField::URLScheme,
        "http://localhost:8000",
        ShouldFuzz::URLScheme,
        Encoder::Base64,
        test_scheme_with_base64_encoder,
        "aHR0cA=="
    );
    generate_field_test_with_unit_variants!(
        scheme,
        RequestField::URLScheme,
        "http://localhost:8000",
        ShouldFuzz::URLScheme,
        Encoder::Hex,
        test_scheme_with_hex_encoder,
        "68747470"
    );
    generate_field_test_with_unit_variants!(
        scheme,
        RequestField::URLScheme,
        "http://localhost:8000",
        ShouldFuzz::URLScheme,
        Encoder::Url,
        test_scheme_with_url_encoder,
        "http"
    );

    generate_field_test_with_unit_variants!(
        path,
        RequestField::Path,
        "http://localhost:8000/derp",
        ShouldFuzz::URLPath,
        Encoder::Base64,
        test_path_with_base64_encoder,
        "L2RlcnA="
    );
    generate_field_test_with_unit_variants!(
        path,
        RequestField::Path,
        "http://localhost:8000/derp",
        ShouldFuzz::URLPath,
        Encoder::Hex,
        test_path_with_hex_encoder,
        "2f64657270"
    );
    generate_field_test_with_unit_variants!(
        path,
        RequestField::Path,
        "http://localhost:8000/derp",
        ShouldFuzz::URLPath,
        Encoder::Url,
        test_path_with_url_encoder,
        "%2Fderp"
    );

    generate_field_test!(
        method,
        RequestField::HTTPMethod,
        ShouldFuzz::HTTPMethod,
        Encoder::Base64,
        test_method_with_base64_encoder,
        "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
    );
    generate_field_test!(
        method,
        RequestField::HTTPMethod,
        ShouldFuzz::HTTPMethod,
        Encoder::Hex,
        test_method_with_hex_encoder,
        "69276d2061206d6f7265206e6f726d616c20737472696e673f"
    );
    generate_field_test!(
        method,
        RequestField::HTTPMethod,
        ShouldFuzz::HTTPMethod,
        Encoder::Url,
        test_method_with_url_encoder,
        "i%27m+a+more+normal+string%3F"
    );

    generate_field_test!(
        version,
        RequestField::HTTPVersion,
        ShouldFuzz::HTTPVersion,
        Encoder::Base64,
        test_version_with_base64_encoder,
        "aSdtIGEgbW9yZSBub3JtYWwgc3RyaW5nPw=="
    );
    generate_field_test!(
        version,
        RequestField::HTTPVersion,
        ShouldFuzz::HTTPVersion,
        Encoder::Hex,
        test_version_with_hex_encoder,
        "69276d2061206d6f7265206e6f726d616c20737472696e673f"
    );
    generate_field_test!(
        version,
        RequestField::HTTPVersion,
        ShouldFuzz::HTTPVersion,
        Encoder::Url,
        test_version_with_url_encoder,
        "i%27m+a+more+normal+string%3F"
    );
}
