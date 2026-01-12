use crate::error::{FeroxFuzzError, RequestErrorKind};
use crate::input::Data;
use crate::std_ext::convert::AsInner;
use reqwest::Version;
use tracing::{error, instrument};

/// internal helper to validate http version
#[instrument(skip_all, level = "trace")]
pub(super) fn parse_version(data: &Data) -> Result<Version, FeroxFuzzError> {
    match data.inner().get(5..) {
        Some([0x30, 0x2e, 0x39]) => Ok(Version::HTTP_09),
        Some([0x31, 0x2e, 0x30]) => Ok(Version::HTTP_10),
        Some([0x31, 0x2e, 0x31]) => Ok(Version::HTTP_11),
        Some([0x32, 0x2e, 0x30]) => Ok(Version::HTTP_2),
        Some([0x33, 0x2e, 0x30]) => Ok(Version::HTTP_3),
        _ => {
            error!(%data, "failed to parse http version; must be a valid http version when using a reqwest client");

            Err(FeroxFuzzError::InvalidVersionError {
                version: format!("{data}"),
            })
        }
    }
}

/// internal helper to convert [`reqwest::Error`] to [`FeroxFuzzError`]
#[allow(clippy::needless_pass_by_value)]
#[instrument(skip_all, level = "trace")]
pub(super) fn reqwest_to_ferox_error(source: reqwest::Error) -> FeroxFuzzError {
    let status = source.status().map(|status_code| status_code.as_u16());

    let kind = if source.is_body() {
        // Returns true if the error is related to the request or response body
        RequestErrorKind::Body(status)
    } else if source.is_connect() {
        // Returns true if the error is related to connect
        //
        // note: connect is a more specific error than a request error and both
        // can be true at the same time; don't change the order of the if statements
        // without thinking about the specificity of the error
        RequestErrorKind::Connect(status)
    } else if source.is_decode() {
        // Returns true if the error is related to decoding the response’s body
        RequestErrorKind::Decode(status)
    } else if source.is_redirect() {
        // Returns true if the error is from a RedirectPolicy
        RequestErrorKind::Redirect(status)
    } else if source.is_timeout() {
        // Returns true if the error is related to a timeout
        //
        // note: timeout is a more specific error than a request error and both
        // can be true at the same time; don't change the order of the if statements
        // without thinking about the specificity of the error
        RequestErrorKind::Timeout
    } else if source.is_request() {
        // Returns true if the error is related to the request
        RequestErrorKind::Request(status)
    } else {
        RequestErrorKind::Unknown
    };

    error!(?kind, "error occurred while sending request: {}", source);

    FeroxFuzzError::RequestError {
        kind,
        message: source.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// parsed versions return correct values
    #[test]
    fn parsed_versions_are_correct() {
        let versions = [
            b"HTTP/0.9",
            b"HTTP/1.0",
            b"HTTP/1.1",
            b"HTTP/2.0",
            b"HTTP/3.0",
        ];
        for version in versions {
            let data = Data::Static(version.to_vec());
            assert!(parse_version(&data).is_ok());
        }

        assert!(parse_version(&Data::Static(b"not valid".to_vec())).is_err());
    }
}
