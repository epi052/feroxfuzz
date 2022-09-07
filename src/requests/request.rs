//! Request object where most fields of the request may be set to [`Data::Fuzzable`]
//! or [`Data::Static`]
use super::ShouldFuzz;
use crate::error::FeroxFuzzError;
use crate::input::Data;
use crate::std_ext::convert::IntoInner;

use derive_more::{Constructor, From, Into, Not, Sum};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use tracing::{error, instrument};
use url::Url;

use std::fmt::{self, Display, Formatter};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::str::FromStr;
use std::time::Duration;

impl IntoInner for Url {
    type Type = Self;

    fn into_inner(self) -> Self::Type {
        self
    }
}

/// internal helper used to determine which collection is in use: headers or params
#[derive(Copy, Clone, Debug)]
enum CollectionId {
    Headers,
    Params,
}

/// request identifier: uniqueness is the user's responsibility
#[derive(
    Copy,
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Sum,
    From,
    Into,
    Not,
    Constructor,
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RequestId(usize);

impl Display for RequestId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "RequestId<{}>", self.0)
    }
}

impl<T> Add<T> for RequestId
where
    T: Into<usize>,
{
    type Output = Self;

    fn add(self, other: T) -> Self::Output {
        Self(self.0 + other.into())
    }
}

impl<T> Sub<T> for RequestId
where
    T: Into<usize>,
{
    type Output = Self;

    fn sub(self, other: T) -> Self::Output {
        Self(self.0 - other.into())
    }
}

impl<T> AddAssign<T> for RequestId
where
    T: Into<usize>,
{
    fn add_assign(&mut self, rhs: T) {
        self.0 += rhs.into();
    }
}

impl<T> SubAssign<T> for RequestId
where
    T: Into<usize>,
{
    fn sub_assign(&mut self, rhs: T) {
        self.0 -= rhs.into();
    }
}

/// data container representing all possible fields of an http request and its url
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct Request {
    pub(crate) id: RequestId,
    pub(crate) parsed_url: Url,
    pub(crate) original_url: String,
    pub(crate) scheme: Data,
    pub(crate) username: Option<Data>,
    pub(crate) password: Option<Data>,
    pub(crate) host: Option<Data>,
    pub(crate) port: Option<Data>,
    pub(crate) path: Data,
    pub(crate) fragment: Option<Data>,
    pub(crate) method: Data,
    pub(crate) body: Option<Data>,
    pub(crate) headers: Option<Vec<(Data, Data)>>,
    pub(crate) params: Option<Vec<(Data, Data)>>,
    pub(crate) user_agent: Option<Data>,
    pub(crate) version: Data,
    pub(crate) timeout: Duration,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            id: RequestId::default(),
            parsed_url: Url::parse("http://no.url.provided.local/").unwrap(),
            original_url: String::new(),
            body: None,
            headers: None,
            params: None,
            timeout: Duration::from_secs(7),
            method: Data::from_str("GET").unwrap(),
            user_agent: None,
            version: Data::from_str("HTTP/1.1").unwrap(),
            scheme: Data::from_str("http").unwrap(),
            username: None,
            password: None,
            host: None,
            port: None,
            path: Data::from_str("/").unwrap(),
            fragment: None,
        }
    }
}

impl From<Url> for Request {
    fn from(url: Url) -> Self {
        // grab any query parameters
        let pairs: Vec<_> = url
            .query_pairs()
            .into_iter()
            .map(|(key, value)| {
                (
                    Data::Static(key.as_bytes().to_vec()),
                    Data::Static(value.as_bytes().to_vec()),
                )
            })
            .collect();

        Self {
            original_url: url.to_string(),
            scheme: Data::Static(url.scheme().as_bytes().to_vec()),
            username: if url.username().is_empty() {
                None
            } else {
                Some(Data::Static(url.username().as_bytes().to_vec()))
            },
            password: url
                .password()
                .map(|password| Data::Static(password.as_bytes().to_vec())),
            host: url
                .host()
                .map(|host| Data::Static(host.to_string().as_bytes().to_vec())),
            port: url
                .port()
                .map(|port| Data::Static(port.to_string().as_bytes().to_vec())),
            path: Data::Static(url.path().as_bytes().to_vec()),
            fragment: url
                .fragment()
                .map(|fragment| Data::Static(fragment.as_bytes().to_vec())),
            params: if pairs.is_empty() { None } else { Some(pairs) },
            parsed_url: url,
            ..Self::default()
        }
    }
}

impl Request {
    // ----------------
    // Constructors
    // ----------------

    /// Return a new, default `Request`
    ///
    /// # Note
    ///
    /// Strongly consider using the [`Request::from_url`] constructor, it is the
    /// recommended entry point for creating a `Request`
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a new `Request`, as long as the given `url` is valid. Valid in this context means
    /// it is able to be parsed into a [`url::Url`](https://docs.rs/url/latest/url/struct.Url.html).
    ///
    /// # Examples
    ///
    /// When `fuzz_directives` is `None`, all fields are marked `Static`. Individual fields can be
    /// set to `Fuzzable` later through the more specific `fuzzable_*` setter methods, if desired.
    ///
    /// ```
    /// # use feroxfuzz::requests::{ShouldFuzz, Request, RequestId};
    /// # use feroxfuzz::input::Data;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://user:pass@localhost:12345/path?querykey=queryval&stuff=things#frag", None)?;
    ///
    /// assert_eq!(request.scheme(), &Data::Static(b"http".to_vec()));
    /// assert_eq!(request.params(), Some(vec![(Data::Static(b"querykey".to_vec()), Data::Static(b"queryval".to_vec())), (Data::Static(b"stuff".to_vec()), Data::Static(b"things".to_vec()))].as_slice()));
    /// assert_eq!(request.username(), Some(&Data::Static(b"user".to_vec())));
    /// assert_eq!(request.password(), Some(&Data::Static(b"pass".to_vec())));
    /// assert_eq!(request.host(), Some(&Data::Static(b"localhost".to_vec())));
    /// assert_eq!(request.port(), Some(&Data::Static(b"12345".to_vec())));
    /// assert_eq!(request.path(), &Data::Static(b"/path".to_vec()));
    /// assert_eq!(request.fragment(), Some(&Data::Static(b"frag".to_vec())));
    /// // populated by `Default` impl
    /// assert_eq!(request.method(), &Data::Static(b"GET".to_vec()));
    /// assert_eq!(request.version(), &Data::Static(b"HTTP/1.1".to_vec()));
    /// assert_eq!(request.timeout(), &Duration::from_secs(7));
    /// assert_eq!(request.id(), RequestId::new(0));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When `fuzz_directives` is `Some`, all fields that correspond to the [`ShouldFuzz`] variants
    /// are marked `Fuzzable`. Individual fields can be set to `Static` later through the more
    ///  specific `static_*` setter methods, if desired.
    ///
    /// ```
    /// # use feroxfuzz::requests::{ShouldFuzz, Request, RequestId};
    /// # use feroxfuzz::input::Data;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let directives = [ShouldFuzz::URLPath(b"/path"), ShouldFuzz::HTTPMethod(b"GET"), ShouldFuzz::HTTPVersion(b"HTTP/1.1")];
    /// let mut request = Request::from_url("https://localhost", Some(&directives))?;
    ///
    /// assert_eq!(request.scheme(), &Data::Static(b"https".to_vec()));
    /// assert_eq!(request.username(), None);
    /// assert_eq!(request.password(), None);
    /// assert_eq!(request.host(), Some(&Data::Static(b"localhost".to_vec())));
    /// assert_eq!(request.port(), None);
    /// assert_eq!(request.path(), &Data::Fuzzable(b"/path".to_vec()));
    /// assert_eq!(request.fragment(), None);
    /// // populated by `Default` impl, still set to Fuzzable, when appropriate
    /// assert_eq!(request.method(), &Data::Fuzzable(b"GET".to_vec()));
    /// assert_eq!(request.version(), &Data::Fuzzable(b"HTTP/1.1".to_vec()));
    /// assert_eq!(request.timeout(), &Duration::from_secs(7));
    /// assert_eq!(request.id(), RequestId::new(0));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the given `url` is invalid or
    /// if an unknown [`ShouldFuzz`] variant is encountered.
    ///
    /// Additionally, if this function receives one of the following
    /// [`ShouldFuzz::Key`] variants, it will raise an error, as they
    /// don't make sense in this particular context
    ///
    /// - `Key`
    /// - `Value`
    /// - `KeyAndValue`
    #[allow(clippy::missing_panics_doc)]
    #[instrument(level = "trace")]
    pub fn from_url(
        url: &str,
        fuzz_directives: Option<&[ShouldFuzz]>,
    ) -> Result<Self, FeroxFuzzError> {
        let parsed = Url::parse(url).map_err(|source| {
            error!(%url, "Failed to parse URL: {}", source);
            FeroxFuzzError::InvalidUrl {
                source,
                url: url.to_string(),
            }
        })?;

        let mut request: Self = parsed.into();

        if let Some(directives) = fuzz_directives {
            for directive in directives {
                match directive {
                    ShouldFuzz::URLScheme(scheme) => {
                        request.scheme = Data::Fuzzable(scheme.to_vec());
                    }
                    ShouldFuzz::URLUsername(username) => {
                        request.username = Some(Data::Fuzzable(username.to_vec()));
                    }
                    ShouldFuzz::URLPassword(password) => {
                        request.password = Some(Data::Fuzzable(password.to_vec()));
                    }
                    ShouldFuzz::URLHost => {
                        if request.host.is_some() {
                            request.host.as_mut().unwrap().toggle_type();
                        }
                    }
                    ShouldFuzz::URLPort(port) => {
                        request.port = Some(Data::Fuzzable(port.to_vec()));
                    }
                    ShouldFuzz::URLPath(path) => {
                        request.path = Data::Fuzzable(path.to_vec());
                    }
                    ShouldFuzz::URLFragment(fragment) => {
                        request.fragment = Some(Data::Fuzzable(fragment.to_vec()));
                    }
                    ShouldFuzz::URLParameterKey(parameter, delimiter) => {
                        request.add_fuzzable_param(parameter, delimiter, ShouldFuzz::Key)?;
                    }
                    ShouldFuzz::URLParameterValue(parameter, delimiter) => {
                        request.add_fuzzable_param(parameter, delimiter, ShouldFuzz::Value)?;
                    }
                    ShouldFuzz::URLParameterKeyAndValue(parameter, delimiter) => {
                        request.add_fuzzable_param(
                            parameter,
                            delimiter,
                            ShouldFuzz::KeyAndValue,
                        )?;
                    }
                    ShouldFuzz::HeaderKey(header, delimiter) => {
                        request.add_fuzzable_header(header, delimiter, ShouldFuzz::Key)?;
                    }
                    ShouldFuzz::HeaderValue(header, delimiter) => {
                        request.add_fuzzable_header(header, delimiter, ShouldFuzz::Value)?;
                    }
                    ShouldFuzz::HeaderKeyAndValue(header, delimiter) => {
                        request.add_fuzzable_header(header, delimiter, ShouldFuzz::KeyAndValue)?;
                    }
                    ShouldFuzz::RequestBody(body) => {
                        request.body = Some(Data::Fuzzable(body.to_vec()));
                    }
                    ShouldFuzz::HTTPMethod(method) => {
                        request.method = Data::Fuzzable(method.to_vec());
                    }
                    ShouldFuzz::HTTPVersion(version) => {
                        request.version = Data::Fuzzable(version.to_vec());
                    }
                    ShouldFuzz::UserAgent(user_agent) => {
                        request.user_agent = Some(Data::Fuzzable(user_agent.to_vec()));
                    }
                    _ => {
                        // invalid directive used, raise error
                        error!(?directive, "Invalid directive used");

                        return Err(FeroxFuzzError::InvalidDirective {
                            directive: format!("{:?}", directive),
                        });
                    }
                }
            }
        }

        Ok(request)
    }

    // ----------------
    // External Helpers
    // ----------------

    /// returns a string representation of all internal [`Data`] fields that collectively
    /// make up a url. This function is designed to be used to go from the original url
    /// to the newly mutated url in its string form.
    ///
    /// # Errors
    ///
    /// returns an error if one of the fields used to build the url string is not valid
    /// utf-8
    pub fn url_to_string(&self) -> Result<String, FeroxFuzzError> {
        // start out with a size larger than the current url's length
        let capacity = self.original_url().len() * 2;
        let mut str_builder = String::with_capacity(capacity);

        // as long as we use `url::Url` to do the initial parse of the
        // original url, we're guaranteed to have a scheme. The Url constructor
        // returns `RelativeUrlWithoutBase` if no scheme is present, and would
        // have to be handled before making it here
        str_builder.push_str(self.scheme.as_str()?);
        str_builder.push_str("://");

        if let Some(username) = self.username() {
            str_builder.push_str(username.as_str()?);

            if self.password().is_none() {
                // username without password, need to add the @ now
                str_builder.push('@');
            }
        }

        if let Some(password) = self.password() {
            str_builder.push(':');
            str_builder.push_str(password.as_str()?);
            str_builder.push('@');
        }

        if let Some(host) = self.host() {
            str_builder.push_str(host.as_str()?);
        }

        if let Some(port) = self.port() {
            str_builder.push(':');
            str_builder.push_str(port.as_str()?);
        }

        str_builder.push_str(self.path.as_str()?);

        if let Some(params) = self.params() {
            let mut first_param = true;

            for (key, value) in params {
                if first_param {
                    str_builder.push('?');
                    first_param = false;
                } else {
                    str_builder.push('&');
                }

                str_builder.push_str(key.as_str()?);
                str_builder.push('=');
                str_builder.push_str(value.as_str()?);
            }
        }

        if let Some(fragment) = self.fragment() {
            str_builder.push('#');
            str_builder.push_str(fragment.as_str()?);
        }

        Ok(str_builder)
    }

    /// the parsed [`Url`] that this request was constructed from
    #[must_use]
    pub fn parsed_url(&self) -> &Url {
        &self.parsed_url
    }

    /// when building a [`reqwest::Request`] to pass to the provided client implementations that
    /// use a [`reqwest`] client underneath, knowing whether the [`Url`] needs to be rebuilt or
    /// not is very useful, so this utility function was broken out to serve that purpose.
    #[must_use]
    pub fn url_is_fuzzable(&self) -> bool {
        if self.scheme.is_fuzzable() || self.path.is_fuzzable() {
            // get the fields that don't require some/none checks or iteration out of the way
            return true;
        }

        // the next set require checking some/none
        for field in [
            self.username.as_ref(),
            self.password.as_ref(),
            self.host.as_ref(),
            self.port.as_ref(),
            self.fragment.as_ref(),
        ]
        .iter()
        .flatten()
        {
            if field.is_fuzzable() {
                return true;
            }
        }

        // finally, url query params
        if let Some(params) = self.params() {
            for (key, value) in params {
                if key.is_fuzzable() || value.is_fuzzable() {
                    return true;
                }
            }
        }

        false
    }

    // ----------------
    // Internal Helpers
    // ----------------

    /// internal helper: splits a byte-array based on the given delimiter; mimics `str::split_once`
    #[instrument(skip_all, level = "trace")]
    fn get_key_and_value<'a>(
        &mut self,
        to_split: &'a [u8],
        delim: &[u8],
        collection: CollectionId,
    ) -> Result<(&'a [u8], &'a [u8]), FeroxFuzzError> {
        // initial bounds check on delimiter
        if delim.is_empty() {
            error!(?delim, ?collection, "Empty delimiter");

            return Err(FeroxFuzzError::KeyValueParseError {
                key_value_pair: to_split.to_vec(),
                reason: String::from("the given delimiter is empty"),
            });
        }

        // find the first index of the delimiter
        let offset = to_split
            .windows(delim.len())
            .position(|window| window == delim);

        // make sure we found something
        if offset.is_none() {
            error!(?to_split, ?delim, "Delimiter not found");

            return Err(FeroxFuzzError::KeyValueParseError {
                key_value_pair: to_split.to_vec(),
                reason: format!("Could not find {:x?} in {:x?}", delim, to_split),
            });
        }

        // create headers/params if necessary
        match collection {
            CollectionId::Headers => {
                if self.headers.is_none() {
                    self.headers = Some(Vec::new());
                }
            }
            CollectionId::Params => {
                if self.params.is_none() {
                    self.params = Some(Vec::new());
                }
            }
        }

        // emulate str::split behavior, where the delimiter is removed from the result
        //
        // when creating `value`, since the delimiter is variable length, need to
        // move the offset that many bytes to the right in order to correctly
        // remove the delimiter
        let key = &to_split[..offset.unwrap()];
        let value = &to_split[offset.unwrap() + delim.len()..];

        Ok((key, value))
    }

    /// internal helper: adds the given key/value to the specified collection with Fuzzable/Static marked
    /// as appropriate
    fn add_key_value_pair(
        &mut self,
        key: &[u8],
        value: &[u8],
        directive: Option<ShouldFuzz>,
        collection: CollectionId,
    ) -> Result<(), FeroxFuzzError> {
        // assumption: self.get_key_and_value has been called first with the given `CollectionId`
        // thereby creating the collection if it didn't already exist. i.e. we're safe to unwrap
        let coll = match collection {
            CollectionId::Headers => self.headers.as_mut().unwrap(),
            CollectionId::Params => self.params.as_mut().unwrap(),
        };

        match directive {
            Some(dir) => match dir {
                ShouldFuzz::KeyAndValue => {
                    coll.push((Data::Fuzzable(key.to_vec()), Data::Fuzzable(value.to_vec())));
                }
                ShouldFuzz::Key => {
                    coll.push((Data::Fuzzable(key.to_vec()), Data::Static(value.to_vec())));
                }
                ShouldFuzz::Value => {
                    coll.push((Data::Static(key.to_vec()), Data::Fuzzable(value.to_vec())));
                }
                _ => {
                    error!(?dir, "Invalid directive");

                    return Err(FeroxFuzzError::InvalidDirective {
                        directive: format!("{:?}", dir),
                    });
                }
            },
            None => {
                coll.push((Data::Static(key.to_vec()), Data::Static(value.to_vec())));
            }
        }

        Ok(())
    }

    // ----------------
    // Getters/Setters - same order as struct definition
    // ----------------

    /// get the id
    #[must_use]
    #[inline]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// get a mutable reference to the id
    ///
    /// use this as the id setter/manipulator, if necessary
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    ///
    /// *request.id_mut() = RequestId::new(10);
    ///
    /// assert_eq!(request.id(), RequestId::new(10));
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[inline]
    pub fn id_mut(&mut self) -> &mut RequestId {
        &mut self.id
    }

    /// get the original url
    #[must_use]
    #[inline]
    pub fn original_url(&self) -> &str {
        &self.original_url
    }

    /// get the scheme
    #[must_use]
    #[inline]
    pub const fn scheme(&self) -> &Data {
        &self.scheme
    }

    /// get a mutable reference to the scheme
    #[must_use]
    #[inline]
    pub fn scheme_mut(&mut self) -> &mut Data {
        &mut self.scheme
    }

    /// set the scheme's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    ///
    /// assert_eq!(request.scheme(), &Data::Static(b"http".to_vec()));
    ///
    /// request.fuzzable_scheme(b"https");
    ///
    /// assert_eq!(request.scheme(), &Data::Fuzzable(b"https".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_scheme(&mut self, scheme: &[u8]) {
        self.scheme = Data::Fuzzable(scheme.to_vec());
    }

    /// set the scheme's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    ///
    /// assert_eq!(request.scheme(), &Data::Static(b"http".to_vec()));
    ///
    /// request.static_scheme(b"https");
    ///
    /// assert_eq!(request.scheme(), &Data::Static(b"https".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_scheme(&mut self, scheme: &[u8]) {
        self.scheme = Data::Static(scheme.to_vec());
    }

    /// get the username
    #[must_use]
    #[inline]
    pub const fn username(&self) -> Option<&Data> {
        self.username.as_ref()
    }

    /// get a mutable reference to the username
    #[must_use]
    #[inline]
    pub fn username_mut(&mut self) -> Option<&mut Data> {
        self.username.as_mut()
    }

    /// set the username's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://user:pass@localhost.com", None)?;
    ///
    /// assert_eq!(request.username(), Some(&Data::Static(b"user".to_vec())));
    ///
    /// request.fuzzable_username(b"user2");
    ///
    /// assert_eq!(request.username(), Some(&Data::Fuzzable(b"user2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_username(&mut self, username: &[u8]) {
        self.username = Some(Data::Fuzzable(username.to_vec()));
    }

    /// set the username's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", Some(&[ShouldFuzz::URLUsername(b"user")]))?;
    ///
    /// assert_eq!(request.username(), Some(&Data::Fuzzable(b"user".to_vec())));
    ///
    /// request.static_username(b"user2");
    ///
    /// assert_eq!(request.username(), Some(&Data::Static(b"user2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_username(&mut self, username: &[u8]) {
        self.username = Some(Data::Static(username.to_vec()));
    }

    /// get the password
    #[must_use]
    #[inline]
    pub const fn password(&self) -> Option<&Data> {
        self.password.as_ref()
    }

    /// get a mutable reference to the password
    #[must_use]
    #[inline]
    pub fn password_mut(&mut self) -> Option<&mut Data> {
        self.password.as_mut()
    }

    /// set the password's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://user:pass@localhost.com", None)?;
    ///
    /// assert_eq!(request.password(), Some(&Data::Static(b"pass".to_vec())));
    ///
    /// request.fuzzable_password(b"pass2");
    ///
    /// assert_eq!(request.password(), Some(&Data::Fuzzable(b"pass2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_password(&mut self, password: &[u8]) {
        self.password = Some(Data::Fuzzable(password.to_vec()));
    }

    /// set the password's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", Some(&[ShouldFuzz::URLPassword(b"pass")]))?;
    ///
    /// assert_eq!(request.password(), Some(&Data::Fuzzable(b"pass".to_vec())));
    ///
    /// request.static_password(b"pass2");
    ///
    /// assert_eq!(request.password(), Some(&Data::Static(b"pass2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_password(&mut self, password: &[u8]) {
        self.password = Some(Data::Static(password.to_vec()));
    }

    /// get the host
    #[must_use]
    #[inline]
    pub const fn host(&self) -> Option<&Data> {
        self.host.as_ref()
    }

    /// get a mutable reference to the host
    #[must_use]
    #[inline]
    pub fn host_mut(&mut self) -> Option<&mut Data> {
        self.host.as_mut()
    }

    /// set the host's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", None)?;
    ///
    /// assert_eq!(request.host(), Some(&Data::Static(b"localhost.com".to_vec())));
    ///
    /// request.fuzzable_host(b"schmocalhost.com");
    ///
    /// assert_eq!(request.host(), Some(&Data::Fuzzable(b"schmocalhost.com".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_host(&mut self, host: &[u8]) {
        self.host = Some(Data::Fuzzable(host.to_vec()));
    }

    /// set the host's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", Some(&[ShouldFuzz::URLHost]))?;
    ///
    /// assert_eq!(request.host(), Some(&Data::Fuzzable(b"localhost.com".to_vec())));
    ///
    /// request.static_host(b"schmocalhost.com");
    ///
    /// assert_eq!(request.host(), Some(&Data::Static(b"schmocalhost.com".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_host(&mut self, host: &[u8]) {
        self.host = Some(Data::Static(host.to_vec()));
    }

    /// get the port
    #[must_use]
    #[inline]
    pub const fn port(&self) -> Option<&Data> {
        self.port.as_ref()
    }

    /// get a mutable reference to the port
    #[must_use]
    #[inline]
    pub fn port_mut(&mut self) -> Option<&mut Data> {
        self.port.as_mut()
    }

    /// set the port's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com:12345", None)?;
    ///
    /// assert_eq!(request.port(), Some(&Data::Static(b"12345".to_vec())));
    ///
    /// request.fuzzable_port(b"54321");
    ///
    /// assert_eq!(request.port(), Some(&Data::Fuzzable(b"54321".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_port(&mut self, port: &[u8]) {
        self.port = Some(Data::Fuzzable(port.to_vec()));
    }

    /// set the port's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", Some(&[ShouldFuzz::URLPort(b"12345")]))?;
    ///
    /// assert_eq!(request.port(), Some(&Data::Fuzzable(b"12345".to_vec())));
    ///
    /// request.static_port(b"54321");
    ///
    /// assert_eq!(request.port(), Some(&Data::Static(b"54321".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_port(&mut self, port: &[u8]) {
        self.port = Some(Data::Static(port.to_vec()));
    }

    /// get the path
    #[must_use]
    #[inline]
    pub const fn path(&self) -> &Data {
        &self.path
    }

    /// get a mutable reference to the path
    #[must_use]
    #[inline]
    pub fn path_mut(&mut self) -> &mut Data {
        &mut self.path
    }

    /// set the path's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path", None)?;
    ///
    /// assert_eq!(request.path(), &Data::Static(b"/path".to_vec()));
    ///
    /// request.fuzzable_path(b"/path2");
    ///
    /// assert_eq!(request.path(), &Data::Fuzzable(b"/path2".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_path(&mut self, path: &[u8]) {
        self.path = Data::Fuzzable(path.to_vec());
    }

    /// set the path's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com", Some(&[ShouldFuzz::URLPath(b"/path")]))?;
    ///
    /// assert_eq!(request.path(), &Data::Fuzzable(b"/path".to_vec()));
    ///
    /// request.static_path(b"/path2");
    ///
    /// assert_eq!(request.path(), &Data::Static(b"/path2".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_path(&mut self, path: &[u8]) {
        self.path = Data::Static(path.to_vec());
    }

    /// get the fragment
    #[must_use]
    #[inline]
    pub const fn fragment(&self) -> Option<&Data> {
        self.fragment.as_ref()
    }

    /// get a mutable reference to the fragment
    #[must_use]
    #[inline]
    pub fn fragment_mut(&mut self) -> Option<&mut Data> {
        self.fragment.as_mut()
    }

    /// set the fragment's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path#frag", None)?;
    ///
    /// assert_eq!(request.fragment(), Some(&Data::Static(b"frag".to_vec())));
    ///
    /// request.fuzzable_fragment(b"frag2");
    ///
    /// assert_eq!(request.fragment(), Some(&Data::Fuzzable(b"frag2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_fragment(&mut self, fragment: &[u8]) {
        self.fragment = Some(Data::Fuzzable(fragment.to_vec()));
    }

    /// set the fragment's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path", Some(&[ShouldFuzz::URLFragment(b"frag")]))?;
    ///
    /// assert_eq!(request.fragment(), Some(&Data::Fuzzable(b"frag".to_vec())));
    ///
    /// request.static_fragment(b"frag2");
    ///
    /// assert_eq!(request.fragment(), Some(&Data::Static(b"frag2".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_fragment(&mut self, fragment: &[u8]) {
        self.fragment = Some(Data::Static(fragment.to_vec()));
    }

    /// get the method
    #[must_use]
    #[inline]
    pub const fn method(&self) -> &Data {
        &self.method
    }

    /// get a mutable reference to the method
    #[must_use]
    #[inline]
    pub fn method_mut(&mut self) -> &mut Data {
        &mut self.method
    }

    /// set the method's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path", None)?;
    ///
    /// assert_eq!(request.method(), &Data::Static(b"GET".to_vec()));
    ///
    /// request.fuzzable_method(b"POST");
    ///
    /// assert_eq!(request.method(), &Data::Fuzzable(b"POST".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_method(&mut self, method: &[u8]) {
        self.method = Data::Fuzzable(method.to_vec());
    }

    /// set the method's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path", Some(&[ShouldFuzz::HTTPMethod(b"GET")]))?;
    ///
    /// assert_eq!(request.method(), &Data::Fuzzable(b"GET".to_vec()));
    ///
    /// request.static_method(b"POST");
    ///
    /// assert_eq!(request.method(), &Data::Static(b"POST".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_method(&mut self, method: &[u8]) {
        self.method = Data::Static(method.to_vec());
    }

    /// get the body
    #[must_use]
    #[inline]
    pub const fn body(&self) -> Option<&Data> {
        self.body.as_ref()
    }

    /// get a mutable reference to the body
    #[must_use]
    #[inline]
    pub fn body_mut(&mut self) -> Option<&mut Data> {
        self.body.as_mut()
    }

    /// set the body's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/", None)?;
    ///
    /// assert_eq!(request.body(), None);
    ///
    /// request.fuzzable_body(b"{\"auth\": \"token\"}");
    ///
    /// assert_eq!(request.body(), Some(&Data::Fuzzable(b"{\"auth\": \"token\"}".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_body(&mut self, body: &[u8]) {
        self.body = Some(Data::Fuzzable(body.to_vec()));
    }

    /// set the body's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/", Some(&[ShouldFuzz::RequestBody(b"body")]))?;
    ///
    /// assert_eq!(request.body(), Some(&Data::Fuzzable(b"body".to_vec())));
    ///
    /// request.static_body(b"{\"auth\": \"token\"}");
    ///
    /// assert_eq!(request.body(), Some(&Data::Static(b"{\"auth\": \"token\"}".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_body(&mut self, body: &[u8]) {
        self.body = Some(Data::Static(body.to_vec()));
    }

    /// get the headers
    #[must_use]
    #[inline]
    pub fn headers(&self) -> Option<&[(Data, Data)]> {
        self.headers.as_deref()
    }

    /// get a mutable reference to the headers
    #[must_use]
    #[inline]
    pub fn headers_mut(&mut self) -> Option<&mut [(Data, Data)]> {
        self.headers.as_deref_mut()
    }

    /// Add a [`Data::Fuzzable`] header. Fuzzable means that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy.
    ///
    /// `directive` should be one of the following variants
    /// - [`ShouldFuzz::Key`]
    /// - [`ShouldFuzz::Value`]
    /// - [`ShouldFuzz::KeyAndValue`]
    ///
    /// # Examples
    ///
    /// When `Key` is used, only the header's key is marked [`Data::Fuzzable`], while
    /// the header's value is marked [`Data::Static`].
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Fuzzable(b"stuff".to_vec()), Data::Static(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_header(b"stuff:things", b":", ShouldFuzz::Key)?;
    ///
    /// assert_eq!(request.headers(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When `Value` is used, only the header's value is marked [`Data::Fuzzable`], while
    /// the header's key is marked [`Data::Static`].
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Static(b"stuff".to_vec()), Data::Fuzzable(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_header(b"stuff: things", b": ", ShouldFuzz::Value)?;
    ///
    /// assert_eq!(request.headers(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When `KeyAndValue` is used, both the header's key and its value are marked [`Data::Fuzzable`]
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Fuzzable(b"stuff".to_vec()), Data::Fuzzable(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_header(b"stuff : things", b" : ", ShouldFuzz::KeyAndValue)?;
    ///
    /// assert_eq!(request.headers(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the delimiter passed in as `delim` is empty, an error is returned.
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// // delim must not be empty
    /// let result = request.add_fuzzable_header(b"stuff : things", b"", ShouldFuzz::Key);
    ///
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If the delimiter passed in as `delim` is not found within `header` an error
    /// is returned.
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// // header must contain delim
    /// let result = request.add_fuzzable_header(b"stuff : things", b"???", ShouldFuzz::Key);
    ///
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If this function receives a [`ShouldFuzz`]
    /// variant other than the three listed below, it will return an error,
    /// as only what's below make sense in this particular context.
    ///
    /// - `Key`
    /// - `Value`
    /// - `KeyAndValue`
    #[instrument(skip_all, level = "trace")]
    pub fn add_fuzzable_header(
        &mut self,
        header: &[u8],
        delim: &[u8],
        directive: ShouldFuzz,
    ) -> Result<(), FeroxFuzzError> {
        let collection = CollectionId::Headers;
        // side-effect: self.headers is created if value was None upon call
        let (key, value) = self.get_key_and_value(header, delim, collection)?;

        self.add_key_value_pair(key, value, Some(directive), collection)?;

        Ok(())
    }

    /// Add a [`Data::Static`] header. Static means that when
    /// it's passed to a mutator, the internal contents will not change.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Static(b"stuff".to_vec()), Data::Static(b"things".to_vec()));
    ///
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_static_header(b"stuff:things", b":")?;
    ///
    /// assert_eq!(request.headers(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the delimiter passed in as `delim` is not found within `header` OR `delim` is empty, an error
    /// will be returned. See [`Request::add_fuzzable_header`] for error examples.
    #[instrument(skip_all, level = "trace")]
    pub fn add_static_header(&mut self, header: &[u8], delim: &[u8]) -> Result<(), FeroxFuzzError> {
        let collection = CollectionId::Headers;

        let (key, value) = self.get_key_and_value(header, delim, collection)?;

        self.add_key_value_pair(key, value, None, collection)?;

        Ok(())
    }

    /// get the url parameters
    #[must_use]
    #[inline]
    pub fn params(&self) -> Option<&[(Data, Data)]> {
        self.params.as_deref()
    }

    /// get a mutable reference to the url parameters
    #[must_use]
    #[inline]
    pub fn params_mut(&mut self) -> Option<&mut [(Data, Data)]> {
        self.params.as_deref_mut()
    }

    /// Add a [`Data::Fuzzable`] query parameter. Fuzzable means that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy.
    ///
    /// `directive` should be one of the following variants
    /// - [`ShouldFuzz::Key`]
    /// - [`ShouldFuzz::Value`]
    /// - [`ShouldFuzz::KeyAndValue`]
    ///
    /// # Examples
    ///
    /// When `Key` is used, only the param's key is marked [`Data::Fuzzable`], while
    /// the param's value is marked [`Data::Static`].
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Fuzzable(b"stuff".to_vec()), Data::Static(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_param(b"stuff=things", b"=", ShouldFuzz::Key)?;
    ///
    /// assert_eq!(request.params(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When `Value` is used, only the param's value is marked [`Data::Fuzzable`], while
    /// the param's key is marked [`Data::Static`].
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Static(b"stuff".to_vec()), Data::Fuzzable(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_param(b"stuff=things", b"=", ShouldFuzz::Value)?;
    ///
    /// assert_eq!(request.params(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When `KeyAndValue` is used, both the param's key and its value are marked [`Data::Fuzzable`]
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let expected = (Data::Fuzzable(b"stuff".to_vec()), Data::Fuzzable(b"things".to_vec()));
    ///
    /// // all fields marked `Static`
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// request.add_fuzzable_param(b"stuff = things", b" = ", ShouldFuzz::KeyAndValue)?;
    ///
    /// assert_eq!(request.params(), Some(vec![expected].as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the delimiter passed in as `delim` is empty, an error is returned.
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// // delim must not be empty
    /// let result = request.add_fuzzable_param(b"stuff = things", b"", ShouldFuzz::Key);
    ///
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If the delimiter passed in as `delim` is not found within `param` an error
    /// is returned.
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost/", None)?;
    ///
    /// // header must contain delim
    /// let result = request.add_fuzzable_param(b"stuff : things", b"???", ShouldFuzz::Key);
    ///
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If this function receives a [`ShouldFuzz`]
    /// variant other than the three listed below, it will return an error,
    /// as only what's below make sense in this particular context.
    ///
    /// - `Key`
    /// - `Value`
    /// - `KeyAndValue`
    #[instrument(skip_all, level = "trace")]
    pub fn add_fuzzable_param(
        &mut self,
        header: &[u8],
        delim: &[u8],
        directive: ShouldFuzz,
    ) -> Result<(), FeroxFuzzError> {
        let collection = CollectionId::Params;
        // side-effect: self.headers is created if value was None upon call
        let (key, value) = self.get_key_and_value(header, delim, collection)?;

        self.add_key_value_pair(key, value, Some(directive), collection)?;

        Ok(())
    }

    /// Add a [`Data::Static`] query parameter. Static means that when
    /// it's passed to a mutator, the internal contents will not change.
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::ShouldFuzz;
    /// # use feroxfuzz::requests::Request;
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut expected = vec![(Data::Static(b"stuff".to_vec()), Data::Static(b"things".to_vec()))];
    /// let from_url_call = (Data::Static(b"mostuff".to_vec()), Data::Static(b"mothings".to_vec()));
    ///
    /// // gathered during call to `from_url`
    /// expected.insert(0, from_url_call.clone());
    ///
    /// let mut request = Request::from_url("http://localhost/path?mostuff=mothings", None)?;
    ///
    /// assert_eq!(request.params(), Some(vec![from_url_call].as_slice()));
    /// request.add_static_param(b"stuff=things", b"=")?;
    ///
    /// assert_eq!(request.params(), Some(expected.as_slice()));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If the delimiter passed in as `delim` is not found within `param` OR `delim` is empty, an error
    /// will be returned. See [`Request::add_fuzzable_param`] for error examples.
    #[instrument(skip_all, level = "trace")]
    pub fn add_static_param(&mut self, param: &[u8], delim: &[u8]) -> Result<(), FeroxFuzzError> {
        let collection = CollectionId::Params;

        let (key, value) = self.get_key_and_value(param, delim, collection)?;

        self.add_key_value_pair(key, value, None, collection)?;

        Ok(())
    }

    /// get the user-agent
    #[must_use]
    #[inline]
    pub const fn user_agent(&self) -> Option<&Data> {
        self.user_agent.as_ref()
    }

    /// get a mutable reference to the user-agent
    #[must_use]
    #[inline]
    pub fn user_agent_mut(&mut self) -> Option<&mut Data> {
        self.user_agent.as_mut()
    }

    /// set the `user_agent`'s value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    ///
    /// assert_eq!(request.user_agent(), None);
    ///
    /// request.fuzzable_user_agent(b"def-not-mozilla");
    ///
    /// assert_eq!(request.user_agent(), Some(&Data::Fuzzable(b"def-not-mozilla".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_user_agent(&mut self, user_agent: &[u8]) {
        self.user_agent = Some(Data::Fuzzable(user_agent.to_vec()));
    }

    /// set the `user_agent`'s value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, RequestId, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    ///
    /// assert_eq!(request.user_agent(), None);
    ///
    /// request.static_user_agent(b"def-not-mozilla");
    ///
    /// assert_eq!(request.user_agent(), Some(&Data::Static(b"def-not-mozilla".to_vec())));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_user_agent(&mut self, user_agent: &[u8]) {
        self.user_agent = Some(Data::Static(user_agent.to_vec()));
    }

    /// get the version
    #[must_use]
    #[inline]
    pub const fn version(&self) -> &Data {
        &self.version
    }

    /// get a mutable reference to the version
    #[must_use]
    #[inline]
    pub fn version_mut(&mut self) -> &mut Data {
        &mut self.version
    }

    /// set the version's value to [`Data::Fuzzable`], meaning that when
    /// it's passed to a mutator, the internal contents should change, based upon
    /// the wrapping fuzzer's mutator and fuzz strategy
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/", None)?;
    ///
    /// assert_eq!(request.version(), &Data::Static(b"HTTP/1.1".to_vec()));
    ///
    /// request.fuzzable_version(b"HTTP/1.0");
    ///
    /// assert_eq!(request.version(), &Data::Fuzzable(b"HTTP/1.0".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn fuzzable_version(&mut self, version: &[u8]) {
        self.version = Data::Fuzzable(version.to_vec());
    }

    /// set the version's value to [`Data::Static`], meaning that the
    /// contents will not change when it's passed to a mutator
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::{Request, ShouldFuzz};
    /// # use feroxfuzz::input::Data;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::from_url("http://localhost.com/path", Some(&[ShouldFuzz::HTTPVersion(b"HTTP/1.1")]))?;
    ///
    /// assert_eq!(request.version(), &Data::Fuzzable(b"HTTP/1.1".to_vec()));
    ///
    /// request.static_version(b"HTTP/1.0");
    ///
    /// assert_eq!(request.version(), &Data::Static(b"HTTP/1.0".to_vec()));
    ///
    /// # Ok(())
    /// # }
    /// ```
    pub fn static_version(&mut self, version: &[u8]) {
        self.version = Data::Static(version.to_vec());
    }

    /// get the timeout
    #[must_use]
    #[inline]
    pub const fn timeout(&self) -> &Duration {
        &self.timeout
    }

    /// get a mutable reference to the timeout
    ///
    /// use this as the timeout setter, if necessary
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::requests::Request;
    /// # use std::time::Duration;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut request = Request::new();
    /// let new_timeout = Duration::from_millis(1500);
    ///
    /// *request.timeout_mut() = new_timeout;
    ///
    /// assert_eq!(request.timeout(), &new_timeout);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    #[inline]
    pub fn timeout_mut(&mut self) -> &mut Duration {
        &mut self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Request::new` returns the same as `Request::default`
    #[test]
    fn new_request_returns_default_impl() {
        assert_eq!(Request::new(), Request::default());
    }

    /// `get_key_and_value` returns error on empty delim
    #[test]
    fn get_key_and_value_errors_on_empty_delim() {
        let mut req = Request::new();
        assert!(req
            .get_key_and_value(b"stuff", b"", CollectionId::Headers)
            .is_err());
    }

    /// `get_key_and_value` returns error on delim-not-found
    #[test]
    fn get_key_and_value_errors_on_delim_not_found() {
        let mut req = Request::new();
        assert!(req
            .get_key_and_value(b"stuff", b"x", CollectionId::Headers)
            .is_err());
    }

    /// `get_key_and_value` creates headers collection if missing
    #[test]
    fn get_key_and_value_creates_headers_when_missing() {
        let mut req = Request::new();

        assert!(req.headers.is_none());

        req.get_key_and_value(b"stuff", b"s", CollectionId::Headers)
            .unwrap();

        assert_eq!(req.headers, Some(Vec::new()));
    }

    /// `get_key_and_value` creates params collection if missing
    #[test]
    fn get_key_and_value_creates_params_when_missing() {
        let mut req = Request::new();

        assert!(req.params.is_none());

        req.get_key_and_value(b"stuff", b"s", CollectionId::Params)
            .unwrap();

        assert_eq!(req.params, Some(Vec::new()));
    }

    /// `get_key_and_value` returns correct key/value with single byte delim
    #[test]
    fn get_key_and_value_is_correct_single_byte_delim() {
        let mut req = Request::new();

        // delim as first char
        let (key, value) = req
            .get_key_and_value(b"stuff", b"s", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"");
        assert_eq!(value, b"tuff");

        // delim as last char
        let (key, value) = req
            .get_key_and_value(b"stufF", b"F", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"stuf");
        assert_eq!(value, b"");

        // delim in the middle
        let (key, value) = req
            .get_key_and_value(b"stuff:things", b":", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"stuff");
        assert_eq!(value, b"things");
    }

    /// `get_key_and_value` returns correct key/value with multi-byte delim
    #[test]
    fn get_key_and_value_is_correct_multi_byte_delim() {
        let mut req = Request::new();

        // delim as first char
        let (key, value) = req
            .get_key_and_value(b"stuff", b"st", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"");
        assert_eq!(value, b"uff");

        // delim as last char
        let (key, value) = req
            .get_key_and_value(b"stufF", b"fF", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"stu");
        assert_eq!(value, b"");

        // delim in the middle
        let (key, value) = req
            .get_key_and_value(b"stuff::things", b"::", CollectionId::Params)
            .unwrap();

        assert_eq!(key, b"stuff");
        assert_eq!(value, b"things");
    }

    /// `add_key_value_pair` adds correct Data tuple
    #[test]
    fn add_key_value_pair_adds_two_fuzz_with_key_and_value_directive() {
        let expected = (
            Data::Fuzzable(b"stuff".to_vec()),
            Data::Fuzzable(b"things".to_vec()),
        );
        let mut req = Request::new();

        // normally happens via get_key_and_value's side-effect
        req.headers = Some(Vec::new());

        req.add_key_value_pair(
            b"stuff",
            b"things",
            Some(ShouldFuzz::KeyAndValue),
            CollectionId::Headers,
        )
        .unwrap();

        assert_eq!(req.headers, Some(vec![expected]));
    }

    /// `add_key_value_pair` adds correct Data tuple
    #[test]
    fn add_key_value_pair_adds_one_fuzz_with_key_directive() {
        let expected = (
            Data::Fuzzable(b"stuff".to_vec()),
            Data::Static(b"things".to_vec()),
        );
        let mut req = Request::new();

        // normally happens via get_key_and_value's side-effect
        req.headers = Some(Vec::new());

        req.add_key_value_pair(
            b"stuff",
            b"things",
            Some(ShouldFuzz::Key),
            CollectionId::Headers,
        )
        .unwrap();

        assert_eq!(req.headers, Some(vec![expected]));
    }

    /// `add_key_value_pair` adds correct Data tuple
    #[test]
    fn add_key_value_pair_adds_one_fuzz_with_value_directive() {
        let expected = (
            Data::Static(b"stuff".to_vec()),
            Data::Fuzzable(b"things".to_vec()),
        );
        let mut req = Request::new();

        // normally happens via get_key_and_value's side-effect
        req.headers = Some(Vec::new());

        req.add_key_value_pair(
            b"stuff",
            b"things",
            Some(ShouldFuzz::Value),
            CollectionId::Headers,
        )
        .unwrap();

        assert_eq!(req.headers, Some(vec![expected]));
    }

    /// `add_key_value_pair` adds correct Data tuple
    #[test]
    fn add_key_value_pair_adds_zero_fuzz_with_none_directive() {
        let expected = (
            Data::Static(b"stuff".to_vec()),
            Data::Static(b"things".to_vec()),
        );
        let mut req = Request::new();

        // normally happens via get_key_and_value's side-effect
        req.headers = Some(Vec::new());

        req.add_key_value_pair(b"stuff", b"things", None, CollectionId::Headers)
            .unwrap();

        assert_eq!(req.headers, Some(vec![expected]));
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_base_url() {
        let expected = String::from("http://localhost/");
        let request: Request = Url::parse(&expected).unwrap().into();

        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_username_and_password_variations() {
        let expected = String::from("https://user@localhost/");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);

        let expected = String::from("https://user:pass@localhost/");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);

        let expected = String::from("https://:pass@localhost/");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_base_url_with_port() {
        let expected = String::from("http://localhost:12345/");
        let request: Request = Url::parse(&expected).unwrap().into();

        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_param_variations() {
        let expected = String::from("http://localhost/?stuff=things");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);

        let expected = String::from("http://localhost/?stuff=things&derp=pred&a=b");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);

        let expected = String::from("http://localhost/?=things");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);

        let expected = String::from("http://localhost/?stuff=&what=ever");
        let request: Request = Url::parse(&expected).unwrap().into();
        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_with_fragment() {
        let expected = String::from("http://localhost/#thing");
        let request: Request = Url::parse(&expected).unwrap().into();

        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_to_string` produces correct url with separators
    #[test]
    fn url_to_string_with_everything() {
        let expected = String::from(
            "http://user:pass@localhost:12345/path?querykey=queryval&stuff=things&key=#frag",
        );
        let request: Request = Url::parse(&expected).unwrap().into();

        assert_eq!(request.url_to_string().unwrap(), expected);
    }

    /// `url_is_fuzzable` returns accurate results
    #[test]
    fn url_is_fuzzable_variations() {
        let mut request = Request::from_url("http://localhost/", None).unwrap();
        assert!(!request.url_is_fuzzable());

        request
            .add_fuzzable_param(b"a=b", b"=", ShouldFuzz::Key)
            .unwrap();
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request
            .add_fuzzable_param(b"a=b", b"=", ShouldFuzz::Value)
            .unwrap();
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request
            .add_fuzzable_param(b"a=b", b"=", ShouldFuzz::KeyAndValue)
            .unwrap();
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_fragment(b"#stuff");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_host(b"derp.com");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_password(b"stuff");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_path(b"/things");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_port(b"1111");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_scheme(b"http");
        assert!(request.url_is_fuzzable());

        request = Request::from_url("http://localhost/", None).unwrap();
        request.fuzzable_username(b"admin");
        assert!(request.url_is_fuzzable());
    }
}
