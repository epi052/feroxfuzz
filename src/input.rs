//! fuzzable and static input data representations
use crate::error::FeroxFuzzError;
use crate::std_ext::convert::{AsInner, IntoInner};
use crate::std_ext::fmt::DisplayExt;
use crate::AsBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;
use std::string::ParseError;

use tracing::{error, instrument};

/// Base-level input type; can be marked `Fuzzable` or `Static`
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Data {
    /// fuzzable data; when passed to a mutator, the internal contents
    /// may change, dependent upon the mutator and fuzz strategy
    Fuzzable(Vec<u8>),

    /// non-fuzzable data; internal contents will not change during mutation
    Static(Vec<u8>),
}

impl AsInner for Data {
    type Type = Vec<u8>;

    fn inner(&self) -> &Self::Type {
        match self {
            Self::Fuzzable(value) | Self::Static(value) => value,
        }
    }
}

impl IntoInner for Data {
    type Type = Vec<u8>;

    /// Consumes this `Data` variant, returning the underlying value
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::input::Data;
    /// # use std::str::FromStr;
    /// # use feroxfuzz::IntoInner;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut data = Data::from_str("AAA")?;
    /// assert_eq!(data, Data::Static(vec![0x41, 0x41, 0x41]));
    ///
    /// assert_eq!(data.into_inner(), vec![0x41, 0x41, 0x41]);
    /// # Ok(())
    /// # }
    /// ```
    fn into_inner(self) -> Self::Type {
        match self {
            Self::Fuzzable(value) | Self::Static(value) => value,
        }
    }
}

impl Debug for Data {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fuzzable(_) => f.debug_tuple("Fuzzable").field(&self.format()).finish(),
            Self::Static(_) => f.debug_tuple("Static").field(&self.format()).finish(),
        }
    }
}

impl Display for Data {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.format())
    }
}

impl Default for Data {
    /// return an empty non-fuzzable variant
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::input::Data;
    /// let empty = Data::default();
    ///
    /// assert_eq!(empty, Data::Static(Vec::new()));
    /// ```
    fn default() -> Self {
        Self::Static(Vec::new())
    }
}

impl Data {
    /// create a new [`Data::Static`] instance with an empty buffer / length of 0
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// swap a `Data` variant from `Fuzzable` to `Static` and vice-versa
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::input::Data;
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut data = Data::from_str("AAA")?;
    /// assert_eq!(data, Data::Static(vec![0x41, 0x41, 0x41]));
    ///
    /// data.toggle_type();
    ///
    /// assert_eq!(data, Data::Fuzzable(vec![0x41, 0x41, 0x41]));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ```
    /// # use feroxfuzz::input::Data;
    /// # use std::str::FromStr;
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut data = Data::Fuzzable("AAA".as_bytes().to_vec());
    /// assert_eq!(data, Data::Fuzzable(vec![0x41, 0x41, 0x41]));
    ///
    /// data.toggle_type();
    ///
    /// assert_eq!(data, Data::from_str("AAA")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn toggle_type(&mut self) {
        *self = match std::mem::take(self) {
            Self::Fuzzable(inner) => Self::Static(inner),
            Self::Static(inner) => Self::Fuzzable(inner),
        }
    }

    /// internal helper: formats inner byte-arrays into something more readable
    fn format(&self) -> String {
        match self {
            // if the inner bytes are all valid utf-8, we can simply print them as a string
            // otherwise, we'll print the first 3 bytes as hex
            Self::Fuzzable(value) | Self::Static(value) => {
                std::str::from_utf8(value).map_or_else(|_| self.display_top(3), String::from)
            }
        }
    }

    /// returns whether or not this piece of data is marked fuzzable or not
    #[must_use]
    pub const fn is_fuzzable(&self) -> bool {
        matches!(self, Self::Fuzzable(_))
    }

    /// returns an `&str` representation of the underlying
    /// bytes
    ///
    /// # Errors
    ///
    /// will error when underlying bytes are not valid utf-8
    #[instrument(skip_all, level = "trace")]
    pub fn as_str(&self) -> Result<&str, FeroxFuzzError> {
        std::str::from_utf8(self.inner()).map_err(|err| {
            error!(?err, "failed to convert Data to utf-8");

            FeroxFuzzError::UnparsableData { source: err }
        })
    }

    /// resize the inner buffer length to match `new_size`
    pub fn resize(&mut self, new_size: usize) {
        match self {
            Self::Fuzzable(inner) | Self::Static(inner) => inner.resize(new_size, 0),
        }
    }

    /// size of the inner buffer
    #[must_use]
    pub const fn len(&self) -> usize {
        match self {
            Self::Fuzzable(inner) | Self::Static(inner) => inner.len(),
        }
    }

    /// returns `true` if the inner buffer contains no elements
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Fuzzable(inner) | Self::Static(inner) => inner.is_empty(),
        }
    }

    /// get a mutable reference to the inner buffer of `u8`s
    #[must_use]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Fuzzable(inner) | Self::Static(inner) => inner,
        }
    }
}

impl FromStr for Data {
    type Err = ParseError;

    /// a `Data::Static` variant may be created directly from an `&str` type
    ///
    /// # Examples
    ///
    /// ```
    /// # use feroxfuzz::input::Data;
    /// use std::str::FromStr;  // trait must be in scope
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let data = Data::from_str("AAA")?;
    /// assert_eq!(data, Data::Static(vec![0x41, 0x41, 0x41]));
    /// # Ok(())
    /// # }
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::Static(s.as_bytes().to_vec()))
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Fuzzable(inner) | Self::Static(inner) => inner,
        }
    }
}

impl From<Vec<u8>> for Data {
    fn from(value: Vec<u8>) -> Self {
        Self::Static(value)
    }
}

impl From<&[u8]> for Data {
    fn from(value: &[u8]) -> Self {
        Self::Static(value.to_owned())
    }
}

impl From<String> for Data {
    fn from(value: String) -> Self {
        Self::Static(value.into_bytes())
    }
}

impl From<&str> for Data {
    fn from(value: &str) -> Self {
        // this is the same as Data::from_str(value), however, to appease
        // clippy, we're using the FromStr impl here without the Ok()
        //
        // clippy doesn't like having an unwrap in a From<T>, even though
        // Data's FromStr impl is infallible
        Self::Static(value.as_bytes().to_vec())
    }
}

impl AsBytes for Data {
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl PartialEq<&Self> for Data {
    fn eq(&self, other: &&Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl PartialEq<Data> for &Data {
    fn eq(&self, other: &Data) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl PartialEq<str> for Data {
    fn eq(&self, other: &str) -> bool {
        self.as_ref() == other.as_bytes()
    }
}

impl PartialEq<Data> for str {
    fn eq(&self, other: &Data) -> bool {
        self.as_bytes() == other.as_ref()
    }
}

impl PartialEq<&str> for Data {
    fn eq(&self, other: &&str) -> bool {
        self.as_ref() == other.as_bytes()
    }
}

impl PartialEq<Data> for &str {
    fn eq(&self, other: &Data) -> bool {
        self.as_bytes() == other.as_ref()
    }
}

impl PartialEq<String> for Data {
    fn eq(&self, other: &String) -> bool {
        self.as_ref() == other.as_bytes()
    }
}

impl PartialEq<Data> for String {
    fn eq(&self, other: &Data) -> bool {
        self.as_bytes() == other.as_ref()
    }
}

impl PartialEq<&[u8]> for Data {
    fn eq(&self, other: &&[u8]) -> bool {
        &self.as_ref() == other
    }
}

impl PartialEq<Data> for &[u8] {
    fn eq(&self, other: &Data) -> bool {
        self == &other.as_ref()
    }
}

impl PartialEq<Vec<u8>> for Data {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other
    }
}

impl PartialEq<Data> for Vec<u8> {
    fn eq(&self, other: &Data) -> bool {
        self == other.as_ref()
    }
}
