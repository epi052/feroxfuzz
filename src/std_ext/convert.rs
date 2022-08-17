use std::collections::HashMap;
/// The traits in this module provide a way to convert from one type to another type
use std::ffi::CString;

/// return reference to inner type
pub trait AsInner {
    /// the inner type that should be exposed
    type Type;

    /// get a reference to the inner type, which is of type [`Self::Type`]
    fn inner(&self) -> &Self::Type;
}

/// convert wrapper into its inner type
pub trait IntoInner {
    /// the type to return to the caller of `.into_inner()`
    type Type;

    /// convert the implementor into [`IntoInner::Type`]
    fn into_inner(self) -> Self::Type;
}

/// simple trait to add a `.as_bytes()` equivalent to implementors
pub trait AsBytes {
    /// Returns a byte slice of the implementor's contents
    fn as_bytes(&self) -> &[u8];
}

macro_rules! strings_as_bytes {
    ($implementor:ty) => {
        impl AsBytes for $implementor {
            fn as_bytes(&self) -> &[u8] {
                <Self>::as_bytes(&self)
            }
        }

        impl AsBytes for &$implementor {
            fn as_bytes(&self) -> &[u8] {
                <$implementor>::as_bytes(&self)
            }
        }
    };
}

macro_rules! vecs_as_bytes {
    ($implementor:ty) => {
        impl AsBytes for $implementor {
            fn as_bytes(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl AsBytes for &$implementor {
            fn as_bytes(&self) -> &[u8] {
                self.as_slice()
            }
        }
    };
}

vecs_as_bytes!(Vec<u8>);

strings_as_bytes!(String);
strings_as_bytes!(str);
strings_as_bytes!(CString);

impl<BH> IntoInner for HashMap<String, Vec<u8>, BH>
where
    BH: std::hash::BuildHasher,
{
    type Type = Self;

    fn into_inner(self) -> Self::Type {
        self
    }
}
