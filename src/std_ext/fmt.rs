use super::convert::AsInner;
use lazy_static::lazy_static;
use regex::Regex;
use std::any::type_name;
use std::fmt::Debug;

lazy_static! {
    /// translate fully qualified crate paths to just their names
    ///
    /// `feroxfuzz::corpora::wordlist::Wordlist<alloc::vec::Vec<&str>, &str>`
    ///
    /// becomes
    ///
    /// `Wordlist<Vec<&str>, &str>`
    static ref TYPENAME_REGEX: Regex = Regex::new(r"\w+::").unwrap();
}

/// Extend the [`Display`] trait to provide a uniform format for library types
pub trait DisplayExt {
    /// display the type, its length, and the first `n` elements in the collection
    fn display_top(&self, n: usize) -> String;
}

impl<T> DisplayExt for T
where
    T: AsInner,
    <T as AsInner>::Type: IntoIterator + Clone,
    <<T as AsInner>::Type as IntoIterator>::Item: Debug,
{
    fn display_top(&self, n: usize) -> String {
        let name = TYPENAME_REGEX.replace_all(type_name::<T>(), "");

        let inner = self.inner().to_owned();
        let mut length = 0;
        let mut peek = Vec::with_capacity(n);

        for (i, item) in inner.into_iter().enumerate() {
            // building peek and length in a single loop eliminates a second allocation for another iterator
            if i < n {
                peek.push(item);
            }
            length += 1;
        }

        format!(
            "{}::{{len={}, top-{}={:x?}}}",
            name,
            length,
            peek.len(),
            peek
        )
    }
}
