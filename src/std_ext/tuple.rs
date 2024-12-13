// note: the following traits are from libafl. It was too heavy a solution to bring LibAFL
// along for a few traits and their rand implementation, so they're copied here instead.
// Full credit for the following traits goes to the LibAFL authors.

use core::any::type_name;
use core::ptr::{addr_of, addr_of_mut};

/// We need fixed names for many parts of this lib.
pub trait Named {
    /// Provide the name of this element.
    fn name(&self) -> &str;
}

/// Returns if the type `T` is equal to `U`
/// As this relies on [`type_name`](https://doc.rust-lang.org/std/any/fn.type_name.html#note) internally,
/// there is a chance for collisions.
/// Use `nightly` if you need a perfect match at all times.
#[inline]
#[must_use]
pub fn type_eq<T: ?Sized, U: ?Sized>() -> bool {
    type_name::<T>() == type_name::<U>()
}

/// Match for a name and return the value
///
/// # Note
/// This operation may not be 100% accurate with Rust stable, see the notes for `type_eq`
/// (in `nightly`, it uses [specialization](https://stackoverflow.com/a/60138532/7658998)).
pub trait MatchName {
    /// Match for a name and return the borrowed value
    fn match_name<T>(&self, name: &str) -> Option<&T>;
    /// Match for a name and return the mut borrowed value
    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T>;
}

impl MatchName for () {
    fn match_name<T>(&self, _name: &str) -> Option<&T> {
        None
    }
    fn match_name_mut<T>(&mut self, _name: &str) -> Option<&mut T> {
        None
    }
}

impl<Head, Tail> MatchName for (Head, Tail)
where
    Head: Named,
    Tail: MatchName,
{
    fn match_name<T>(&self, name: &str) -> Option<&T> {
        if type_eq::<Head, T>() && name == self.0.name() {
            unsafe { addr_of!(self.0).cast::<T>().as_ref() }
        } else {
            self.1.match_name::<T>(name)
        }
    }

    fn match_name_mut<T>(&mut self, name: &str) -> Option<&mut T> {
        if type_eq::<Head, T>() && name == self.0.name() {
            unsafe { (addr_of_mut!(self.0).cast::<T>()).as_mut() }
        } else {
            self.1.match_name_mut::<T>(name)
        }
    }
}
